use core::{fmt, mem, str};
use ibc::{Backend, IceError, IceResult, PhysicalAddress, ResultExt, VirtualAddress};

use self::profile::{Pointer, StructOffset};

mod profile;

/// Values that we can read from guest memory
trait Readable: Sized {
    fn read<B: ibc::Backend>(windows: &Windows<B>, addr: VirtualAddress) -> IceResult<Self>;
}

impl<T: bytemuck::Pod> Readable for T {
    fn read<B: ibc::Backend>(windows: &Windows<B>, addr: VirtualAddress) -> IceResult<Self> {
        let val = windows.read_kernel_value(addr)?;
        Ok(val)
    }
}

impl<T> Readable for Pointer<T> {
    fn read<B: ibc::Backend>(windows: &Windows<B>, addr: VirtualAddress) -> IceResult<Self> {
        let addr = VirtualAddress(windows.read_kernel_value(addr)?);
        Ok(Pointer::new(addr))
    }
}

trait HasStruct<Layout> {
    fn get_struct_layout(&self) -> &Layout;
}

impl From<ibc::Thread> for Pointer<profile::Ethread> {
    fn from(thread: ibc::Thread) -> Self {
        Self::new(thread.0)
    }
}

impl From<Pointer<profile::Ethread>> for ibc::Thread {
    fn from(path: Pointer<profile::Ethread>) -> Self {
        Self(path.addr)
    }
}

impl From<ibc::Process> for Pointer<profile::Eprocess> {
    fn from(thread: ibc::Process) -> Self {
        Self::new(thread.0)
    }
}

impl From<Pointer<profile::Eprocess>> for ibc::Process {
    fn from(path: Pointer<profile::Eprocess>) -> Self {
        Self(path.addr)
    }
}

impl From<ibc::Vma> for Pointer<profile::MmvadShort> {
    fn from(vma: ibc::Vma) -> Self {
        Self::new(vma.0)
    }
}

impl From<Pointer<profile::MmvadShort>> for ibc::Vma {
    fn from(vma: Pointer<profile::MmvadShort>) -> Self {
        Self(vma.addr)
    }
}

const KERNEL_PDB: &[u8] = b"ntkrnlmp.pdb\0";

pub struct Windows<B> {
    pub backend: B,
    kpgd: PhysicalAddress,
    base_addr: VirtualAddress,
    profile: profile::Profile,
}

#[derive(Debug, Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[derive(Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct Codeview {
    magic: [u8; 4],
    guid: Guid,
    age: u32,
    name: [u8; 24],
}

impl Codeview {
    fn pdb_id(&self) -> String {
        use fmt::Write;

        let mut s = String::with_capacity(33);
        (|| {
            let Guid {
                data1,
                data2,
                data3,
                data4,
            } = self.guid;
            write!(s, "{data1:08X}{data2:04X}{data3:04X}")?;
            for x in data4 {
                write!(s, "{x:02X}")?;
            }
            write!(s, "{}", self.age)
        })()
        .expect("Failed to format GUID");
        s
    }

    fn name(&self) -> Result<&str, str::Utf8Error> {
        let i = self
            .name
            .iter()
            .enumerate()
            .find(|(_, b)| **b == 0)
            .unwrap()
            .0;
        str::from_utf8(&self.name[..i])
    }
}

fn pe_get_pdb_guid<B: Backend>(
    backend: &B,
    pgd: PhysicalAddress,
    addr: VirtualAddress,
    buf: &mut Vec<u8>,
) -> IceResult<Option<Codeview>> {
    buf.resize(0x1000, 0);
    backend.read_virtual_memory(pgd, addr, buf)?;

    if !buf.starts_with(b"MZ") {
        return Ok(None);
    }

    let pe = object::read::pe::PeFile::<'_, object::pe::ImageNtHeaders64>::parse(buf.as_slice())
        .map_err(IceError::new)?;
    let size = pe
        .nt_headers()
        .optional_header
        .size_of_image
        .get(object::endian::LittleEndian) as usize;
    buf.resize(size, 0);

    for i in 1..(size / 0x1000) {
        let _ = backend.read_virtual_memory(
            pgd,
            addr + i as u64 * 0x1000,
            &mut buf[i * 0x1000..(i + 1) * 0x1000],
        );
    }

    let index = match memchr::memmem::find(&buf, b"RSDS") {
        Some(i) => i,
        None => return Ok(None),
    };

    let mut codeview: Codeview = bytemuck::Zeroable::zeroed();
    bytemuck::bytes_of_mut(&mut codeview)
        .copy_from_slice(&buf[index..index + mem::size_of::<Codeview>()]);

    Ok(Some(codeview))
}

fn find_kernel<B: Backend>(
    backend: &B,
    kpgd: PhysicalAddress,
) -> IceResult<Option<(String, VirtualAddress)>> {
    let mut buf = vec![0; 0];

    for addr in backend
        .iter_in_kernel_memory(kpgd, b"MZ")
        .map_while(|addr| addr.ok())
        .filter(|addr| addr.0 & 0xfff == 0)
    {
        if let Ok(Some(codeview)) = pe_get_pdb_guid(backend, kpgd, addr, &mut buf) {
            if &codeview.name[..KERNEL_PDB.len()] == KERNEL_PDB {
                return Ok(Some((codeview.pdb_id(), addr)));
            }
        }
    }

    Ok(None)
}

impl<B: Backend> Windows<B> {
    pub fn create(backend: B, profile: ibc::SymbolsIndexer) -> IceResult<Self> {
        let profile = profile::Profile::new(profile)?;
        let kpgd = backend.find_kernel_pgd(false, &[VirtualAddress(0xfffff78000000000)])?;
        let (pdb_id, base_addr) =
            find_kernel(&backend, kpgd)?.context("failed to find kernel data")?;
        log::info!("Found kernel at 0x{base_addr:x} (PDB: {pdb_id})");
        let this = Self {
            backend,
            kpgd,
            base_addr,
            profile,
        };

        Ok(this)
    }

    #[allow(dead_code)]
    fn read_kernel_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()> {
        self.backend.read_virtual_memory(self.kpgd, addr, buf)
    }

    fn read_kernel_value<T: bytemuck::Pod>(&self, addr: VirtualAddress) -> IceResult<T> {
        self.backend.read_value_virtual(self.kpgd, addr)
    }

    /// Converts a pointer to a struct to a pointer to a field
    ///
    /// Generic parameters ensure that the conversion is valid.
    fn read_struct<L, T>(
        &self,
        pointer: Pointer<L>,
        get_offset: impl FnOnce(&L) -> StructOffset<T>,
    ) -> IceResult<Pointer<T>>
    where
        Self: HasStruct<L>,
    {
        if pointer.is_null() {
            return Err(IceError::deref_null_ptr());
        }
        let offset = get_offset(self.get_struct_layout());
        Ok(Pointer::new(pointer.addr + offset.offset))
    }

    /// Reads a field from a struct pointer
    fn read_struct_pointer<L, T: Readable>(
        &self,
        pointer: Pointer<L>,
        get_offset: impl FnOnce(&L) -> StructOffset<T>,
    ) -> IceResult<T>
    where
        Self: HasStruct<L>,
    {
        if pointer.is_null() {
            return Err(IceError::deref_null_ptr());
        }
        let offset = get_offset(self.get_struct_layout());
        T::read(self, pointer.addr + offset.offset)
    }

    /// Iterate a kernel linked list, yielding elements of type `T`
    fn iterate_list<T, O, F>(
        &self,
        head: Pointer<profile::ListEntry>,
        get_offset: O,
        mut f: F,
    ) -> IceResult<()>
    where
        Self: HasStruct<T> + HasStruct<profile::ListEntry>,
        O: FnOnce(&T) -> StructOffset<profile::ListEntry>,
        F: FnMut(Pointer<T>) -> IceResult<()>,
    {
        let mut pos = head;
        let offset = get_offset(self.get_struct_layout()).offset;

        loop {
            pos = self.read_struct_pointer(pos, |list| list.Flink)?;

            if pos == head {
                break;
            }

            f(Pointer::new(pos.addr - offset))?;
        }

        Ok(())
    }

    fn _iterate_tree<T, F>(
        &self,
        node: Pointer<profile::RtlBalancedNode>,
        f: &mut F,
    ) -> IceResult<()>
    where
        F: FnMut(Pointer<T>) -> IceResult<()>,
    {
        let left = self.read_struct_pointer(node, |node| node.Left)?;
        if !left.is_null() {
            self._iterate_tree(left, f)?;
        }

        f(Pointer::new(node.addr))?;

        let right = self.read_struct_pointer(node, |node| node.Right)?;
        if !right.is_null() {
            self._iterate_tree(right, f)?;
        }

        Ok(())
    }

    /// Iterate a kernel AVL tree, yielding elements of type `T`
    fn iterate_tree<T, O, F>(
        &self,
        root: Pointer<profile::RtlAvlTree>,
        get_offset: O,
        mut f: F,
    ) -> IceResult<()>
    where
        Self: HasStruct<T> + HasStruct<profile::RtlAvlTree> + HasStruct<profile::RtlBalancedNode>,
        O: FnOnce(&T) -> StructOffset<profile::RtlBalancedNode>,
        F: FnMut(Pointer<T>) -> IceResult<()>,
    {
        let node = self.read_struct_pointer(root, |tree| tree.Root)?;
        let offset = get_offset(self.get_struct_layout()).offset;

        if offset != 0 {
            return Err(IceError::new("Unsupported structure layout"));
        }

        self._iterate_tree(node, &mut f)
    }

    fn read_unicode_string(&self, ptr: Pointer<profile::UnicodeString>) -> IceResult<String> {
        let len = self.read_struct_pointer(ptr, |str| str.Length)?;
        let mut name = vec![0u16; len as usize / 2];

        let buffer = self.read_struct_pointer(ptr, |str| str.Buffer)?;
        self.backend
            .read_virtual_memory(self.kpgd, buffer, bytemuck::cast_slice_mut(&mut name))?;

        Ok(String::from_utf16_lossy(&name))
    }

    fn kpcr(&self, cpuid: usize) -> IceResult<Pointer<profile::Kpcr>> {
        let per_cpu = self.backend.kernel_per_cpu(cpuid)?;
        Ok(Pointer::new(per_cpu))
    }
}

impl<B: Backend> ibc::Os for Windows<B> {
    fn init_process(&self) -> IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn current_thread(&self, cpuid: usize) -> IceResult<ibc::Thread> {
        let kpcr = self.kpcr(cpuid)?;
        let kprcb = self.read_struct(kpcr, |k| k.Prcb)?;
        let thread = self.read_struct_pointer(kprcb, |k| k.CurrentThread)?;
        Ok(thread.into())
    }

    fn process_is_kernel(&self, _proc: ibc::Process) -> IceResult<bool> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_pid(&self, _proc: ibc::Process) -> IceResult<u64> {
        self.read_struct_pointer(_proc.into(), |eprocess| eprocess.UniqueProcessId)
    }

    fn process_name(&self, _proc: ibc::Process) -> IceResult<String> {
        let name = self.read_struct_pointer(_proc.into(), |eprocess| eprocess.ImageFileName)?;

        let name = match memchr::memchr(0, &name) {
            Some(i) => &name[..i],
            None => &name,
        };

        Ok(String::from_utf8_lossy(name).into_owned())
    }

    fn process_pgd(&self, proc: ibc::Process) -> IceResult<ibc::PhysicalAddress> {
        let kproc = self.read_struct(proc.into(), |eproc| eproc.Pcb)?;

        let dtb = self.read_struct_pointer(kproc, |kproc| kproc.UserDirectoryTableBase)?;

        if dtb.0 != 0 && dtb.0 != 1 {
            return Ok(dtb);
        }

        self.read_struct_pointer(kproc, |kproc| kproc.DirectoryTableBase)
    }

    fn process_exe(&self, _proc: ibc::Process) -> IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_parent(&self, proc: ibc::Process) -> IceResult<ibc::Process> {
        let parent_pid =
            self.read_struct_pointer(proc.into(), |e| e.InheritedFromUniqueProcessId)?;
        Ok(self.find_process_by_pid(parent_pid)?.unwrap_or(proc))
    }

    fn process_for_each_child(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Process) -> IceResult<()>,
    ) -> IceResult<()> {
        let pid = self.process_pid(proc)?;
        self.for_each_process(&mut |proc| {
            let parent_pid =
                self.read_struct_pointer(proc.into(), |e| e.InheritedFromUniqueProcessId)?;
            if parent_pid == pid {
                f(proc)
            } else {
                Ok(())
            }
        })
    }

    fn process_for_each_thread(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Thread) -> IceResult<()>,
    ) -> IceResult<()> {
        let thread_list = self.read_struct(proc.into(), |eproc| eproc.ThreadListHead)?;
        self.iterate_list::<profile::Ethread, _, _>(
            thread_list,
            |ethread| ethread.ThreadListEntry,
            |thread| f(thread.into()),
        )
    }

    fn for_each_process(&self, f: &mut dyn FnMut(ibc::Process) -> IceResult<()>) -> IceResult<()> {
        let head = self.base_addr + self.profile.fast_syms.PsActiveProcessHead;

        self.iterate_list::<profile::Eprocess, _, _>(
            Pointer::new(head),
            |ep| ep.ActiveProcessLinks,
            |proc| f(proc.into()),
        )
    }

    fn process_for_each_vma(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Vma) -> IceResult<()>,
    ) -> IceResult<()> {
        let vad_root = self.read_struct(proc.into(), |ep| ep.VadRoot)?;

        self.iterate_tree::<profile::MmvadShort, _, _>(
            vad_root,
            |vad| vad.VadNode,
            |mmvad| f(mmvad.into()),
        )
    }

    fn process_callstack(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn thread_process(&self, thread: ibc::Thread) -> IceResult<ibc::Process> {
        let tcb = self.read_struct(thread.into(), |k| k.Tcb)?;
        let proc = self.read_struct_pointer(tcb, |k| k.Process)?;
        Ok(proc.into())
    }

    fn thread_id(&self, thread: ibc::Thread) -> IceResult<u64> {
        let cid = self.read_struct(thread.into(), |ethread| ethread.Cid)?;
        self.read_struct_pointer(cid, |cid| cid.UniqueThread)
    }

    fn thread_name(&self, thread: ibc::Thread) -> IceResult<Option<String>> {
        let name = self.read_struct_pointer(thread.into(), |et| et.ThreadName)?;
        if name.is_null() {
            return Ok(None);
        }
        self.read_unicode_string(name).map(Some)
    }

    fn path_to_string(&self, _path: ibc::Path) -> IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_file(&self, _vma: ibc::Vma) -> IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_start(&self, vma: ibc::Vma) -> IceResult<VirtualAddress> {
        let vma = vma.into();
        let low = self.read_struct_pointer(vma, |mmvad| mmvad.StartingVpn)? as u64;
        let high = self.read_struct_pointer(vma, |mmvad| mmvad.StartingVpnHigh)? as u64;
        Ok(VirtualAddress(((high << 32) + low) << 12))
    }

    fn vma_end(&self, vma: ibc::Vma) -> IceResult<VirtualAddress> {
        let vma = vma.into();
        let low = self.read_struct_pointer(vma, |mmvad| mmvad.EndingVpn)? as u64;
        let high = self.read_struct_pointer(vma, |mmvad| mmvad.EndingVpnHigh)? as u64;
        Ok(VirtualAddress(((high << 32) + low + 1) << 12))
    }

    fn vma_flags(&self, _vma: ibc::Vma) -> IceResult<ibc::VmaFlags> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_offset(&self, _vma: ibc::Vma) -> IceResult<u64> {
        Ok(0)
    }

    fn resolve_symbol(&self, addr: VirtualAddress, proc: ibc::Process) -> IceResult<Option<&str>> {
        let vma = match self.process_find_vma_by_address(proc, addr)? {
            Some(vma) => vma,
            None => return Ok(None),
        };
        let pgd = self.process_pgd(proc)?;

        let vma_start = self.vma_start(vma)?;
        let codeview = pe_get_pdb_guid(&self.backend, pgd, vma_start, &mut Vec::new())?;
        let codeview = match codeview {
            Some(codeview) => codeview,
            None => return Ok(None),
        };

        match self.profile.syms.get_lib(codeview.name()?) {
            Ok(lib) => {
                let addr = VirtualAddress((addr - vma_start) as u64);
                Ok(lib.get_symbols(addr))
            }
            Err(_) => Ok(None),
        }
    }
}
