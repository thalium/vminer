use core::{fmt, mem};
use ibc::{Backend, IceError, IceResult, PhysicalAddress, ResultExt, VirtualAddress};

use self::profile::{Pointer, StructOffset};

pub mod profile;

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

const KERNEL_PDB: &[u8] = b"ntkrnlmp.pdb\0";

pub struct Windows<B> {
    pub backend: B,
    kpgd: PhysicalAddress,
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
    name: [u8; 13],
    _pad: [u8; 3],
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
        buf.resize(0x1000, 0);
        backend.read_virtual_memory(kpgd, addr, &mut buf).unwrap();

        let pe =
            object::read::pe::PeFile::<'_, object::pe::ImageNtHeaders64>::parse(buf.as_slice())
                .unwrap();
        let size = pe
            .nt_headers()
            .optional_header
            .size_of_image
            .get(object::endian::LittleEndian) as usize;
        buf.resize(size, 0);

        for i in 1..(size / 0x1000) {
            let _ = backend.read_virtual_memory(
                kpgd,
                addr + i as u64 * 0x1000,
                &mut buf[i * 0x1000..(i + 1) * 0x1000],
            );
        }

        let index = match memchr::memmem::find(&buf, b"RSDS") {
            Some(i) => i,
            None => continue,
        };

        let mut codeview: Codeview = bytemuck::Zeroable::zeroed();
        bytemuck::bytes_of_mut(&mut codeview)
            .copy_from_slice(&buf[index..index + mem::size_of::<Codeview>()]);

        if codeview.name != KERNEL_PDB {
            continue;
        }

        return Ok(Some((codeview.pdb_id(), addr)));
    }

    Ok(None)
}

impl<B: Backend> Windows<B> {
    pub fn create(backend: B, profile: profile::Profile) -> IceResult<Self> {
        let kpgd = backend.find_kernel_pgd(false, &[VirtualAddress(0xfffff78000000000)])?;
        let (pdb_id, addr) = find_kernel(&backend, kpgd)?.context("failed to find kernel data")?;
        println!("Found kernel at 0x{addr:x} (PDB: {pdb_id})");
        Ok(Self {
            backend,
            kpgd,
            profile,
        })
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
        println!("ADDR {:x?}", pointer.addr + offset.offset);
        T::read(self, pointer.addr + offset.offset)
    }

    fn kpcr(&self, cpuid: usize) -> IceResult<Pointer<profile::Kpcr>> {
        let per_cpu = self.backend.kernel_per_cpu(cpuid)?;
        // let addr = VirtualAddress(self.read_kernel_value(per_cpu)?);
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
        // println!("TEST {:x}", self.read_struct_pointer(kprcb, |k| k.KernelDirectoryTableBase)?);
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
        println!("- 0x{name:x}");
        let mut buf = [0; 15];
        self.read_kernel_memory(name, &mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    fn process_pgd(&self, _proc: ibc::Process) -> IceResult<ibc::PhysicalAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_exe(&self, _proc: ibc::Process) -> IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_parent(&self, _proc: ibc::Process) -> IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_child(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Process) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_thread(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Thread) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn for_each_process(&self, _f: &mut dyn FnMut(ibc::Process) -> IceResult<()>) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_vma(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Vma) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
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

    fn thread_name(&self, _thread: ibc::Thread) -> IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn path_to_string(&self, _path: ibc::Path) -> IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_file(&self, _vma: ibc::Vma) -> IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_start(&self, _vma: ibc::Vma) -> IceResult<VirtualAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_end(&self, _vma: ibc::Vma) -> IceResult<VirtualAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_flags(&self, _vma: ibc::Vma) -> IceResult<ibc::VmaFlags> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_offset(&self, _vma: ibc::Vma) -> IceResult<u64> {
        Err(ibc::IceError::unimplemented())
    }

    fn resolve_symbol(&self, _addr: VirtualAddress, _vma: ibc::Vma) -> IceResult<Option<&str>> {
        Err(ibc::IceError::unimplemented())
    }
}
