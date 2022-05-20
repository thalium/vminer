use super::pointer::{Context, HasLayout, Pointer, StructOffset};
use core::{fmt, mem, str};
use ibc::{Backend, IceError, IceResult, Os, PhysicalAddress, ResultExt, VirtualAddress};

mod callstack;
mod profile;

struct ProcSpace<'a, B: Backend> {
    os: &'a Windows<B>,
    pgd: ibc::PhysicalAddress,
}

impl<B: Backend> Clone for ProcSpace<'_, B> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<B: Backend> Copy for ProcSpace<'_, B> {}

impl<B: Backend> Context for ProcSpace<'_, B> {
    #[inline]
    fn read_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()> {
        if addr.is_kernel() {
            self.os.read_virtual_memory(self.os.kernel_pgd(), addr, buf)
        } else {
            self.os.read_virtual_memory(self.pgd, addr, buf)
        }
    }
}

impl<B: Backend> ProcSpace<'_, B> {
    #[inline]
    fn profile(&self) -> &profile::Profile {
        &self.os.profile
    }
}

impl<B: Backend> Context for &Windows<B> {
    #[inline]
    fn read_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()> {
        self.read_virtual_memory(self.kpgd, addr, buf)
    }
}

pointer_defs! {
    ibc::Module = profile::LdrDataTableEntry;
    ibc::Path = profile::FileObject;
    ibc::Process = profile::Eprocess;
    ibc::Thread = profile::Ethread;
    ibc::Vma = profile::MmvadShort;
}

impl<'a, T, B: Backend> Pointer<T, &'a Windows<B>> {
    fn switch_to_userspace(self, proc: ibc::Process) -> IceResult<Pointer<T, ProcSpace<'a, B>>> {
        let pgd = self.ctx.process_pgd(proc)?;
        let proc_space = ProcSpace { os: self.ctx, pgd };
        Ok(self.switch_context(proc_space))
    }
}

impl<Ctx: HasLayout<profile::UnicodeString>> Pointer<profile::UnicodeString, Ctx> {
    fn read_unicode_string(self) -> IceResult<String> {
        let buffer = self.read_field(|str| str.Buffer)?;
        let len = self.read_field(|str| str.Length)?;

        let mut name = vec![0u16; len as usize / 2];
        self.ctx
            .read_memory(buffer, bytemuck::cast_slice_mut(&mut name))?;
        Ok(String::from_utf16_lossy(&name))
    }
}

impl<T, Ctx> Pointer<profile::ListEntry<T>, Ctx>
where
    Ctx: HasLayout<profile::ListEntry> + HasLayout<T>,
{
    /// Iterate a linked list, yielding elements of type `T`
    fn iterate_list<O, F>(self, get_offset: O, mut f: F) -> IceResult<()>
    where
        O: FnOnce(&T) -> StructOffset<profile::ListEntry<T>>,
        F: FnMut(Pointer<T, Ctx>) -> IceResult<()>,
    {
        let mut pos: Pointer<profile::ListEntry, Ctx> = self.monomorphize();
        let offset = get_offset(self.ctx.get_layout()).offset;

        loop {
            pos = pos.read_pointer_field(|list| list.Flink)?;

            if pos == self {
                break;
            }

            f(Pointer::new(pos.addr - offset, self.ctx))?;
        }

        Ok(())
    }
}

impl<Ctx: HasLayout<profile::RtlBalancedNode>> Pointer<profile::RtlBalancedNode, Ctx> {
    fn _iterate_tree<T, F>(self, f: &mut F) -> IceResult<()>
    where
        F: FnMut(Pointer<T, Ctx>) -> IceResult<()>,
    {
        let left = self.read_pointer_field(|node| node.Left)?;
        if !left.is_null() {
            left._iterate_tree(f)?;
        }

        f(Pointer::new(self.addr, self.ctx))?;

        let right = self.read_pointer_field(|node| node.Right)?;
        if !right.is_null() {
            right._iterate_tree(f)?;
        }

        Ok(())
    }
}

impl<T, Ctx> Pointer<profile::RtlAvlTree<T>, Ctx>
where
    Ctx: HasLayout<profile::RtlAvlTree> + HasLayout<profile::RtlBalancedNode> + HasLayout<T>,
{
    /// Iterate a kernel AVL tree, yielding elements of type `T`
    fn iterate_tree<O, F>(self, get_offset: O, mut f: F) -> IceResult<()>
    where
        O: FnOnce(&T) -> StructOffset<profile::RtlBalancedNode<T>>,
        F: FnMut(Pointer<T, Ctx>) -> IceResult<()>,
    {
        let node = self.monomorphize().read_pointer_field(|tree| tree.Root)?;
        let offset = get_offset(self.ctx.get_layout()).offset;

        if offset != 0 {
            return Err(IceError::new("Unsupported structure layout"));
        }

        node._iterate_tree(&mut f)
    }
}

fn read_virtual_memory<B: Backend>(
    backend: &B,
    kpgd: PhysicalAddress,
    mmu_addr: PhysicalAddress,
    addr: VirtualAddress,
    buf: &mut [u8],
) -> ibc::TranslationResult<()> {
    let entry = match backend.read_virtual_memory(mmu_addr, addr, buf) {
        Ok(()) => return Ok(()),
        Err(ibc::TranslationError::Invalid(entry)) => entry,
        Err(ibc::TranslationError::Memory(err)) => return Err(err.into()),
    };

    let offset = addr.0 & ibc::mask(12);

    if entry & (1 << 10) != 0 {
        let entry: u64 = backend.read_value_virtual(kpgd, VirtualAddress(entry >> 16))?;
        if entry & 0x1 != 0 {
            let addr_base = PhysicalAddress(entry & ibc::mask_range(12, 48));
            backend.read_memory(addr_base + offset, buf)?;
            return Ok(());
        } else if entry & (1 << 10) == 0 && entry & (1 << 11) != 0 {
            let addr_base = PhysicalAddress(entry & ibc::mask_range(12, 40));
            backend.read_memory(addr_base + offset, buf)?;
            return Ok(());
        }
    } else if entry & (1 << 11) != 0 {
        let addr_base = PhysicalAddress(entry & ibc::mask_range(12, 40));
        backend.read_memory(addr_base + offset, buf)?;
        return Ok(());
    }

    Err(ibc::TranslationError::Invalid(entry))
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

    fn name(&self) -> Option<&str> {
        let i = self.name.iter().enumerate().find(|(_, b)| **b == 0)?.0;
        str::from_utf8(&self.name[..i]).ok()
    }
}

fn pe_get_pdb_guid<B: Backend>(
    backend: &B,
    kpgd: PhysicalAddress,
    pgd: PhysicalAddress,
    addr: VirtualAddress,
    buf: &mut Vec<u8>,
) -> IceResult<Option<Codeview>> {
    buf.resize(0x1000, 0);
    read_virtual_memory(backend, kpgd, pgd, addr, buf)?;

    if !buf.starts_with(b"MZ") {
        return Ok(None);
    }

    let pe = object::read::pe::PeFile64::parse(buf.as_slice()).map_err(IceError::new)?;
    let size = pe
        .nt_headers()
        .optional_header
        .size_of_image
        .get(object::endian::LittleEndian) as usize;
    buf.resize(size, 0);

    ibc::try_read_virtual_memory(addr, buf, |addr, buf| {
        read_virtual_memory(backend, kpgd, pgd, addr, buf)
    })?;

    let mut codeview: Codeview = bytemuck::Zeroable::zeroed();
    for index in memchr::memmem::find_iter(&buf, b"RSDS") {
        bytemuck::bytes_of_mut(&mut codeview)
            .copy_from_slice(&buf[index..index + mem::size_of::<Codeview>()]);

        if codeview.name().is_some() {
            return Ok(Some(codeview));
        }
    }

    Ok(None)
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
        if let Ok(Some(codeview)) = pe_get_pdb_guid(backend, kpgd, kpgd, addr, &mut buf) {
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

    #[inline]
    fn profile(&self) -> &profile::Profile {
        &self.profile
    }

    #[inline]
    fn pointer_of<'a, T: AsPointer<U>, U>(&'a self, ptr: T) -> Pointer<U, &'a Self> {
        ptr.as_pointer(self)
    }

    #[inline]
    fn kpcr(&self, cpuid: usize) -> IceResult<Pointer<profile::Kpcr, &Self>> {
        let per_cpu = self.backend.kernel_per_cpu(cpuid)?;
        Ok(Pointer::new(per_cpu, self))
    }
}

impl<B: Backend> ibc::Os for Windows<B> {
    fn read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> IceResult<()> {
        ibc::read_virtual_memory(addr, buf, |addr, buf| {
            read_virtual_memory(&self.backend, self.kpgd, mmu_addr, addr, buf)
        })?;
        Ok(())
    }

    fn try_read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> IceResult<()> {
        ibc::try_read_virtual_memory(addr, buf, |addr, buf| {
            read_virtual_memory(&self.backend, self.kpgd, mmu_addr, addr, buf)
        })?;
        Ok(())
    }

    #[inline]
    fn kernel_pgd(&self) -> PhysicalAddress {
        self.kpgd
    }

    fn init_process(&self) -> IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn for_each_kernel_module(
        &self,
        f: &mut dyn FnMut(ibc::Module) -> IceResult<()>,
    ) -> IceResult<()> {
        let head = self.base_addr + self.profile.fast_syms.PsLoadedModuleList;
        let head: Pointer<profile::ListEntry<profile::LdrDataTableEntry>, _> =
            Pointer::new(head, self);

        head.iterate_list(|entry| entry.InLoadOrderLinks, |module| f(module.into()))
    }

    fn current_thread(&self, cpuid: usize) -> IceResult<ibc::Thread> {
        let thread = self
            .kpcr(cpuid)?
            .field(|kpcr| kpcr.Prcb)?
            .read_pointer_field(|kprcb| kprcb.CurrentThread)?;
        Ok(thread.into())
    }

    fn process_is_kernel(&self, _proc: ibc::Process) -> IceResult<bool> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_pid(&self, proc: ibc::Process) -> IceResult<u64> {
        self.pointer_of(proc)
            .read_field(|eproc| eproc.UniqueProcessId)
    }

    fn process_name(&self, proc: ibc::Process) -> IceResult<String> {
        let name = self
            .pointer_of(proc)
            .read_field(|eproc| eproc.ImageFileName)?;

        let name = match memchr::memchr(0, &name) {
            Some(i) => &name[..i],
            None => &name,
        };

        Ok(String::from_utf8_lossy(name).into_owned())
    }

    fn process_pgd(&self, proc: ibc::Process) -> IceResult<ibc::PhysicalAddress> {
        if proc.0.is_null() {
            return Ok(self.kpgd);
        }

        let kproc = self.pointer_of(proc).field(|eproc| eproc.Pcb)?;

        let dtb = kproc.read_field(|kproc| kproc.UserDirectoryTableBase)?;
        if dtb.0 != 0 && dtb.0 != 1 {
            return Ok(dtb);
        }

        kproc.read_field(|kproc| kproc.DirectoryTableBase)
    }

    fn process_exe(&self, proc: ibc::Process) -> IceResult<Option<ibc::Path>> {
        self.pointer_of(proc)
            .read_pointer_field(|e| e.ImageFilePointer)?
            .map_non_null(|path| Ok(path.into()))
    }

    fn process_parent(&self, proc: ibc::Process) -> IceResult<ibc::Process> {
        let parent_pid = self.process_parent_id(proc)?;
        Ok(self.find_process_by_pid(parent_pid)?.unwrap_or(proc))
    }

    fn process_parent_id(&self, proc: ibc::Process) -> IceResult<u64> {
        self.pointer_of(proc)
            .read_field(|eproc| eproc.InheritedFromUniqueProcessId)
    }

    fn process_for_each_child(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Process) -> IceResult<()>,
    ) -> IceResult<()> {
        let pid = self.process_pid(proc)?;
        self.for_each_process(&mut |proc| {
            if self.process_parent_id(proc)? == pid {
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
        self.pointer_of(proc)
            .field(|eproc| eproc.ThreadListHead)?
            .iterate_list(|ethread| ethread.ThreadListEntry, |thread| f(thread.into()))
    }

    fn for_each_process(&self, f: &mut dyn FnMut(ibc::Process) -> IceResult<()>) -> IceResult<()> {
        let head = self.base_addr + self.profile.fast_syms.PsActiveProcessHead;
        let head: Pointer<profile::ListEntry<profile::Eprocess>, _> = Pointer::new(head, self);

        head.iterate_list(|eproc| eproc.ActiveProcessLinks, |proc| f(proc.into()))
    }

    fn process_for_each_vma(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Vma) -> IceResult<()>,
    ) -> IceResult<()> {
        self.pointer_of(proc)
            .field(|eproc| eproc.VadRoot)?
            .iterate_tree(|vad| vad.VadNode, |mmvad| f(mmvad.into()))
    }

    fn process_for_each_module(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Module) -> IceResult<()>,
    ) -> IceResult<()> {
        let peb = self.pointer_of(proc).read_pointer_field(|e| e.Peb)?;
        if peb.is_null() {
            return Ok(());
        }

        peb.switch_to_userspace(proc)?
            .read_pointer_field(|peb| peb.Ldr)?
            .field(|ldr| ldr.InLoadOrderModuleList)?
            .iterate_list(|module| module.InLoadOrderLinks, |module| f(module.into()))
    }

    fn process_callstack(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<()>,
    ) -> IceResult<()> {
        self.iter_process_callstack(proc, f)
    }

    fn thread_process(&self, thread: ibc::Thread) -> IceResult<ibc::Process> {
        let proc = self
            .pointer_of(thread)
            .field(|ethread| ethread.Tcb)?
            .read_pointer_field(|kthread| kthread.Process)?;
        Ok(proc.into())
    }

    fn thread_id(&self, thread: ibc::Thread) -> IceResult<u64> {
        self.pointer_of(thread)
            .field(|ethread| ethread.Cid)?
            .read_field(|cid| cid.UniqueThread)
    }

    fn thread_name(&self, thread: ibc::Thread) -> IceResult<Option<String>> {
        self.pointer_of(thread)
            .read_pointer_field(|ethread| ethread.ThreadName)?
            .map_non_null(|name| name.read_unicode_string())
    }

    fn path_to_string(&self, path: ibc::Path) -> IceResult<String> {
        self.pointer_of(path)
            .field(|file_object| file_object.FileName)?
            .read_unicode_string()
    }

    fn vma_file(&self, _vma: ibc::Vma) -> IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_start(&self, vma: ibc::Vma) -> IceResult<VirtualAddress> {
        let vma = self.pointer_of(vma);
        let low = vma.read_field(|mmvad| mmvad.StartingVpn)? as u64;
        let high = vma.read_field(|mmvad| mmvad.StartingVpnHigh)? as u64;
        Ok(VirtualAddress(((high << 32) + low) << 12))
    }

    fn vma_end(&self, vma: ibc::Vma) -> IceResult<VirtualAddress> {
        let vma = self.pointer_of(vma);
        let low = vma.read_field(|mmvad| mmvad.EndingVpn)? as u64;
        let high = vma.read_field(|mmvad| mmvad.EndingVpnHigh)? as u64;
        Ok(VirtualAddress(((high << 32) + low + 1) << 12))
    }

    fn vma_flags(&self, _vma: ibc::Vma) -> IceResult<ibc::VmaFlags> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_offset(&self, _vma: ibc::Vma) -> IceResult<u64> {
        Ok(0)
    }

    fn module_span(
        &self,
        module: ibc::Module,
        proc: ibc::Process,
    ) -> IceResult<(VirtualAddress, VirtualAddress)> {
        let module = self.pointer_of(module).switch_to_userspace(proc)?;
        let dll_base = module.read_field(|module| module.DllBase)?;
        let size = module.read_field(|module| module.SizeOfImage)?;
        Ok((dll_base, dll_base + size as u64))
    }

    fn module_name(&self, module: ibc::Module, proc: ibc::Process) -> IceResult<String> {
        self.pointer_of(module)
            .switch_to_userspace(proc)?
            .field(|module| module.BaseDllName)?
            .read_unicode_string()
    }

    fn module_path(&self, module: ibc::Module, proc: ibc::Process) -> IceResult<String> {
        self.pointer_of(module)
            .switch_to_userspace(proc)?
            .field(|module| module.FullDllName)?
            .read_unicode_string()
    }

    fn module_resolve_symbol_exact(
        &self,
        addr: VirtualAddress,
        proc: ibc::Process,
        module: ibc::Module,
    ) -> IceResult<Option<&str>> {
        let (mod_start, mod_end) = self.module_span(module, proc)?;
        if !(mod_start..mod_end).contains(&addr) {
            return Err(IceError::new("address not in module"));
        }

        let pgd = if addr.is_kernel() {
            self.kernel_pgd()
        } else {
            self.process_pgd(proc)?
        };

        let codeview = pe_get_pdb_guid(&self.backend, self.kpgd, pgd, mod_start, &mut Vec::new())?;
        let codeview = match codeview {
            Some(codeview) => codeview,
            None => return Ok(None),
        };

        match self.profile.syms.get_lib(codeview.name().unwrap()) {
            Ok(lib) => {
                let addr = VirtualAddress((addr - mod_start) as u64);
                Ok(lib.get_symbol(addr))
            }
            Err(_) => Ok(None),
        }
    }

    fn module_resolve_symbol(
        &self,
        addr: VirtualAddress,
        proc: ibc::Process,
        module: ibc::Module,
    ) -> IceResult<Option<(&str, u64)>> {
        let (mod_start, mod_end) = self.module_span(module, proc)?;
        if !(mod_start..mod_end).contains(&addr) {
            return Err(IceError::new("address not in module"));
        }

        let pgd = if addr.is_kernel() {
            self.kernel_pgd()
        } else {
            self.process_pgd(proc)?
        };

        let codeview = pe_get_pdb_guid(&self.backend, self.kpgd, pgd, mod_start, &mut Vec::new())?;
        let codeview = match codeview {
            Some(codeview) => codeview,
            None => return Ok(None),
        };

        match self.profile.syms.get_lib(codeview.name().unwrap()) {
            Ok(lib) => {
                let addr = VirtualAddress((addr - mod_start) as u64);
                Ok(lib.get_symbol_inexact(addr))
            }
            Err(_) => Ok(None),
        }
    }
}
