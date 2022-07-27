use super::pointer::{self, Context, HasLayout, KernelSpace, Pointer, StructOffset};
use core::{fmt, mem, ops::ControlFlow, str};
use ibc::{IceError, IceResult, PhysicalAddress, ResultExt, VirtualAddress};

mod callstack;
#[cfg(feature = "std")]
mod loader;
mod memory;
mod profile;

#[cfg(feature = "std")]
pub use loader::SymbolLoader;

pointer_defs! {
    ibc::Module = profile::LdrDataTableEntry;
    ibc::Process = profile::Eprocess;
    ibc::Thread = profile::Ethread;
    ibc::Vma = profile::MmvadShort;
}

impl<B: ibc::Backend, Ctx> Pointer<'_, profile::UnicodeString, Windows<B>, Ctx>
where
    Ctx: Context<Windows<B>>,
{
    fn read_unicode_string(self) -> IceResult<String> {
        let buffer = self.read_field(|str| str.Buffer)?;
        let len = self.read_field(|str| str.Length)?;

        let mut name = vec![0u16; len as usize / 2];
        self.ctx
            .read_memory(self.os, buffer, bytemuck::cast_slice_mut(&mut name))?;
        Ok(String::from_utf16_lossy(&name))
    }
}

impl<T, B: ibc::Backend, Ctx> Pointer<'_, profile::ListEntry<T>, Windows<B>, Ctx>
where
    Ctx: Context<Windows<B>>,
    Windows<B>: HasLayout<T, Ctx>,
{
    /// Iterate a linked list, yielding elements of type `T`
    fn iterate_list<O, F>(self, get_offset: O, mut f: F) -> IceResult<()>
    where
        O: FnOnce(&T) -> StructOffset<profile::ListEntry<T>>,
        F: FnMut(Pointer<T, Windows<B>, Ctx>) -> IceResult<ControlFlow<()>>,
    {
        let mut pos: Pointer<profile::ListEntry, _, _> = self.monomorphize();
        let offset = get_offset(self.os.get_layout()).offset;

        loop {
            pos = pos.read_pointer_field(|list| list.Flink)?;

            if pos == self {
                break;
            }

            if f(Pointer::new(pos.addr - offset, self.os, self.ctx))?.is_break() {
                break;
            }
        }

        Ok(())
    }
}

impl<'a, B: ibc::Backend> Pointer<'a, profile::RtlBalancedNode, Windows<B>> {
    fn _iterate_tree<T, F>(self, f: &mut F) -> IceResult<ControlFlow<()>>
    where
        F: FnMut(Pointer<T, Windows<B>>) -> IceResult<ControlFlow<()>>,
    {
        let left = self.read_pointer_field(|node| node.Left)?;
        if !left.is_null() && left._iterate_tree(f)?.is_break() {
            return Ok(ControlFlow::Break(()));
        }

        if f(Pointer::new(self.addr, self.os, self.ctx))?.is_break() {
            return Ok(ControlFlow::Break(()));
        }

        let right = self.read_pointer_field(|node| node.Right)?;
        if !right.is_null() && right._iterate_tree(f)?.is_break() {
            return Ok(ControlFlow::Break(()));
        }

        Ok(ControlFlow::Continue(()))
    }

    fn _find_in_tree<T, F>(self, f: &mut F) -> IceResult<Option<Pointer<'a, T, Windows<B>>>>
    where
        F: FnMut(Pointer<T, Windows<B>>) -> IceResult<core::cmp::Ordering>,
    {
        let ptr = Pointer::new(self.addr, self.os, self.ctx);

        match f(ptr)? {
            core::cmp::Ordering::Less => {
                let right = self.read_pointer_field(|node| node.Right)?;
                if right.is_null() {
                    Ok(None)
                } else {
                    right._find_in_tree(f)
                }
            }
            core::cmp::Ordering::Equal => Ok(Some(ptr)),
            core::cmp::Ordering::Greater => {
                let left = self.read_pointer_field(|node| node.Left)?;
                if left.is_null() {
                    Ok(None)
                } else {
                    left._find_in_tree(f)
                }
            }
        }
    }
}

impl<'a, T, B: ibc::Backend> Pointer<'a, profile::RtlAvlTree<T>, Windows<B>>
where
    Windows<B>: HasLayout<T>,
{
    /// Iterate a kernel AVL tree, yielding elements of type `T`
    fn iterate_tree<O, F>(self, get_offset: O, mut f: F) -> IceResult<()>
    where
        O: FnOnce(&T) -> StructOffset<profile::RtlBalancedNode<T>>,
        F: FnMut(Pointer<T, Windows<B>>) -> IceResult<ControlFlow<()>>,
    {
        let node = self.monomorphize().read_pointer_field(|tree| tree.Root)?;
        let offset = get_offset(self.os.get_layout()).offset;

        if offset != 0 {
            return Err(IceError::new("Unsupported structure layout"));
        }

        node._iterate_tree(&mut f)?;
        Ok(())
    }

    fn find_in_tree<O, F>(
        self,
        get_offset: O,
        mut f: F,
    ) -> IceResult<Option<Pointer<'a, T, Windows<B>>>>
    where
        O: FnOnce(&T) -> StructOffset<profile::RtlBalancedNode<T>>,
        F: FnMut(Pointer<T, Windows<B>>) -> IceResult<core::cmp::Ordering>,
    {
        let node = self.monomorphize().read_pointer_field(|tree| tree.Root)?;
        let offset = get_offset(self.os.get_layout()).offset;

        if offset != 0 {
            return Err(IceError::new("Unsupported structure layout"));
        }

        node._find_in_tree(&mut f)
    }
}

const KERNEL_PDB: &[u8] = b"ntkrnlmp.pdb\0";
const KERNEL_PDB_STR: &str = "ntkrnlmp.pdb";

pub struct Windows<B> {
    backend: B,
    symbols_loader: Box<dyn super::SymbolLoader + Send + Sync>,
    kpgd: PhysicalAddress,
    base_addr: VirtualAddress,
    profile: profile::Profile,

    unswizzle_mask: u64,
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
        let i = memchr::memchr(0, &self.name)?;
        let name = str::from_utf8(&self.name[..i]).ok()?;
        if !name.as_bytes().iter().all(|c| (0x20..0x80).contains(c)) {
            return None;
        }
        Some(name)
    }
}

fn pe_get_pdb_guid<E>(
    addr: VirtualAddress,
    size: Option<u64>,
    try_read_memory: impl Fn(VirtualAddress, &mut [u8]) -> Result<(), E>,
) -> IceResult<Option<Codeview>>
where
    IceError: From<E>,
{
    let mut buffer = [0; 0x1008];
    try_read_memory(addr, &mut buffer[8..])?;

    let size = match size {
        Some(size) => size,
        None => object::read::pe::PeFile64::parse(&buffer[8..])
            .map_err(IceError::new)?
            .nt_headers()
            .optional_header
            .size_of_image
            .get(object::endian::LittleEndian) as u64,
    };

    for offset in (0..size).step_by(0x1000) {
        for index in memchr::memmem::find_iter(&buffer, b"RSDS") {
            let codeview: Codeview = match &buffer.get(index..index + mem::size_of::<Codeview>()) {
                Some(bytes) => bytemuck::pod_read_unaligned(bytes),
                None => {
                    let mut codeview = bytemuck::Zeroable::zeroed();
                    try_read_memory(
                        addr + offset + index as u64,
                        bytemuck::bytes_of_mut(&mut codeview),
                    )?;
                    codeview
                }
            };

            if codeview.name().is_some() {
                return Ok(Some(codeview));
            }
        }

        buffer.copy_within(0x1000.., 0);
        try_read_memory(addr + offset, &mut buffer[8..])?;
    }

    Ok(None)
}

fn find_kernel_pgd<B: ibc::Backend>(backend: &B) -> IceResult<PhysicalAddress> {
    backend
        .find_kernel_pgd(false, &[VirtualAddress(0xfffff78000000000)])
        .context("could not find kernel PGD")
}

fn find_kernel<B: ibc::Backend>(
    backend: &B,
    kpgd: PhysicalAddress,
) -> IceResult<Option<(String, VirtualAddress)>> {
    for addr in backend
        .iter_in_kernel_memory(kpgd, b"MZ")
        .map_while(|addr| addr.ok())
        .filter(|addr| addr.0 & 0xfff == 0)
    {
        let codeview = pe_get_pdb_guid(addr, None, |addr, buf| {
            ibc::try_read_virtual_memory(addr, buf, |addr, buf| {
                backend.read_virtual_memory(kpgd, addr, buf)
            })
        });
        if let Ok(Some(codeview)) = codeview {
            if &codeview.name[..KERNEL_PDB.len()] == KERNEL_PDB {
                return Ok(Some((codeview.pdb_id(), addr)));
            }
        }
    }

    Ok(None)
}

impl<B: ibc::Backend> Windows<B> {
    pub fn create(backend: B, symbols: ibc::SymbolsIndexer) -> IceResult<Self> {
        super::os_builder().with_symbols(symbols).build(backend)
    }

    #[inline]
    fn profile(&self) -> &profile::Profile {
        &self.profile
    }

    #[inline]
    fn pointer_of<T: ToPointer<U>, U>(&self, ptr: T) -> Pointer<U, Self> {
        ptr.to_pointer(self, KernelSpace)
    }

    #[inline]
    fn kpcr(&self, cpuid: usize) -> IceResult<Pointer<profile::Kpcr, Self>> {
        let per_cpu = self.backend.kernel_per_cpu(cpuid)?;
        Ok(Pointer::new(per_cpu, self, KernelSpace))
    }

    fn module_codeview(
        &self,
        proc: ibc::Process,
        module: ibc::Module,
    ) -> IceResult<Option<Codeview>> {
        use ibc::Os;

        let (mod_start, mod_end) = self.module_span(module, proc)?;
        let mod_size = (mod_end - mod_start) as u64;
        let pgd = self.process_pgd(proc)?;

        pe_get_pdb_guid(mod_start, Some(mod_size), |addr, buf| {
            self.try_read_process_memory(proc, pgd, addr, buf)
        })
    }
}

impl<B: ibc::Backend> super::Buildable<B> for Windows<B> {
    fn quick_check(backend: &B) -> Option<super::OsBuilder> {
        let kpgd = find_kernel_pgd(backend).ok()?;
        let (pdb_id, kaslr) = find_kernel(backend, kpgd).ok()??;
        Some(super::OsBuilder {
            kpgd: Some(kpgd),
            kaslr: Some(kaslr),
            version: Some(pdb_id),
            symbols: None,
            loader: None,
        })
    }

    fn build(backend: B, builder: super::OsBuilder) -> IceResult<Self> {
        let kpgd = match builder.kpgd {
            Some(kpgd) => kpgd,
            None => find_kernel_pgd(&backend)?,
        };
        log::debug!("Found Windows PGD at 0x{kpgd:x}");

        let (pdb_id, base_addr) = match builder.kaslr {
            Some(kaslr) => {
                let pdb_id = builder.version.context("missing version")?;
                (pdb_id, kaslr)
            }
            None => find_kernel(&backend, kpgd)
                .context("failed to find kernel data")?
                .context("failed to find kernel data")?,
        };

        log::info!("Found kernel at 0x{base_addr:x} (PDB: {pdb_id})");

        let symbols_loader = match builder.loader {
            Some(loader) => loader,
            #[cfg(target_os = "windows")]
            None => Box::new(loader::SymbolLoader::with_system_root()?),
            #[cfg(all(feature = "std", not(target_os = "windows")))]
            None => Box::new(loader::SymbolLoader::with_root("./data/windows".into())?),
            #[cfg(not(feature = "std"))]
            None => Box::new(super::EmptyLoader),
        };

        let symbols = builder.symbols.unwrap_or_else(ibc::SymbolsIndexer::new);
        symbols.load_module("ntoskrnl.exe".into(), &mut |_| {
            let module = symbols_loader.load(KERNEL_PDB_STR, &pdb_id)?;
            Ok(alloc::sync::Arc::new(module))
        })?;
        let profile = profile::Profile::new(symbols)?;

        let bits = base_addr + profile.fast_syms.KiImplementedPhysicalBits;
        let bits: u64 = backend.read_value_virtual(kpgd, bits)?;
        let unswizzle_mask = !(1 << (bits - 1));

        Ok(Windows {
            backend,
            symbols_loader,
            kpgd,
            base_addr,
            profile,
            unswizzle_mask,
        })
    }
}

impl<B: ibc::Backend> ibc::Os for Windows<B> {
    fn vcpus(&self) -> ibc::arch::runtime::Vcpus {
        use ibc::arch::Vcpus;
        self.backend.vcpus().into_runtime()
    }

    fn read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> IceResult<()> {
        ibc::read_virtual_memory(addr, buf, |addr, buf| {
            self.read_virtual_memory_raw(mmu_addr, addr, buf, None)
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
            self.read_virtual_memory_raw(mmu_addr, addr, buf, None)
        })?;
        Ok(())
    }

    fn read_process_memory(
        &self,
        proc: ibc::Process,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> IceResult<()> {
        ibc::read_virtual_memory(addr, buf, |addr, buf| {
            self.read_virtual_memory_raw(mmu_addr, addr, buf, Some(proc))
        })?;
        Ok(())
    }

    fn try_read_process_memory(
        &self,
        proc: ibc::Process,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> IceResult<()> {
        ibc::try_read_virtual_memory(addr, buf, |addr, buf| {
            self.read_virtual_memory_raw(mmu_addr, addr, buf, Some(proc))
        })?;
        Ok(())
    }

    #[inline]
    fn kernel_pgd(&self) -> PhysicalAddress {
        self.kpgd
    }

    fn init_process(&self) -> IceResult<ibc::Process> {
        Err(ibc::IceError::unsupported())
    }

    fn for_each_kernel_module(
        &self,
        f: &mut dyn FnMut(ibc::Module) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        let head = self.base_addr + self.profile.fast_syms.PsLoadedModuleList;
        let head: Pointer<profile::ListEntry<profile::LdrDataTableEntry>, _> =
            Pointer::new(head, self, KernelSpace);

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

    fn process_id(&self, proc: ibc::Process) -> IceResult<u64> {
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

    fn process_path(&self, proc: ibc::Process) -> IceResult<Option<String>> {
        self.pointer_of(proc)
            .read_pointer_field(|e| e.ImageFilePointer)?
            .map_non_null(|path| {
                path.field(|file_object| file_object.FileName)?
                    .read_unicode_string()
            })
    }

    fn process_parent(&self, proc: ibc::Process) -> IceResult<ibc::Process> {
        let parent_pid = self.process_parent_id(proc)?;
        Ok(self.find_process_by_id(parent_pid)?.unwrap_or(proc))
    }

    fn process_parent_id(&self, proc: ibc::Process) -> IceResult<u64> {
        self.pointer_of(proc)
            .read_field(|eproc| eproc.InheritedFromUniqueProcessId)
    }

    fn process_for_each_child(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Process) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        let pid = self.process_id(proc)?;
        self.for_each_process(&mut |proc| {
            if self.process_parent_id(proc)? == pid {
                f(proc)
            } else {
                Ok(ControlFlow::Continue(()))
            }
        })
    }

    fn process_for_each_thread(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Thread) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        self.pointer_of(proc)
            .field(|eproc| eproc.ThreadListHead)?
            .iterate_list(|ethread| ethread.ThreadListEntry, |thread| f(thread.into()))
    }

    fn for_each_process(
        &self,
        f: &mut dyn FnMut(ibc::Process) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        let head = self.base_addr + self.profile.fast_syms.PsActiveProcessHead;
        let head: Pointer<profile::ListEntry<profile::Eprocess>, _> =
            Pointer::new(head, self, KernelSpace);

        head.iterate_list(|eproc| eproc.ActiveProcessLinks, |proc| f(proc.into()))
    }

    fn process_for_each_vma(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Vma) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        self.pointer_of(proc)
            .field(|eproc| eproc.VadRoot)?
            .iterate_tree(|vad| vad.VadNode, |mmvad| f(mmvad.into()))
    }

    fn process_find_vma_by_address(
        &self,
        proc: ibc::Process,
        addr: VirtualAddress,
    ) -> IceResult<Option<ibc::Vma>> {
        let mmvad = self
            .pointer_of(proc)
            .field(|eproc| eproc.VadRoot)?
            .find_in_tree(
                |vad| vad.VadNode,
                |mmvad| {
                    let vma = mmvad.into();

                    Ok(if addr < self.vma_start(vma)? {
                        std::cmp::Ordering::Greater
                    } else if addr < self.vma_end(vma)? {
                        std::cmp::Ordering::Equal
                    } else {
                        std::cmp::Ordering::Less
                    })
                },
            )?;
        Ok(mmvad.map(|m| m.into()))
    }

    fn process_for_each_module(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Module) -> IceResult<ControlFlow<()>>,
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

    fn process_callstack_with_regs(
        &self,
        proc: ibc::Process,
        instruction_pointer: VirtualAddress,
        stack_pointer: VirtualAddress,
        base_pointer: Option<VirtualAddress>,
        f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        self.iter_callstack(proc, instruction_pointer, stack_pointer, base_pointer, f)
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

    fn vma_path(&self, _vma: ibc::Vma) -> IceResult<Option<String>> {
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

    fn module_symbols(
        &self,
        proc: ibc::Process,
        module: ibc::Module,
    ) -> IceResult<Option<&ibc::ModuleSymbols>> {
        let name = self.module_name(module, proc)?;
        self.profile.syms.load_module(name.into(), &mut |_| {
            let codeview = self.module_codeview(proc, module)?;

            let module = match codeview {
                Some(codeview) => self
                    .symbols_loader
                    .load(codeview.name().unwrap(), &codeview.pdb_id())?,
                None => None,
            };

            Ok(alloc::sync::Arc::new(module))
        })
    }
}
