pub mod callstack;
mod profile;

use super::pointer::{Context, HasLayout, KernelSpace, Pointer};
use alloc::{string::String, vec::Vec};
use core::{fmt, ops::ControlFlow};
use vmc::{Os, PhysicalAddress, ResultExt, VirtualAddress, VmError, VmResult};

pub use profile::Profile;

pointer_defs! {
    vmc::Module = profile::VmAreaStruct;
    vmc::Process = profile::TaskStruct;
    vmc::Thread = profile::TaskStruct;
    vmc::Vma = profile::VmAreaStruct;
}

impl<T, B: vmc::Backend> Pointer<'_, profile::ListHead<T>, Linux<B>>
where
    Linux<B>: HasLayout<T>,
{
    /// Iterate a linked list, yielding elements of type `T`
    fn iterate_list<O, F, P>(self, get_offset: O, mut f: F) -> VmResult<()>
    where
        O: FnOnce(&T) -> P,
        P: super::pointer::HasOffset<Target = profile::ListHead<T>>,
        F: FnMut(Pointer<T, Linux<B>>) -> VmResult<ControlFlow<()>>,
    {
        let mut pos = self.monomorphize();
        let offset = get_offset(self.os.get_layout()?).offset()?;

        loop {
            pos = pos.read_pointer_field(|list| list.next)?;

            if pos == self {
                break;
            }

            f(Pointer::new(pos.addr - offset, self.os, self.ctx))?;
        }

        Ok(())
    }
}

impl<B: vmc::Backend> Pointer<'_, profile::Dentry, Linux<B>> {
    fn build_path(self, buf: &mut Vec<u8>) -> VmResult<()> {
        // Paths start with the last components in the kernel but we want them
        // to start by the root, so we call ourselves recursively to build the
        // beginning first

        let parent = self.read_pointer_field(|d| d.d_parent)?;
        if parent != self {
            parent.build_path(buf)?;
        }

        self._read_file_name(buf)
    }

    fn _read_file_name(self, buf: &mut Vec<u8>) -> VmResult<()> {
        let qstr = self.field(|d| d.d_name)?;
        let name = qstr.read_field(|qstr| qstr.name)?;

        // TODO: use qstr.len here
        let mut len = buf.len();
        buf.extend_from_slice(&[0; 256]);
        if len > 0 && buf[len - 1] != b'/' {
            buf[len] = b'/';
            len += 1;
        }
        self.ctx.read_memory(self.os, name, &mut buf[len..])?;

        match memchr::memchr(0, &buf[len..]) {
            Some(i) => buf.truncate(len + i),
            None => todo!(),
        }

        Ok(())
    }
}

impl<B: vmc::Backend> Pointer<'_, profile::Path, Linux<B>> {
    fn read_file_name(self) -> VmResult<String> {
        let mut buf = Vec::new();
        self.read_pointer_field(|p| p.dentry)?
            ._read_file_name(&mut buf)?;
        String::from_utf8(buf).map_err(VmError::new)
    }

    fn read_file_path(self) -> VmResult<String> {
        let mut buf = Vec::new();
        self.read_pointer_field(|p| p.dentry)?
            .build_path(&mut buf)?;
        String::from_utf8(buf).map_err(VmError::new)
    }
}

#[cfg(feature = "std")]
pub struct SymbolLoader {
    root: std::path::PathBuf,
}

#[cfg(feature = "std")]
impl SymbolLoader {
    pub fn with_root(path: std::path::PathBuf) -> VmResult<Self> {
        std::fs::create_dir_all(&path)?;
        Ok(Self { root: path })
    }
}

#[cfg(feature = "std")]
impl super::SymbolLoader for SymbolLoader {
    fn load(&self, name: &str, id: &str) -> VmResult<Option<vmc::ModuleSymbols>> {
        let path: std::path::PathBuf = [&*self.root, id.as_ref(), name.as_ref()].iter().collect();

        path.exists()
            .then(|| vmc::ModuleSymbols::from_file(path))
            .transpose()
    }
}

pub struct Linux<B> {
    backend: B,
    symbols_loader: Box<dyn super::SymbolLoader + Send + Sync>,
    profile: Profile,
    kpgd: PhysicalAddress,
    kaslr: i64,
}

impl<B: vmc::Backend> Linux<B> {
    pub fn create(backend: B, symbols: vmc::SymbolsIndexer) -> VmResult<Self> {
        super::OsBuilder::new().with_symbols(symbols).build(backend)
    }

    fn read_kernel_value<T: bytemuck::Pod>(&self, addr: VirtualAddress) -> VmResult<T> {
        let mut value = bytemuck::Zeroable::zeroed();
        self.read_virtual_memory(self.kpgd, addr, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }

    #[inline]
    fn pointer_of<T: ToPointer<U>, U>(&self, ptr: T) -> Pointer<U, Self> {
        ptr.to_pointer(self, KernelSpace)
    }

    pub fn per_cpu(&self, vcpu: vmc::VcpuId) -> VmResult<VirtualAddress> {
        let per_cpu_offset = self.profile.fast_syms.per_cpu_offset + self.kaslr;
        self.read_kernel_value(per_cpu_offset + 8 * vcpu.0 as u64)
    }

    fn process_mm(&self, proc: vmc::Process) -> VmResult<Option<Pointer<profile::MmStruct, Self>>> {
        let proc = self.pointer_of(proc);
        let mut mm = proc.read_pointer_field(|ts| ts.mm)?;

        // Kernel processes use this instead. This is NULL too on aarch64 though
        if mm.is_null() {
            mm = proc.read_pointer_field(|ts| ts.active_mm)?;
        }

        mm.map_non_null(Ok)
    }

    fn vma_offset(&self, vma: vmc::Vma) -> VmResult<u64> {
        self.pointer_of(vma)
            .read_field(|vma| vma.vm_pgoff)
            .map(|offset| offset * 4096)
    }
}

fn get_banner_addr<B: vmc::Backend>(
    backend: &B,
    mmu_addr: PhysicalAddress,
) -> vmc::MemoryAccessResult<Option<VirtualAddress>> {
    backend.find_in_kernel_memory(mmu_addr, b"Linux version ")
}

impl<B: vmc::Backend> super::Buildable<B> for Linux<B> {
    fn quick_check(backend: &B) -> Option<super::OsBuilder> {
        let kpgd = backend.find_kernel_pgd(true, &[]).ok()?;
        let kaslr = get_banner_addr(backend, kpgd).ok()??;
        Some(super::OsBuilder::new().with_kpgd(kpgd).with_kaslr(kaslr))
    }

    fn build(backend: B, builder: super::OsBuilder) -> VmResult<Self> {
        let kpgd = match builder.kpgd {
            Some(kpgd) => kpgd,
            None => backend
                .find_kernel_pgd(true, &[])
                .context("could not find kernel PGD")?,
        };
        log::debug!("Found Linux PGD at 0x{kpgd:x}");

        let banner_addr = match builder.kaslr {
            Some(kaslr) => kaslr,
            None => get_banner_addr(&backend, kpgd)
                .context("could not find banner address")?
                .context("could not find banner address")?,
        };
        log::info!("Found Linux banner at 0x{banner_addr:x}");
        let mut banner = [0; 0x1000];
        vmc::read_virtual_memory(banner_addr, &mut banner, |addr, buf| {
            backend.read_virtual_memory(kpgd, addr, buf)
        })?;
        let banner = &banner[..memchr::memchr(0, &banner).unwrap()];
        log::debug!("Banner: \"{}\"", String::from_utf8_lossy(banner));

        let symbols_loader = match builder.loader {
            Some(loader) => loader,
            #[cfg(feature = "std")]
            None => Box::new(SymbolLoader::with_root("./data/linux".into())?),
            #[cfg(not(feature = "std"))]
            None => Box::new(super::EmptyLoader),
        };

        let symbols = builder.symbols.unwrap_or_default();
        let profile = Profile::new(symbols)?;

        let base_banner_addr = profile.fast_syms.linux_banner;
        let kaslr = banner_addr.0.wrapping_sub(base_banner_addr.0) as i64;

        Ok(Linux {
            backend,
            symbols_loader,
            profile,
            kpgd,
            kaslr,
        })
    }
}

impl<B: vmc::Backend> vmc::HasVcpus for Linux<B> {
    type Arch = B::Arch;

    fn arch(&self) -> Self::Arch {
        self.backend.arch()
    }

    fn vcpus_count(&self) -> usize {
        self.backend.vcpus_count()
    }

    fn registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<<Self::Arch as vmc::Architecture>::Registers> {
        self.backend.registers(vcpu)
    }

    fn special_registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<<Self::Arch as vmc::Architecture>::SpecialRegisters> {
        self.backend.special_registers(vcpu)
    }

    fn other_registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<<Self::Arch as vmc::Architecture>::OtherRegisters> {
        self.backend.other_registers(vcpu)
    }

    fn instruction_pointer(&self, vcpu: vmc::VcpuId) -> vmc::VcpuResult<VirtualAddress> {
        self.backend.instruction_pointer(vcpu)
    }

    fn stack_pointer(&self, vcpu: vmc::VcpuId) -> vmc::VcpuResult<VirtualAddress> {
        self.backend.stack_pointer(vcpu)
    }

    fn base_pointer(&self, vcpu: vmc::VcpuId) -> vmc::VcpuResult<Option<VirtualAddress>> {
        self.backend.base_pointer(vcpu)
    }

    fn pgd(&self, vcpu: vmc::VcpuId) -> vmc::VcpuResult<PhysicalAddress> {
        self.backend.pgd(vcpu)
    }

    fn kernel_per_cpu(&self, vcpu: vmc::VcpuId) -> vmc::VcpuResult<Option<VirtualAddress>> {
        self.backend.kernel_per_cpu(vcpu)
    }
}

impl<B: vmc::Backend> vmc::Os for Linux<B> {
    fn read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> VmResult<()> {
        vmc::read_virtual_memory(addr, buf, |addr, buf| {
            self.backend.read_virtual_memory(mmu_addr, addr, buf)
        })?;
        Ok(())
    }

    fn try_read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> VmResult<()> {
        vmc::try_read_virtual_memory(addr, buf, |addr, buf| {
            self.backend.read_virtual_memory(mmu_addr, addr, buf)
        })?;
        Ok(())
    }

    #[inline]
    fn kernel_pgd(&self) -> PhysicalAddress {
        self.kpgd
    }

    fn for_each_kernel_module(
        &self,
        _f: &mut dyn FnMut(vmc::Module) -> VmResult<ControlFlow<()>>,
    ) -> VmResult<()> {
        Ok(())
    }

    fn init_process(&self) -> VmResult<vmc::Process> {
        Ok(vmc::Process(self.profile.fast_syms.init_task + self.kaslr))
    }

    fn current_thread(&self, vcpu: vmc::VcpuId) -> VmResult<vmc::Thread> {
        match self.profile.fast_syms.current_task {
            Some(current_task) => {
                let current_task = self.per_cpu(vcpu)? + current_task;
                let addr = self.read_kernel_value(current_task)?;
                Ok(vmc::Thread(addr))
            }
            None => {
                // The symbol `current_task` may not exist (eg on Aarch64, where
                // Linux gets it from register `sp_el0`, which is not valid for
                // this if the current process is a userspace one.
                // In this case we find it the poor man's way: we iterate the
                // process list and find a matching PGD.
                //
                // FIXME: This will always yield the thread group leader instead
                // of the current thread

                use vmc::{Architecture, HasVcpus};

                let vcpu_pgd = self.backend.pgd(vcpu)?;

                if let vmc::arch::RuntimeArchitecture::Aarch64(_) = self.arch().into_runtime() {
                    if self.instruction_pointer(vcpu)?.is_kernel() {
                        let current_task =
                            VirtualAddress(vmc::arch::AssumeAarch64(self).registers(vcpu)?.sp);
                        return Ok(vmc::Thread(current_task));
                    }
                }

                log::debug!("Using fallback to get current task");

                let mut current_task = None;
                self.for_each_process(&mut |proc| {
                    let proc_pgd = self.process_pgd(proc)?;
                    Ok(if proc_pgd == vcpu_pgd {
                        current_task = Some(vmc::Thread(proc.0));
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    })
                })?;

                current_task.ok_or_else(|| vmc::VmError::new("cannot find current thread"))
            }
        }
    }

    fn thread_process(&self, thread: vmc::Thread) -> VmResult<vmc::Process> {
        let pointer = self
            .pointer_of(thread)
            .read_pointer_field(|ts| ts.group_leader)?;
        Ok(pointer.into())
    }

    fn process_is_kernel(&self, proc: vmc::Process) -> VmResult<bool> {
        let flags = self.pointer_of(proc).read_field(|ts| ts.flags)?;
        Ok(flags & 0x200000 != 0)
    }

    fn process_id(&self, proc: vmc::Process) -> VmResult<u64> {
        self.pointer_of(proc)
            .read_field(|ts| ts.tgid)
            .map(|pid| pid as u64)
    }

    fn process_name(&self, proc: vmc::Process) -> VmResult<String> {
        let comm = self.pointer_of(proc).read_field(|ts| ts.comm)?;

        let buf = match memchr::memchr(0, &comm) {
            Some(i) => &comm[..i],
            None => &comm,
        };

        Ok(String::from_utf8_lossy(buf).into_owned())
    }

    fn process_pgd(&self, proc: vmc::Process) -> VmResult<PhysicalAddress> {
        match self.process_mm(proc)? {
            Some(mm) => {
                let pgd = mm.read_field(|mms| mms.pgd)?;
                Ok(self.backend.virtual_to_physical(self.kpgd, pgd)?)
            }
            None => {
                if self.process_is_kernel(proc)? {
                    Ok(self.kpgd)
                } else {
                    Err(vmc::VmError::new("process has NULL mm"))
                }
            }
        }
    }

    fn process_path(&self, proc: vmc::Process) -> VmResult<Option<String>> {
        match self.process_mm(proc)? {
            Some(mm) => mm
                .read_pointer_field(|mm| mm.exe_file)?
                .map_non_null(|file| file.field(|file| file.f_path)?.read_file_path()),
            None => Ok(None),
        }
    }

    fn process_parent(&self, proc: vmc::Process) -> VmResult<vmc::Process> {
        let proc = self
            .pointer_of(proc)
            .read_pointer_field(|ts| ts.real_parent)?;
        Ok(proc.into())
    }

    fn process_parent_id(&self, proc: vmc::Process) -> VmResult<u64> {
        self.process_id(self.process_parent(proc)?)
    }

    fn process_for_each_child(
        &self,
        proc: vmc::Process,
        f: &mut dyn FnMut(vmc::Process) -> VmResult<ControlFlow<()>>,
    ) -> VmResult<()> {
        self.pointer_of(proc)
            .field(|ts| ts.children)?
            .iterate_list(|ts| ts.sibling, |child| f(child.into()))
    }

    fn process_for_each_thread(
        &self,
        proc: vmc::Process,
        f: &mut dyn FnMut(vmc::Thread) -> VmResult<ControlFlow<()>>,
    ) -> VmResult<()> {
        self.pointer_of(proc)
            .field(|ts| ts.thread_group)?
            .iterate_list(|ts| ts.thread_group, |thread| f(thread.into()))
    }

    fn for_each_process(
        &self,
        f: &mut dyn FnMut(vmc::Process) -> VmResult<ControlFlow<()>>,
    ) -> VmResult<()> {
        let init = self.init_process()?;
        self.pointer_of(init)
            .field(|ts| ts.tasks)?
            .iterate_list(|ts| ts.tasks, |proc| f(proc.into()))
    }

    fn process_for_each_vma(
        &self,
        proc: vmc::Process,
        f: &mut dyn FnMut(vmc::Vma) -> VmResult<ControlFlow<()>>,
    ) -> VmResult<()> {
        let mm = match self.process_mm(proc)? {
            Some(mm) => mm,
            None => return Ok(()),
        };

        let mut cur_vma = mm.read_pointer_field(|mm| mm.mmap)?;

        while !cur_vma.is_null() {
            f(cur_vma.into())?;
            cur_vma = cur_vma.read_pointer_field(|vma| vma.vm_next)?;
        }

        Ok(())
    }

    fn process_for_each_module(
        &self,
        proc: vmc::Process,
        f: &mut dyn FnMut(vmc::Module) -> VmResult<ControlFlow<()>>,
    ) -> VmResult<()> {
        self.process_for_each_vma(proc, &mut |vma| {
            if self.vma_offset(vma)? == 0 && self.vma_path(vma)?.is_some() {
                f(vmc::Module(vma.0))
            } else {
                Ok(ControlFlow::Continue(()))
            }
        })
    }

    fn process_callstack_with_regs(
        &self,
        proc: vmc::Process,
        instruction_pointer: VirtualAddress,
        stack_pointer: VirtualAddress,
        base_pointer: Option<VirtualAddress>,
        f: &mut dyn FnMut(&vmc::StackFrame) -> VmResult<ControlFlow<()>>,
    ) -> VmResult<()> {
        callstack::iter(
            self,
            proc,
            instruction_pointer,
            stack_pointer,
            base_pointer,
            f,
        )
    }

    fn thread_id(&self, thread: vmc::Thread) -> VmResult<u64> {
        self.pointer_of(thread)
            .read_field(|ts| ts.pid)
            .map(|pid| pid as u64)
    }

    fn thread_name(&self, thread: vmc::Thread) -> VmResult<Option<String>> {
        self.process_name(vmc::Process(thread.0)).map(Some)
    }

    fn vma_path(&self, vma: vmc::Vma) -> VmResult<Option<String>> {
        self.pointer_of(vma)
            .read_pointer_field(|vma| vma.vm_file)?
            .map_non_null(|file| file.field(|file| file.f_path)?.read_file_path())
    }

    fn vma_start(&self, vma: vmc::Vma) -> VmResult<VirtualAddress> {
        self.pointer_of(vma).read_field(|vma| vma.vm_start)
    }

    fn vma_end(&self, vma: vmc::Vma) -> VmResult<VirtualAddress> {
        self.pointer_of(vma).read_field(|vma| vma.vm_end)
    }

    fn vma_flags(&self, vma: vmc::Vma) -> VmResult<vmc::VmaFlags> {
        let flags = self.pointer_of(vma).read_field(|vma| vma.vm_flags)?;
        Ok(vmc::VmaFlags(flags))
    }

    fn module_span(
        &self,
        module: vmc::Module,
        _proc: vmc::Process,
    ) -> VmResult<(VirtualAddress, VirtualAddress)> {
        let module = self.pointer_of(module);

        let file = module.read_pointer_field(|vma| vma.vm_file)?;
        let start = module.read_field(|vma| vma.vm_start)?;

        let mut current = module;

        loop {
            let next = current.read_pointer_field(|vma| vma.vm_next)?;

            if next.is_null() || next.read_pointer_field(|vma| vma.vm_file)? != file {
                let end = current.read_field(|vma| vma.vm_end)?;
                break Ok((start, end));
            }

            current = next;
        }
    }

    fn module_name(&self, module: vmc::Module, _proc: vmc::Process) -> VmResult<String> {
        self.pointer_of(module)
            .read_pointer_field(|vma| vma.vm_file)?
            .field(|file| file.f_path)?
            .read_file_name()
    }

    fn module_path(&self, module: vmc::Module, _proc: vmc::Process) -> VmResult<String> {
        self.pointer_of(module)
            .read_pointer_field(|vma| vma.vm_file)?
            .field(|file| file.f_path)?
            .read_file_path()
    }

    fn module_symbols(
        &self,
        proc: vmc::Process,
        module: vmc::Module,
    ) -> VmResult<Option<&vmc::ModuleSymbols>> {
        let name = self.module_name(module, proc)?;
        self.profile.syms.load_module(name.into(), &mut |name| {
            use vmc::Architecture;

            let id = match self.backend.arch().into_runtime() {
                vmc::arch::RuntimeArchitecture::X86_64(_) => "x86_64",
                vmc::arch::RuntimeArchitecture::Aarch64(_) => "aarch64",
                vmc::arch::RuntimeArchitecture::Riscv64(_) => "riscv64",
            };

            let module = self.symbols_loader.load(name, id)?;
            Ok(alloc::sync::Arc::new(module))
        })
    }
}

impl<B> fmt::Debug for Linux<B> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Linux").finish_non_exhaustive()
    }
}
