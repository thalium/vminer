pub mod callstack;
mod profile;

use super::pointer::{Context, HasLayout, KernelSpace, Pointer, StructOffset};
use crate::core::{self as ice, IceError, IceResult, Os, PhysicalAddress, VirtualAddress};
use alloc::{string::String, vec::Vec};
use core::{fmt, ops::ControlFlow};

pub use profile::Profile;

pointer_defs! {
    ibc::Module = profile::VmAreaStruct;
    ibc::Process = profile::TaskStruct;
    ibc::Thread = profile::TaskStruct;
    ibc::Vma = profile::VmAreaStruct;
}

impl<T, B: ibc::Backend> Pointer<'_, profile::ListHead<T>, Linux<B>>
where
    Linux<B>: HasLayout<T>,
{
    /// Iterate a linked list, yielding elements of type `T`
    fn iterate_list<O, F>(self, get_offset: O, mut f: F) -> IceResult<()>
    where
        O: FnOnce(&T) -> StructOffset<profile::ListHead<T>>,
        F: FnMut(Pointer<T, Linux<B>>) -> IceResult<ControlFlow<()>>,
    {
        let mut pos = self.monomorphize();
        let offset = get_offset(self.os.get_layout()).offset;

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

impl<B: ibc::Backend> Pointer<'_, profile::Dentry, Linux<B>> {
    fn build_path(self, buf: &mut Vec<u8>) -> IceResult<()> {
        // Paths start with the last components in the kernel but we want them
        // to start by the root, so we call ourselves recursively to build the
        // beginning first

        let parent = self.read_pointer_field(|d| d.d_parent)?;
        if parent != self {
            parent.build_path(buf)?;
        }

        self._read_file_name(buf)
    }

    fn _read_file_name(self, buf: &mut Vec<u8>) -> IceResult<()> {
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

impl<B: ibc::Backend> Pointer<'_, profile::Path, Linux<B>> {
    fn read_file_name(self) -> IceResult<String> {
        let mut buf = Vec::new();
        self.read_pointer_field(|p| p.dentry)?
            ._read_file_name(&mut buf)?;
        String::from_utf8(buf).map_err(IceError::new)
    }

    fn read_file_path(self) -> IceResult<String> {
        let mut buf = Vec::new();
        self.read_pointer_field(|p| p.dentry)?
            .build_path(&mut buf)?;
        String::from_utf8(buf).map_err(IceError::new)
    }
}

pub struct Linux<B> {
    backend: B,
    profile: Profile,
    kpgd: PhysicalAddress,
    kaslr: i64,
}

pub fn get_aslr<B: ice::Backend>(
    backend: &B,
    profile: &Profile,
    kpgd: PhysicalAddress,
) -> IceResult<i64> {
    let base_banner_addr = profile.fast_syms.linux_banner;
    let banner_addr = get_banner_addr(backend, kpgd)?.ok_or("could not find banner address")?;

    Ok(banner_addr.0.overflowing_sub(base_banner_addr.0).0 as i64)
}

impl<B: ice::Backend> Linux<B> {
    pub fn create(backend: B, profile: ibc::SymbolsIndexer) -> IceResult<Self> {
        let profile = Profile::new(profile)?;
        let kpgd = backend.find_kernel_pgd(true, &[])?;
        let kaslr = get_aslr(&backend, &profile, kpgd)?;

        Ok(Linux {
            backend,
            profile,
            kpgd,
            kaslr,
        })
    }

    fn read_kernel_value<T: bytemuck::Pod>(&self, addr: VirtualAddress) -> IceResult<T> {
        let mut value = bytemuck::Zeroable::zeroed();
        self.read_virtual_memory(self.kpgd, addr, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }

    #[inline]
    fn pointer_of<T: ToPointer<U>, U>(&self, ptr: T) -> Pointer<U, Self> {
        ptr.to_pointer(self, KernelSpace)
    }

    pub fn per_cpu(&self, cpuid: usize) -> IceResult<VirtualAddress> {
        let per_cpu_offset = self.profile.fast_syms.per_cpu_offset + self.kaslr;
        self.read_kernel_value(per_cpu_offset + 8 * cpuid as u64)
    }

    pub fn find_symbol(&self, lib: &str, addr: VirtualAddress) -> Option<&str> {
        let lib = self.profile.syms.get_lib(lib).ok()?;
        lib.get_symbol(addr)
    }

    pub fn find_symbol_inexact(&self, lib: &str, addr: VirtualAddress) -> Option<(&str, u64)> {
        let lib = self.profile.syms.get_lib(lib).ok()?;
        lib.get_symbol_inexact(addr)
    }

    fn process_mm(
        &self,
        proc: ice::Process,
    ) -> IceResult<Option<Pointer<profile::MmStruct, Self>>> {
        let proc = self.pointer_of(proc);
        let mut mm = proc.read_pointer_field(|ts| ts.mm)?;

        // Kernel processes use this instead. This is NULL too on aarch64 though
        if mm.is_null() {
            mm = proc.read_pointer_field(|ts| ts.active_mm)?;
        }

        mm.map_non_null(Ok)
    }
}

fn get_banner_addr<B: ice::Backend>(
    backend: &B,
    mmu_addr: PhysicalAddress,
) -> ice::MemoryAccessResult<Option<VirtualAddress>> {
    backend.find_in_kernel_memory(mmu_addr, b"Linux version")
}

impl<B: ice::Backend> super::OsBuilder<B> for Linux<B> {
    fn quick_check(backend: &B) -> IceResult<bool> {
        let mmu_addr = backend.find_kernel_pgd(true, &[])?;
        Ok(get_banner_addr(backend, mmu_addr)?.is_some())
    }
}

impl<B: ice::Backend> ice::Os for Linux<B> {
    fn read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> IceResult<()> {
        ibc::read_virtual_memory(addr, buf, |addr, buf| {
            self.backend.read_virtual_memory(mmu_addr, addr, buf)
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
        _f: &mut dyn FnMut(ibc::Module) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        Ok(())
    }

    fn init_process(&self) -> IceResult<ibc::Process> {
        Ok(ibc::Process(self.profile.fast_syms.init_task + self.kaslr))
    }

    fn current_thread(&self, cpuid: usize) -> IceResult<ibc::Thread> {
        match self.profile.fast_syms.current_task {
            Some(current_task) => {
                let current_task = self.per_cpu(cpuid)? + current_task;
                let addr = self.read_kernel_value(current_task)?;
                Ok(ibc::Thread(addr))
            }
            None => {
                // The symbol `current_task` may not exist (eg on Aach64, where
                // Linux gets it from register `sp_el0`, which is not valid for
                // this if the current process is a userspace one.
                // In this case we find it the poor man's way: we iterate the
                // process list and find a matching PGD.
                //
                // FIXME: This will always yield the thread group leader instead
                // of the current thread

                use ibc::arch::{Vcpu, Vcpus};

                let vcpu = self.backend.vcpus().get(cpuid);
                let vcpu_pgd = vcpu.pgd();

                if let ice::arch::runtime::Vcpu::Aarch64(vcpu) = vcpu.into_runtime() {
                    if vcpu.instruction_pointer().is_kernel() {
                        let current_task = VirtualAddress(vcpu.registers.sp);
                        return Ok(ibc::Thread(current_task));
                    }
                }

                log::debug!("Using fallback to get current task");

                let mut current_task = None;
                self.for_each_process(&mut |proc| {
                    let proc_pgd = self.process_pgd(proc)?;
                    Ok(if proc_pgd == vcpu_pgd {
                        current_task = Some(ibc::Thread(proc.0));
                        ControlFlow::Break(())
                    } else {
                        ControlFlow::Continue(())
                    })
                })?;

                current_task.ok_or_else(|| ibc::IceError::new("cannot find current thread"))
            }
        }
    }

    fn thread_process(&self, thread: ibc::Thread) -> IceResult<ibc::Process> {
        let pointer = self
            .pointer_of(thread)
            .read_pointer_field(|ts| ts.group_leader)?;
        Ok(pointer.into())
    }

    fn process_is_kernel(&self, proc: ibc::Process) -> IceResult<bool> {
        let flags = self.pointer_of(proc).read_field(|ts| ts.flags)?;
        Ok(flags & 0x200000 != 0)
    }

    fn process_pid(&self, proc: ibc::Process) -> IceResult<u64> {
        self.pointer_of(proc)
            .read_field(|ts| ts.tgid)
            .map(|pid| pid as u64)
    }

    fn process_name(&self, proc: ice::Process) -> IceResult<String> {
        let comm = self.pointer_of(proc).read_field(|ts| ts.comm)?;

        let buf = match memchr::memchr(0, &comm) {
            Some(i) => &comm[..i],
            None => &comm,
        };

        Ok(String::from_utf8_lossy(buf).into_owned())
    }

    fn process_pgd(&self, proc: ice::Process) -> IceResult<PhysicalAddress> {
        match self.process_mm(proc)? {
            Some(mm) => {
                let pgd = mm.read_field(|mms| mms.pgd)?;
                Ok(self.backend.virtual_to_physical(self.kpgd, pgd)?)
            }
            None => {
                if self.process_is_kernel(proc)? {
                    Ok(self.kpgd)
                } else {
                    Err(ibc::IceError::new("process has NULL mm"))
                }
            }
        }
    }

    fn process_path(&self, proc: ice::Process) -> IceResult<Option<String>> {
        match self.process_mm(proc)? {
            Some(mm) => mm
                .read_pointer_field(|mm| mm.exe_file)?
                .map_non_null(|file| file.field(|file| file.f_path)?.read_file_path()),
            None => Ok(None),
        }
    }

    fn process_parent(&self, proc: ice::Process) -> IceResult<ice::Process> {
        let proc = self
            .pointer_of(proc)
            .read_pointer_field(|ts| ts.real_parent)?;
        Ok(proc.into())
    }

    fn process_parent_id(&self, proc: ibc::Process) -> IceResult<u64> {
        self.process_pid(self.process_parent(proc)?)
    }

    fn process_for_each_child(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Process) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        self.pointer_of(proc)
            .field(|ts| ts.children)?
            .iterate_list(|ts| ts.sibling, |child| f(child.into()))
    }

    fn process_for_each_thread(
        &self,
        proc: ice::Process,
        f: &mut dyn FnMut(ice::Thread) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        self.pointer_of(proc)
            .field(|ts| ts.thread_group)?
            .iterate_list(|ts| ts.thread_group, |thread| f(thread.into()))
    }

    fn for_each_process(
        &self,
        f: &mut dyn FnMut(ibc::Process) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        let init = self.init_process()?;
        self.pointer_of(init)
            .field(|ts| ts.tasks)?
            .iterate_list(|ts| ts.tasks, |proc| f(proc.into()))
    }

    fn process_for_each_vma(
        &self,
        proc: ice::Process,
        f: &mut dyn FnMut(ice::Vma) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
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
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Module) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        self.process_for_each_vma(proc, &mut |vma| {
            if self.vma_offset(vma)? == 0 && self.vma_path(vma)?.is_some() {
                f(ibc::Module(vma.0))
            } else {
                Ok(ControlFlow::Continue(()))
            }
        })
    }

    fn process_callstack(
        &self,
        proc: ice::Process,
        f: &mut dyn FnMut(&ice::StackFrame) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        callstack::iter(self, proc, f)
    }

    fn thread_id(&self, thread: ice::Thread) -> IceResult<u64> {
        self.pointer_of(thread)
            .read_field(|ts| ts.pid)
            .map(|pid| pid as u64)
    }

    fn thread_name(&self, thread: ibc::Thread) -> IceResult<Option<String>> {
        self.process_name(ibc::Process(thread.0)).map(Some)
    }

    fn vma_path(&self, vma: ice::Vma) -> IceResult<Option<String>> {
        self.pointer_of(vma)
            .read_pointer_field(|vma| vma.vm_file)?
            .map_non_null(|file| file.field(|file| file.f_path)?.read_file_path())
    }

    fn vma_start(&self, vma: ice::Vma) -> IceResult<VirtualAddress> {
        self.pointer_of(vma).read_field(|vma| vma.vm_start)
    }

    fn vma_end(&self, vma: ice::Vma) -> IceResult<VirtualAddress> {
        self.pointer_of(vma).read_field(|vma| vma.vm_end)
    }

    fn vma_flags(&self, vma: ice::Vma) -> IceResult<ibc::VmaFlags> {
        let flags = self.pointer_of(vma).read_field(|vma| vma.vm_flags)?;
        Ok(ibc::VmaFlags(flags))
    }

    fn vma_offset(&self, vma: ice::Vma) -> IceResult<u64> {
        self.pointer_of(vma)
            .read_field(|vma| vma.vm_pgoff)
            .map(|offset| offset * 4096)
    }

    fn module_span(
        &self,
        module: ibc::Module,
        _proc: ibc::Process,
    ) -> IceResult<(VirtualAddress, VirtualAddress)> {
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

    fn module_name(&self, module: ibc::Module, _proc: ibc::Process) -> IceResult<String> {
        self.pointer_of(module)
            .read_pointer_field(|vma| vma.vm_file)?
            .field(|file| file.f_path)?
            .read_file_name()
    }

    fn module_path(&self, module: ibc::Module, _proc: ibc::Process) -> IceResult<String> {
        self.pointer_of(module)
            .read_pointer_field(|vma| vma.vm_file)?
            .field(|file| file.f_path)?
            .read_file_path()
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

        let addr = VirtualAddress((addr - mod_start) as u64);
        let module = self.module_name(module, proc)?;

        Ok(self.find_symbol(&module, addr))
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

        let addr = VirtualAddress((addr - mod_start) as u64);
        let module = self.module_name(module, proc)?;

        Ok(self.find_symbol_inexact(&module, addr))
    }
}

impl<B> fmt::Debug for Linux<B> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Linux").finish_non_exhaustive()
    }
}
