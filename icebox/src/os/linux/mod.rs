pub mod callstack;
pub mod profile;

use crate::core::{
    self as ice, IceError, IceResult, MemoryAccessResultExt, PhysicalAddress, VirtualAddress,
};
use crate::utils::OnceCell;
use alloc::{string::String, vec::Vec};
use core::fmt;
use hashbrown::HashMap;

pub use profile::Profile;

use self::profile::{Pointer, StructOffset};

/// Values that we can read from guest memory
trait Readable: Sized {
    fn read<B: ice::Backend>(linux: &Linux<B>, addr: VirtualAddress) -> IceResult<Self>;
}

impl<T: bytemuck::Pod> Readable for T {
    fn read<B: ice::Backend>(linux: &Linux<B>, addr: VirtualAddress) -> IceResult<Self> {
        let val = linux.read_kernel_value(addr)?;
        Ok(val)
    }
}

impl<T> Readable for Pointer<T> {
    fn read<B: ice::Backend>(linux: &Linux<B>, addr: VirtualAddress) -> IceResult<Self> {
        let addr = VirtualAddress(linux.read_kernel_value(addr)?);
        Ok(Pointer::new(addr))
    }
}

trait HasStruct<Layout> {
    fn get_struct_layout(&self) -> &Layout;
}

// Conversions between core types and kernel pointeurs

impl From<ice::Path> for Pointer<profile::Path> {
    fn from(path: ice::Path) -> Self {
        Self::new(path.0)
    }
}

impl From<Pointer<profile::Path>> for ice::Path {
    fn from(path: Pointer<profile::Path>) -> Self {
        Self(path.addr)
    }
}

impl From<ice::Process> for Pointer<profile::TaskStruct> {
    fn from(proc: ice::Process) -> Self {
        Self::new(proc.0)
    }
}

impl From<Pointer<profile::TaskStruct>> for ice::Process {
    fn from(path: Pointer<profile::TaskStruct>) -> Self {
        Self(path.addr)
    }
}

impl From<ice::Thread> for Pointer<profile::TaskStruct> {
    fn from(thread: ice::Thread) -> Self {
        Self::new(thread.0)
    }
}

impl From<Pointer<profile::TaskStruct>> for ice::Thread {
    fn from(path: Pointer<profile::TaskStruct>) -> Self {
        Self(path.addr)
    }
}

impl From<ice::Vma> for Pointer<profile::VmAreaStruct> {
    fn from(vma: ice::Vma) -> Self {
        Self::new(vma.0)
    }
}

impl From<Pointer<profile::VmAreaStruct>> for ice::Vma {
    fn from(path: Pointer<profile::VmAreaStruct>) -> Self {
        Self(path.addr)
    }
}

/// Cached data for a process
///
/// FIXME: should we really keep this ? Maybe only for "complex" fields ?
#[derive(Default)]
struct ProcessData {
    name: OnceCell<String>,
    pid: OnceCell<u32>,

    parent: OnceCell<ibc::Process>,
    children: OnceCell<Vec<ibc::Process>>,
}

pub struct Linux<B> {
    backend: B,
    profile: Profile,
    kpgd: PhysicalAddress,
    kaslr: i64,

    processes: OnceCell<HashMap<ibc::Process, ProcessData>>,
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
    pub fn create(backend: B, profile: Profile) -> IceResult<Self> {
        let kpgd = backend.find_kernel_pgd(true, &[])?;
        let kaslr = get_aslr(&backend, &profile, kpgd)?;

        Ok(Linux {
            backend,
            profile,
            kpgd,
            kaslr,

            processes: OnceCell::new(),
        })
    }

    fn read_kernel_value<T: bytemuck::Pod>(&self, addr: VirtualAddress) -> IceResult<T> {
        self.backend.read_value_virtual(self.kpgd, addr)
    }

    fn read_kernel_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()> {
        self.backend.read_virtual_memory(self.kpgd, addr, buf)
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

    /// Reads a value behind a pointer
    #[allow(dead_code)]
    fn read_pointer<T: Readable>(&self, pointer: Pointer<T>) -> IceResult<T> {
        if pointer.is_null() {
            return Err(IceError::deref_null_ptr());
        }
        T::read(self, pointer.addr)
    }

    pub fn per_cpu(&self, cpuid: usize) -> IceResult<VirtualAddress> {
        let per_cpu_offset = self.profile.fast_syms.per_cpu_offset + self.kaslr;
        self.read_kernel_value(per_cpu_offset + 8 * cpuid as u64)
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

                use ibc::{
                    arch::{Vcpu, Vcpus},
                    Os,
                };

                let vcpu = self.backend.vcpus().get(cpuid);
                let vcpu_pgd = vcpu.pgd();

                match vcpu.into_runtime() {
                    ice::arch::runtime::Vcpu::Aarch64(vcpu) => {
                        if vcpu.instruction_pointer().is_kernel() {
                            let current_task = VirtualAddress(vcpu.registers.sp);
                            return Ok(ibc::Thread(current_task));
                        }
                    }
                    _ => (),
                };

                log::debug!("Using fallback to get current task");

                let mut current_task = None;
                self.for_each_process(&mut |proc| {
                    let proc_pgd = self.process_pgd(proc)?;
                    if proc_pgd == vcpu_pgd {
                        current_task = Some(ibc::Thread(proc.0));
                    }
                    Ok(())
                })?;

                current_task.ok_or_else(|| ibc::IceError::new("cannot find current thread"))
            }
        }
    }

    /// Iterate a kernel linked list, yielding elements of type `T`
    fn iterate_list<T, O, F>(
        &self,
        head: Pointer<profile::ListHead>,
        get_offset: O,
        mut f: F,
    ) -> IceResult<()>
    where
        Self: HasStruct<T> + HasStruct<profile::ListHead>,
        O: FnOnce(&T) -> StructOffset<profile::ListHead>,
        F: FnMut(Pointer<T>) -> IceResult<()>,
    {
        let mut pos = head;
        let offset = get_offset(self.get_struct_layout()).offset;

        loop {
            pos = self.read_struct_pointer(pos, |list| list.next)?;

            if pos == head {
                break;
            }

            f(Pointer::new(pos.addr - offset))?;
        }

        Ok(())
    }

    fn processes(&self) -> IceResult<&HashMap<ibc::Process, ProcessData>> {
        self.processes.get_or_try_init(|| {
            let mut processes = HashMap::new();

            let init = ibc::Os::init_process(self)?;

            processes.insert(init, ProcessData::default());

            self.iterate_list::<profile::TaskStruct, _, _>(
                self.read_struct(init.into(), |ts| ts.tasks)?,
                |ts| ts.tasks,
                |proc| {
                    processes.insert(proc.into(), ProcessData::default());
                    Ok(())
                },
            )?;

            Ok(processes)
        })
    }

    fn process(&self, proc: ibc::Process) -> IceResult<Option<&ProcessData>> {
        let procs = self.processes()?;
        Ok(procs.get(&proc))
    }

    fn process_iter_children<F>(&self, proc: ibc::Process, mut f: F) -> IceResult<()>
    where
        F: FnMut(ibc::Process) -> IceResult<()>,
    {
        let children = self.read_struct(proc.into(), |ts| ts.children)?;
        self.iterate_list::<profile::TaskStruct, _, _>(
            children,
            |ts| ts.sibling,
            |child| f(child.into()),
        )
    }

    fn build_path(&self, dentry: Pointer<profile::Dentry>, buf: &mut Vec<u8>) -> IceResult<()> {
        // Paths start with the last components in the kernel but we want them
        // to start by the root, so we call ourselves recursively to build the
        // beginning first

        let parent = self.read_struct_pointer(dentry, |d| d.d_parent)?;
        if parent != dentry {
            self.build_path(parent, buf)?;
        }

        let qstr = self.read_struct(dentry, |d| d.d_name)?;
        let name = self.read_struct_pointer(qstr, |qstr| qstr.name)?;

        // TODO: use qstr.len here
        let mut len = buf.len();
        buf.extend_from_slice(&[0; 256]);
        if len > 0 && buf[len - 1] != b'/' {
            buf[len] = b'/';
            len += 1;
        }
        self.read_kernel_memory(name, &mut buf[len..])?;

        match memchr::memchr(0, &buf[len..]) {
            Some(i) => buf.truncate(len + i),
            None => todo!(),
        }

        Ok(())
    }

    pub fn find_symbol(&self, lib: &str, addr: VirtualAddress) -> Option<&str> {
        let lib = self.profile.syms.get_lib(lib).ok()?;
        lib.get_name(addr)
    }

    fn process_mm(&self, proc: ice::Process) -> IceResult<Pointer<profile::MmStruct>> {
        let proc = proc.into();
        let mut mm = self.read_struct_pointer(proc, |ts| ts.mm)?;

        // Kernel processes use this instead. This is NULL too on aarch64 though
        if mm.is_null() {
            mm = self.read_struct_pointer(proc, |ts| ts.active_mm)?;
        }

        Ok(mm)
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
    fn init_process(&self) -> IceResult<ibc::Process> {
        Ok(ibc::Process(self.profile.fast_syms.init_task + self.kaslr))
    }

    fn current_thread(&self, cpuid: usize) -> IceResult<ibc::Thread> {
        self.current_thread(cpuid)
    }

    fn thread_process(&self, thread: ibc::Thread) -> IceResult<ibc::Process> {
        let pointer = self.read_struct_pointer(thread.into(), |ts| ts.group_leader)?;
        Ok(pointer.into())
    }

    fn process_is_kernel(&self, proc: ibc::Process) -> IceResult<bool> {
        let flags = self.read_struct_pointer(proc.into(), |ts| ts.flags)?;
        Ok(flags & 0x200000 != 0)
    }

    fn process_pid(&self, proc: ibc::Process) -> IceResult<u64> {
        let get_pid = || self.read_struct_pointer(proc.into(), |ts| ts.tgid);

        match self.process(proc)? {
            Some(proc) => proc.pid.get_or_try_init(get_pid).map(|pid| *pid),
            None => get_pid(),
        }
        .map(|pid| pid as u64)
    }

    fn process_name(&self, proc: ice::Process) -> IceResult<String> {
        let get_name = || {
            let comm = self.read_struct_pointer(proc.into(), |ts| ts.comm)?;

            let buf = match memchr::memchr(0, &comm) {
                Some(i) => &comm[..i],
                None => &comm,
            };

            Ok(String::from_utf8_lossy(buf).into_owned())
        };

        match self.process(proc)? {
            Some(proc) => proc.name.get_or_try_init(get_name).map(Clone::clone),
            None => get_name(),
        }
    }

    fn process_pgd(&self, proc: ice::Process) -> IceResult<PhysicalAddress> {
        let mm = self.process_mm(proc)?;
        if mm.is_null() {
            if self.process_is_kernel(proc)? {
                Ok(self.kpgd)
            } else {
                Err(ibc::IceError::new("process has NULL mm"))
            }
        } else {
            let pgd = self.read_struct_pointer(mm, |mms| mms.pgd)?;
            self.backend.virtual_to_physical(self.kpgd, pgd).valid()
        }
    }

    fn process_exe(&self, proc: ice::Process) -> IceResult<Option<ibc::Path>> {
        let mm = self.process_mm(proc)?;

        let file = self.read_struct_pointer(mm, |mm| mm.exe_file)?;
        if file.is_null() {
            return Ok(None);
        }
        let path = self.read_struct(file, |file| file.f_path)?;
        Ok(Some(path.into()))
    }

    fn process_parent(&self, proc: ice::Process) -> IceResult<ice::Process> {
        let get_parent = || {
            let proc = self.read_struct_pointer(proc.into(), |ts| ts.real_parent)?;
            Ok(proc.into())
        };

        match self.process(proc)? {
            Some(proc) => proc.parent.get_or_try_init(get_parent).map(|p| *p),
            None => get_parent(),
        }
    }

    fn process_for_each_child(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Process) -> IceResult<()>,
    ) -> IceResult<()> {
        match self.process(proc)? {
            Some(proc_data) => {
                let children = proc_data.children.get_or_try_init(|| {
                    let mut children = Vec::new();
                    self.process_iter_children(proc, |child| {
                        children.push(child);
                        Ok(())
                    })?;
                    Ok(children)
                })?;

                children.iter().copied().try_for_each(f)
            }
            None => self.process_iter_children(proc, f),
        }
    }

    fn process_for_each_thread(
        &self,
        proc: ice::Process,
        f: &mut dyn FnMut(ice::Thread) -> IceResult<()>,
    ) -> IceResult<()> {
        let thread_group = self.read_struct(proc.into(), |ts| ts.thread_group)?;
        self.iterate_list::<profile::TaskStruct, _, _>(
            thread_group,
            |ts| ts.thread_group,
            |thread| f(thread.into()),
        )
    }

    fn for_each_process(&self, f: &mut dyn FnMut(ibc::Process) -> IceResult<()>) -> IceResult<()> {
        self.processes()?.keys().copied().try_for_each(f)
    }

    fn process_for_each_vma(
        &self,
        proc: ice::Process,
        f: &mut dyn FnMut(ice::Vma) -> IceResult<()>,
    ) -> IceResult<()> {
        let mm = self.process_mm(proc)?;
        let mut cur_vma = self.read_struct_pointer(mm, |mm| mm.mmap)?;

        while !cur_vma.is_null() {
            f(cur_vma.into())?;
            cur_vma = self.read_struct_pointer(cur_vma, |vma| vma.vm_next)?;
        }

        Ok(())
    }

    fn process_callstack(
        &self,
        proc: ice::Process,
        f: &mut dyn FnMut(&ice::StackFrame) -> IceResult<()>,
    ) -> IceResult<()> {
        callstack::iter(self, proc, f)
    }

    fn thread_id(&self, thread: ice::Thread) -> IceResult<u64> {
        self.read_struct_pointer(thread.into(), |ts| ts.pid)
            .map(|pid| pid as u64)
    }

    fn thread_name(&self, thread: ibc::Thread) -> IceResult<Option<String>> {
        self.process_name(ibc::Process(thread.0)).map(Some)
    }

    fn path_to_string(&self, path: ice::Path) -> IceResult<String> {
        let dentry = self.read_struct_pointer(path.into(), |p| p.dentry)?;
        let mut buf = Vec::new();

        self.build_path(dentry, &mut buf)?;

        String::from_utf8(buf).map_err(ice::IceError::new)
    }

    fn vma_file(&self, vma: ice::Vma) -> IceResult<Option<ibc::Path>> {
        let file = self.read_struct_pointer(vma.into(), |vma| vma.vm_file)?;

        if file.is_null() {
            return Ok(None);
        }
        let path = self.read_struct(file, |file| file.f_path)?;
        Ok(Some(path.into()))
    }

    fn vma_start(&self, vma: ice::Vma) -> IceResult<VirtualAddress> {
        self.read_struct_pointer(vma.into(), |vma| vma.vm_start)
    }

    fn vma_end(&self, vma: ice::Vma) -> IceResult<VirtualAddress> {
        self.read_struct_pointer(vma.into(), |vma| vma.vm_end)
    }

    fn vma_flags(&self, vma: ice::Vma) -> IceResult<ibc::VmaFlags> {
        let flags: u64 = self.read_struct_pointer(vma.into(), |vma| vma.vm_flags)?;
        Ok(ibc::VmaFlags(flags))
    }

    fn vma_offset(&self, vma: ice::Vma) -> IceResult<u64> {
        self.read_struct_pointer(vma.into(), |vma| vma.vm_pgoff)
            .map(|offset| offset * 4096)
    }

    fn resolve_symbol(&self, addr: VirtualAddress, vma: ice::Vma) -> IceResult<Option<&str>> {
        if !self.vma_contains(vma, addr)? {
            return Err(IceError::new("the address does not belong to the VMA"));
        }

        let offset = addr - (self.vma_start(vma)? - self.vma_offset(vma)?);
        let addr = VirtualAddress(offset as u64);

        let module = match self.vma_file(vma)? {
            Some(path) => self.path_to_string(path)?,
            None => return Ok(None),
        };
        let module = match module.rsplit_once('/') {
            Some((_, module)) => module,
            None => return Ok(None),
        };

        Ok(self.find_symbol(&module, addr))
    }
}

impl<B> fmt::Debug for Linux<B> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Linux").finish_non_exhaustive()
    }
}
