pub mod callstack;
pub mod process;
pub mod profile;

use crate::core::{self as ice, IceResult, MemoryAccessResultExt, PhysicalAddress, VirtualAddress};
use crate::utils::OnceCell;
use alloc::{string::String, vec::Vec};
use core::fmt;
use hashbrown::HashMap;

use process::Process;
pub use profile::Profile;

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

fn per_cpu<B: ice::Backend>(backend: &B, cpuid: usize) -> IceResult<VirtualAddress> {
    backend.kernel_per_cpu(cpuid, is_kernel_addr)
}

fn find_kpgd<B: ice::Backend>(backend: &B) -> IceResult<PhysicalAddress> {
    let valid_addr = per_cpu(backend, 0)?;
    backend.find_kernel_pgd(valid_addr)
}

pub fn get_aslr<B: ice::Backend>(
    backend: &B,
    profile: &Profile,
    kpgd: PhysicalAddress,
) -> IceResult<i64> {
    let base_banner_addr = profile.syms.get_addr("linux_banner")?;
    let (banner_addr, _) =
        get_banner_addr(backend, kpgd)?.ok_or("could not find banner address")?;

    Ok(banner_addr.0.overflowing_sub(base_banner_addr.0).0 as i64)
}

pub const fn is_kernel_addr(addr: VirtualAddress) -> bool {
    (addr.0 as i64) < 0
}

impl<B: ice::Backend> Linux<B> {
    pub fn create(backend: B, profile: Profile) -> IceResult<Self> {
        let kpgd = find_kpgd(&backend)?;
        let kaslr = get_aslr(&backend, &profile, kpgd)?;

        Ok(Linux {
            backend,
            profile,
            kpgd,
            kaslr,

            processes: OnceCell::new(),
        })
    }

    fn kernel_to_physical(&self, addr: VirtualAddress) -> IceResult<PhysicalAddress> {
        self.backend.virtual_to_physical(self.kpgd, addr).valid()
    }

    fn read_kernel_value<T: bytemuck::Pod>(&self, addr: VirtualAddress) -> IceResult<T> {
        self.backend.read_value_virtual(self.kpgd, addr)
    }

    fn read_kernel_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()> {
        self.backend.read_virtual_memory(self.kpgd, addr, buf)
    }

    #[cfg(feature = "std")]
    pub fn read_current_task(&self, cpuid: usize) -> IceResult<()> {
        let current_task = per_cpu(&self.backend, cpuid)?
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);

        let addr = self.read_kernel_value(current_task)?;

        let addr = self.kernel_to_physical(addr)?;
        let task_struct = self.profile.syms.get_struct("task_struct")?;

        for win in task_struct.fields[..100].windows(2) {
            match win {
                [current, next] => {
                    let size = (next.offset - current.offset) as usize;
                    let mut buf = [0; 1024];
                    let buf = &mut buf[..size];
                    self.backend.read_memory(addr + current.offset, buf)?;

                    match size {
                        4 => {
                            let x: &u32 = bytemuck::from_bytes(buf);
                            println!("{} ({}): {}", current.name, size, x);
                        }
                        8 => {
                            let x: &u64 = bytemuck::from_bytes(buf);
                            println!("{} ({}): {}", current.name, size, x);
                        }
                        _ => println!("{} ({}): {:02x?}", current.name, size, buf),
                    }
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }

    pub fn current_thread(&self, cpuid: usize) -> IceResult<ibc::Thread> {
        let current_task = per_cpu(&self.backend, cpuid)?
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);

        let addr = self.read_kernel_value(current_task)?;
        Ok(ibc::Thread(addr))
    }

    pub fn iterate_list(
        &self,
        head: VirtualAddress,
        mut f: impl FnMut(VirtualAddress) -> IceResult<()>,
    ) -> IceResult<()> {
        let mut pos = head;
        let next_offset = self.profile.fast_offsets.list_head_next;

        loop {
            pos = self.read_kernel_value(pos + next_offset)?;

            if pos == head {
                break;
            }

            f(pos)?;
        }

        Ok(())
    }

    fn processes(&self) -> IceResult<&HashMap<ibc::Process, ProcessData>> {
        self.processes.get_or_try_init(|| {
            let mut processes = HashMap::new();

            let offsets = &self.profile.fast_offsets;
            let init = ibc::Os::init_process(self)?;

            processes.insert(init, ProcessData::default());
            self.iterate_list(init.0 + offsets.task_struct_tasks, |addr| {
                let proc = ibc::Process(addr - offsets.task_struct_tasks);
                processes.insert(proc, ProcessData::default());
                Ok(())
            })?;

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
        let offsets = &self.profile.fast_offsets;

        self.iterate_list(proc.0 + offsets.task_struct_children, |addr| {
            f(ibc::Process(addr - offsets.task_struct_sibling))
        })
    }

    fn build_path(&self, dentry: VirtualAddress, buf: &mut Vec<u8>) -> IceResult<()> {
        let offsets = &self.profile.fast_offsets;

        let parent: VirtualAddress = self.read_kernel_value(dentry + offsets.dentry_d_parent)?;
        if parent != dentry {
            self.build_path(parent, buf)?;
        }

        let name: VirtualAddress =
            self.read_kernel_value(dentry + offsets.dentry_d_name + offsets.qstr_name)?;

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
}

fn get_banner_addr<B: ice::Backend>(
    backend: &B,
    mmu_addr: PhysicalAddress,
) -> ice::MemoryAccessResult<Option<(VirtualAddress, PhysicalAddress)>> {
    const OFFSET: usize = 0x1000;
    const TARGET: &[u8] = b"Linux version";

    const KERNEL_START: u64 = 0xffffffff80000000;
    const KERNEL_END: u64 = 0xfffffffffff00000;

    let mut buf = [0; OFFSET + TARGET.len()];
    let finder = memchr::memmem::Finder::new(TARGET);

    for addr in (KERNEL_START..KERNEL_END).step_by(OFFSET) {
        let addr = VirtualAddress(addr);
        if let Some(paddr) = backend.virtual_to_physical(mmu_addr, addr)? {
            backend.read_memory(paddr, &mut buf)?;

            if let Some(offset) = finder.find(&buf) {
                let offset = offset as u64;
                return Ok(Some((addr + offset, paddr + offset)));
            }
        }
    }

    Ok(None)
}

impl<B: ice::Backend> super::OsBuilder<B> for Linux<B> {
    fn quick_check(backend: &B) -> IceResult<bool> {
        let mmu_addr = find_kpgd(backend)?;
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
        Process::new(ibc::Process(thread.0), self).group_leader()
    }

    fn process_is_kernel(&self, proc: ibc::Process) -> IceResult<bool> {
        Process::new(proc, self).is_kernel()
    }

    fn process_pid(&self, proc: ibc::Process) -> IceResult<u32> {
        let get_pid = || Process::new(proc, self).pid();

        match self.process(proc)? {
            Some(proc) => proc.pid.get_or_try_init(get_pid).map(|pid| *pid),
            None => get_pid(),
        }
    }

    fn process_name(&self, proc: ice::Process) -> IceResult<String> {
        let get_name = || Process::new(proc, self).comm();

        match self.process(proc)? {
            Some(proc) => proc.name.get_or_try_init(get_name).map(Clone::clone),
            None => get_name(),
        }
    }

    fn process_pgd(&self, proc: ice::Process) -> IceResult<PhysicalAddress> {
        Process::new(proc, self).pgd()
    }

    fn process_exe(&self, proc: ice::Process) -> IceResult<Option<ibc::Path>> {
        let mm = Process::new(proc, self).mm()?;
        let offsets = &self.profile.fast_offsets;

        let file: VirtualAddress = self.read_kernel_value(mm + offsets.mm_struct_exe_file)?;
        if file.is_null() {
            return Ok(None);
        }
        // let path = self.kernel_to_physical(file + offsets.file_f_path)?;
        Ok(Some(ibc::Path(file + offsets.file_f_path)))
    }

    fn process_parent(&self, proc: ice::Process) -> IceResult<ice::Process> {
        let get_parent = || Process::new(proc, self).parent();

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
        let offsets = &self.profile.fast_offsets;

        self.iterate_list(proc.0 + offsets.task_struct_thread_group, |addr| {
            f(ibc::Thread(addr - offsets.task_struct_thread_group))
        })
    }

    fn for_each_process(&self, f: &mut dyn FnMut(ibc::Process) -> IceResult<()>) -> IceResult<()> {
        self.processes()?.keys().copied().try_for_each(f)
    }

    fn process_for_each_vma(
        &self,
        proc: ice::Process,
        f: &mut dyn FnMut(ice::Vma) -> IceResult<()>,
    ) -> IceResult<()> {
        let offsets = &self.profile.fast_offsets;

        let mm = Process::new(proc, self).mm()?;
        let mut cur_vma: VirtualAddress = self.read_kernel_value(mm + offsets.mm_struct_mmap)?;

        while !cur_vma.is_null() {
            f(ice::Vma(cur_vma))?;
            cur_vma = self.read_kernel_value(cur_vma + offsets.vm_area_struct_vm_next)?;
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

    fn thread_id(&self, thread: ice::Thread) -> IceResult<u32> {
        Process::new(ibc::Process(thread.0), self).tid()
    }

    fn thread_name(&self, thread: ibc::Thread) -> IceResult<String> {
        self.process_name(ibc::Process(thread.0))
    }

    fn path_to_string(&self, path: ice::Path) -> IceResult<String> {
        let offsets = &self.profile.fast_offsets;

        let dentry = self.read_kernel_value(path.0 + offsets.path_d_entry)?;
        let mut buf = Vec::new();

        self.build_path(dentry, &mut buf)?;

        String::from_utf8(buf).map_err(|err| ice::IceError::new(err))
    }

    fn vma_file(&self, vma: ice::Vma) -> IceResult<Option<ibc::Path>> {
        let offsets = &self.profile.fast_offsets;

        let file: VirtualAddress =
            self.read_kernel_value(vma.0 + offsets.vm_area_struct_vm_file)?;

        if file.is_null() {
            return Ok(None);
        }
        Ok(Some(ibc::Path(file + offsets.file_f_path)))
    }

    fn vma_start(&self, vma: ice::Vma) -> IceResult<VirtualAddress> {
        self.read_kernel_value(vma.0 + self.profile.fast_offsets.vm_area_struct_vm_start)
    }

    fn vma_end(&self, vma: ice::Vma) -> IceResult<VirtualAddress> {
        self.read_kernel_value(vma.0 + self.profile.fast_offsets.vm_area_struct_vm_end)
    }

    fn vma_flags(&self, vma: ice::Vma) -> IceResult<ibc::VmaFlags> {
        let flags: u64 =
            self.read_kernel_value(vma.0 + self.profile.fast_offsets.vm_area_struct_vm_flags)?;
        Ok(ibc::VmaFlags(flags))
    }
}

impl<B> fmt::Debug for Linux<B> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Linux").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use crate::backends;
    use crate::os::{Linux, OsBuilder};

    #[test]
    fn quick_check() {
        let vm = backends::kvm_dump::DumbDump::read("../linux.dump").unwrap();
        assert!(Linux::quick_check(&vm).unwrap());

        let vm = backends::kvm_dump::DumbDump::read("../grub.dump").unwrap();
        assert!(!Linux::quick_check(&vm).unwrap());
    }
}
