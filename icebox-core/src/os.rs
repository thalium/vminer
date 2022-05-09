use crate::{IceResult, PhysicalAddress, VirtualAddress};
use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Thread(pub VirtualAddress);

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Process(pub VirtualAddress);

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Path(pub VirtualAddress);

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Vma(pub VirtualAddress);

#[derive(Debug, Clone, Copy)]
pub struct VmaFlags(pub u64);

impl VmaFlags {
    pub const READ: Self = Self(0x1);
    pub const WRITE: Self = Self(0x2);
    pub const EXEC: Self = Self(0x4);

    #[inline]
    pub fn is_read(self) -> bool {
        self.0 & Self::READ.0 != 0
    }

    #[inline]
    pub fn is_write(self) -> bool {
        self.0 & Self::WRITE.0 != 0
    }

    #[inline]
    pub fn is_exec(self) -> bool {
        self.0 & Self::EXEC.0 != 0
    }
}

impl core::ops::BitOr for VmaFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for VmaFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub range: Option<(VirtualAddress, u64)>,
    pub stack_pointer: VirtualAddress,
    pub instruction_pointer: VirtualAddress,
    pub vma: Vma,
    pub file: Option<Path>,
}

pub trait Os {
    fn init_process(&self) -> IceResult<Process>;
    fn current_thread(&self, cpuid: usize) -> IceResult<Thread>;
    fn current_process(&self, cpuid: usize) -> IceResult<Process> {
        let thread = self.current_thread(cpuid)?;
        self.thread_process(thread)
    }
    fn find_process_by_name(&self, name: &str) -> IceResult<Option<Process>> {
        let mut proc = None;

        self.for_each_process(&mut |p| {
            if self.process_name(p)? == name {
                proc = Some(p);
            }
            Ok(())
        })?;

        Ok(proc)
    }
    fn find_process_by_pid(&self, pid: u64) -> IceResult<Option<Process>> {
        let mut proc = None;

        self.for_each_process(&mut |p| {
            if self.process_pid(p)? == pid {
                proc = Some(p);
            }
            Ok(())
        })?;

        Ok(proc)
    }

    fn process_is_kernel(&self, proc: Process) -> IceResult<bool>;
    fn process_pid(&self, proc: Process) -> IceResult<u64>;
    fn process_name(&self, proc: Process) -> IceResult<String>;
    fn process_pgd(&self, proc: Process) -> IceResult<PhysicalAddress>;
    fn process_exe(&self, proc: Process) -> IceResult<Option<Path>>;
    fn process_parent(&self, proc: Process) -> IceResult<Process>;
    fn process_parent_id(&self, proc: Process) -> IceResult<u64>;
    fn process_for_each_child(
        &self,
        proc: Process,
        f: &mut dyn FnMut(Process) -> IceResult<()>,
    ) -> IceResult<()>;
    fn process_collect_children(&self, proc: Process) -> IceResult<Vec<Process>> {
        let mut procs = Vec::new();
        self.process_for_each_child(proc, &mut |p| Ok(procs.push(p)))?;
        Ok(procs)
    }
    fn process_for_each_thread(
        &self,
        proc: Process,
        f: &mut dyn FnMut(Thread) -> IceResult<()>,
    ) -> IceResult<()>;
    fn process_collect_threads(&self, proc: Process) -> IceResult<Vec<Thread>> {
        let mut threads = Vec::new();
        self.process_for_each_thread(proc, &mut |t| Ok(threads.push(t)))?;
        Ok(threads)
    }

    fn for_each_process(&self, f: &mut dyn FnMut(Process) -> IceResult<()>) -> IceResult<()>;
    fn collect_processes(&self) -> IceResult<Vec<Process>> {
        let mut procs = Vec::new();
        self.for_each_process(&mut |p| Ok(procs.push(p)))?;
        Ok(procs)
    }
    fn process_for_each_vma(
        &self,
        proc: Process,
        f: &mut dyn FnMut(Vma) -> IceResult<()>,
    ) -> IceResult<()>;
    fn process_collect_vmas(&self, proc: Process) -> IceResult<Vec<Vma>> {
        let mut vmas = Vec::new();
        self.process_for_each_vma(proc, &mut |vma| Ok(vmas.push(vma)))?;
        Ok(vmas)
    }

    fn process_find_vma_by_address(
        &self,
        proc: Process,
        addr: VirtualAddress,
    ) -> IceResult<Option<Vma>> {
        let mut vma = None;
        self.process_for_each_vma(proc, &mut |v| {
            if self.vma_contains(v, addr)? {
                vma = Some(v);
            }
            Ok(())
        })?;
        Ok(vma)
    }

    fn process_callstack(
        &self,
        proc: Process,
        f: &mut dyn FnMut(&StackFrame) -> IceResult<()>,
    ) -> IceResult<()>;

    fn thread_process(&self, thread: Thread) -> IceResult<Process>;
    fn thread_id(&self, thread: Thread) -> IceResult<u64>;
    fn thread_name(&self, thread: Thread) -> IceResult<Option<String>>;

    fn path_to_string(&self, path: Path) -> IceResult<String>;

    fn vma_file(&self, vma: Vma) -> IceResult<Option<Path>>;
    fn vma_start(&self, vma: Vma) -> IceResult<VirtualAddress>;
    fn vma_end(&self, vma: Vma) -> IceResult<VirtualAddress>;
    fn vma_flags(&self, vma: Vma) -> IceResult<VmaFlags>;
    fn vma_offset(&self, vma: Vma) -> IceResult<u64>;
    fn vma_contains(&self, vma: Vma, addr: VirtualAddress) -> IceResult<bool> {
        Ok(self.vma_start(vma)? <= addr && addr < self.vma_end(vma)?)
    }

    fn resolve_symbol_exact(
        &self,
        addr: VirtualAddress,
        proc: Process,
        vma: Vma,
    ) -> IceResult<Option<&str>>;
    fn resolve_symbol(
        &self,
        addr: VirtualAddress,
        proc: Process,
        vma: Vma,
    ) -> IceResult<Option<(&str, u64)>>;
}
