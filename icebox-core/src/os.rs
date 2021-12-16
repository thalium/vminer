use crate::{IceResult, PhysicalAddress, VirtualAddress};
use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thread(pub PhysicalAddress);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process(pub PhysicalAddress);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vma(pub PhysicalAddress);

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
    fn find_process_by_pid(&self, pid: u32) -> IceResult<Option<Process>> {
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
    fn process_pid(&self, proc: Process) -> IceResult<u32>;
    fn process_name(&self, proc: Process) -> IceResult<String>;
    fn process_parent(&self, proc: Process) -> IceResult<Process>;
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

    fn thread_process(&self, thread: Thread) -> IceResult<Process>;
    fn thread_id(&self, thread: Thread) -> IceResult<u32>;
    fn thread_name(&self, thread: Thread) -> IceResult<String>;

    fn vma_file(&self, vma: Vma) -> IceResult<Option<String>>;
    fn vma_start(&self, vma: Vma) -> IceResult<VirtualAddress>;
    fn vma_end(&self, vma: Vma) -> IceResult<VirtualAddress>;
}
