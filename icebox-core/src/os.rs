use crate::{GuestPhysAddr, IceResult};
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thread(pub GuestPhysAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process(pub GuestPhysAddr);

pub trait Os {
    fn init_process(&self) -> IceResult<Process>;
    fn current_thread(&self, cpuid: usize) -> IceResult<Thread>;
    fn current_process(&self, cpuid: usize) -> IceResult<Process> {
        let thread = self.current_thread(cpuid)?;
        self.thread_process(thread)
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
    fn process_for_each_thread(
        &self,
        proc: Process,
        f: &mut dyn FnMut(Thread) -> IceResult<()>,
    ) -> IceResult<()>;

    fn for_each_process(&self, f: &mut dyn FnMut(Process) -> IceResult<()>) -> IceResult<()>;

    fn thread_process(&self, thread: Thread) -> IceResult<Process>;
    fn thread_id(&self, thread: Thread) -> IceResult<u32>;
    fn thread_name(&self, thread: Thread) -> IceResult<String>;
}
