use crate::{GuestPhysAddr, IceResult};
use alloc::string::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thread(pub GuestPhysAddr);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Process(pub GuestPhysAddr);

pub trait Os {
    fn current_thread(&self, cpuid: usize) -> IceResult<Thread>;
    fn current_process(&self, cpuid: usize) -> IceResult<Process> {
        let thread = self.current_thread(cpuid)?;
        self.thread_process(thread)
    }

    fn process_pid(&self, proc: Process) -> IceResult<u32>;
    fn process_name(&self, proc: Process) -> IceResult<String>;
    fn process_parent(&self, proc: Process) -> IceResult<Process>;

    fn thread_process(&self, thread: Thread) -> IceResult<Process>;
}
