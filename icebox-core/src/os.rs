use crate::{Backend, GuestPhysAddr, MemoryAccessResult};

#[derive(Debug, Clone, Copy)]
pub struct Thread(pub GuestPhysAddr);

#[derive(Debug, Clone, Copy)]
pub struct Process(pub GuestPhysAddr);

pub trait Os {
    fn quick_check<B: Backend>(_backend: &B) -> MemoryAccessResult<bool> {
        Ok(false)
    }
}
