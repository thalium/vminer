use crate::{backend::MemoryAccessResult, Backend};

pub trait Os {
    fn quick_check<B: Backend>(_backend: &B) -> MemoryAccessResult<bool> {
        Ok(false)
    }
}
