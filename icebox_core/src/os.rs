use crate::{Backend, MemoryAccessResult};

pub trait Os {
    fn quick_check<B: Backend>(_backend: &B) -> MemoryAccessResult<bool> {
        Ok(false)
    }
}
