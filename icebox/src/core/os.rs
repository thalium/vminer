use crate::core::backend::Backend;
use crate::core::error::MemoryAccessResult;

pub trait Os {
    fn quick_check<B: Backend>(_backend: &B) -> MemoryAccessResult<bool> {
        Ok(false)
    }
}
