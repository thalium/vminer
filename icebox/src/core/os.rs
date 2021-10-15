use super::{Architecture, Backend, MemoryAccessResult};

pub trait Os {
    fn quick_check<Arch: Architecture, B: Backend<Arch>>(_backend: &B) -> MemoryAccessResult<bool> {
        Ok(false)
    }
}
