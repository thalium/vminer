#[cfg(feature = "linux")]
pub mod linux;
#[cfg(feature = "linux")]
pub use linux::Linux;

use ibc::{Backend, IceResult};

pub trait OsBuilder<B: Backend> {
    fn quick_check(_backend: &B) -> IceResult<bool> {
        Ok(false)
    }
}
