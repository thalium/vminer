mod linux;
pub use linux::Linux;
mod windows;
pub use windows::Windows;

use std::io;

use crate::Backend;

pub trait Os {
    fn quick_check<B: Backend>(_backend: &B) -> io::Result<bool> {
        Ok(false)
    }
}
