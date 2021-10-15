use core::fmt;

//#[cfg(feature = "std")]
pub use std::error::Error;

//#[cfg(not(feature = "std"))]
//pub trait Error: fmt::Display + fmt::Debug {}

//#[cfg(not(feature = "std"))]
//use alloc::boxed::Box;

#[derive(Debug)]
#[non_exhaustive]
pub enum MemoryAccessError {
    OutOfBounds,
    Io(Box<dyn Error + Send + Sync>),
    Other(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for MemoryAccessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::OutOfBounds => f.write_str("out of bounds memory access"),
            Self::Io(_) => f.write_str("i/o error"),
            Self::Other(e) => e.fmt(f),
        }
    }
}

impl Error for MemoryAccessError {
    #[cfg(feature = "std")]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(&**e),
            _ => None,
        }
    }
}

pub type MemoryAccessResult<T> = Result<T, MemoryAccessError>;
