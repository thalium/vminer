use alloc::boxed::Box;
use core::fmt;

#[cfg(feature = "std")]
pub use std::error::Error;

#[cfg(not(feature = "std"))]
pub trait Error: fmt::Display + fmt::Debug {}

#[derive(Debug)]
#[non_exhaustive]
pub enum MemoryAccessError {
    OutOfBounds,
    #[cfg(feature = "std")]
    Io(std::io::Error),
    Other(Box<dyn Error + Send + Sync>),
}

impl fmt::Display for MemoryAccessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::OutOfBounds => f.write_str("out of bounds memory access"),
            #[cfg(feature = "std")]
            Self::Io(_) => f.write_str("i/o error"),
            Self::Other(e) => e.fmt(f),
        }
    }
}

impl Error for MemoryAccessError {
    #[cfg(feature = "std")]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for MemoryAccessError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[cfg(feature = "std")]
impl From<MemoryAccessError> for std::io::Error {
    fn from(error: MemoryAccessError) -> Self {
        match error {
            MemoryAccessError::OutOfBounds => std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "out of bounds memory access",
            ),
            MemoryAccessError::Io(error) => error,
            MemoryAccessError::Other(error) => {
                std::io::Error::new(std::io::ErrorKind::Other, error)
            }
        }
    }
}

pub type MemoryAccessResult<T> = Result<T, MemoryAccessError>;
