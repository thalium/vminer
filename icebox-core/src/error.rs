use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use core::fmt;

#[cfg(feature = "std")]
pub use std::error::Error;

use crate::seal;

#[cfg(not(feature = "std"))]
pub trait Error: fmt::Display + fmt::Debug {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

#[cfg(not(feature = "std"))]
impl<E> From<E> for Box<dyn Error + Send + Sync>
where
    E: Error + Send + Sync + 'static,
{
    fn from(err: E) -> Self {
        Box::new(err)
    }
}

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
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            #[cfg(feature = "std")]
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for MemoryAccessError {
    #[cold]
    #[inline]
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

#[derive(Debug)]
enum Repr {
    Memory(MemoryAccessError),
    InvalidPage,

    UnsupportedArchitecture,

    MissingSymbol(Box<str>),
    MissingField(Box<str>, Box<str>),

    #[cfg(feature = "std")]
    Io(std::io::Error),
    Other(Box<dyn Error + Send + Sync>),
    Message(Box<str>, Option<Box<dyn Error + Send + Sync>>),
    Context(Box<str>, IceError),
}

#[derive(Debug)]
#[repr(transparent)]
pub struct IceError {
    repr: Box<Repr>,
}

pub type IceResult<T> = Result<T, IceError>;

impl IceError {
    #[inline]
    fn from_repr(repr: Repr) -> Self {
        Self {
            repr: Box::new(repr),
        }
    }

    #[cold]
    pub fn missing_symbol(sym: &str) -> Self {
        Self::from_repr(Repr::MissingSymbol(sym.into()))
    }

    #[cold]
    pub fn missing_field(field: &str, typ: &str) -> Self {
        Self::from_repr(Repr::MissingField(field.into(), typ.into()))
    }

    #[cold]
    pub fn new(err: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self::from_repr(Repr::Other(err.into()))
    }

    #[cold]
    pub fn with_message(
        context: impl fmt::Display,
        err: impl Into<Box<dyn Error + Send + Sync>>,
    ) -> Self {
        Self::from_repr(Repr::Message(context.to_string().into(), Some(err.into())))
    }

    #[cold]
    pub fn unsupported_architecture() -> Self {
        Self::from_repr(Repr::UnsupportedArchitecture)
    }

    pub fn print_backtrace(&self) -> String {
        let mut trace = String::new();
        fmt::write(&mut trace, format_args!("{:#}", self)).unwrap();
        trace
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Repr::Memory(_) => f.write_str("failed to access physical memory"),
            Repr::InvalidPage => f.write_str("failed to translate virtual address"),
            Repr::UnsupportedArchitecture => {
                f.write_str("operation unsupported by the architecture")
            }
            Repr::MissingSymbol(sym) => {
                f.write_fmt(format_args!("missing required symbol \"{}\"", sym))
            }
            Repr::MissingField(field, typ) => f.write_fmt(format_args!(
                "missing required field \"{}\" in type \"{}\"",
                field, typ
            )),

            #[cfg(feature = "std")]
            Repr::Io(_) => f.write_str("I/O error"),
            Repr::Message(msg, _) | Repr::Context(msg, _) => f.write_str(msg),
            Repr::Other(err) => err.fmt(f),
        }
    }
}

impl fmt::Display for IceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            f.write_fmt(format_args!("{}", self.repr))?;

            let mut current = self.source();

            if current.is_some() {
                f.write_str("\n\nCaused by:")?;
            }

            while let Some(cause) = current {
                f.write_fmt(format_args!("\n    {}", cause))?;
                current = cause.source();
            }

            Ok(())
        } else {
            self.repr.fmt(f)
        }
    }
}

impl Error for IceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &*self.repr {
            Repr::Memory(err) => Some(err),
            #[cfg(feature = "std")]
            Repr::Io(err) => Some(err),
            Repr::Message(_, err) => Some(&**err.as_ref()?),
            Repr::Other(err) => err.source(),
            Repr::Context(_, err) => Some(err),
            _ => None,
        }
    }
}

impl From<&str> for IceError {
    #[cold]
    fn from(msg: &str) -> Self {
        Self::from_repr(Repr::Message(msg.into(), None))
    }
}

impl From<MemoryAccessError> for IceError {
    #[cold]
    fn from(err: MemoryAccessError) -> Self {
        Self::from_repr(Repr::Memory(err))
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for IceError {
    #[cold]
    fn from(error: std::io::Error) -> Self {
        Self::from_repr(Repr::Io(error))
    }
}

pub trait MemoryAccessResultExt<T>: seal::Sealed {
    fn valid(self) -> IceResult<T>;
}

impl<T> MemoryAccessResultExt<T> for MemoryAccessResult<Option<T>> {
    fn valid(self) -> IceResult<T> {
        self?.ok_or_else(|| IceError::from_repr(Repr::InvalidPage))
    }
}

pub trait ResultExt<T>: seal::Sealed {
    fn context(self, msg: impl ToString) -> IceResult<T>;
}

impl<T> ResultExt<T> for IceResult<T> {
    fn context(self, msg: impl ToString) -> IceResult<T> {
        self.map_err(|err| IceError::from_repr(Repr::Context(msg.to_string().into(), err)))
    }
}

#[cfg(feature = "python")]
pyo3::create_exception!(icebox, IceboxError, pyo3::exceptions::PyException);

#[cfg(feature = "python")]
impl From<IceError> for pyo3::PyErr {
    fn from(err: IceError) -> Self {
        IceboxError::new_err(err.print_backtrace())
    }
}

#[cfg(feature = "python")]
impl From<MemoryAccessError> for pyo3::PyErr {
    fn from(err: MemoryAccessError) -> Self {
        IceError::from(err).into()
    }
}
