use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use core::fmt;

#[cfg(feature = "std")]
pub use std::error::Error;

use crate::seal;

// Unfortunately `Error` trait does not exist in `core` (yet ?) so we have to
// define it ourselves
#[cfg(not(feature = "std"))]
pub trait Error: fmt::Display + fmt::Debug {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

// Add a few common conversions for convenience

#[cfg(not(feature = "std"))]
impl<E> From<E> for Box<dyn Error + Send + Sync>
where
    E: Error + Send + Sync + 'static,
{
    fn from(err: E) -> Self {
        Box::new(err)
    }
}

#[cfg(not(feature = "std"))]
impl From<&'_ str> for Box<dyn Error + Send + Sync> {
    fn from(err: &str) -> Self {
        String::from(err).into()
    }
}

#[cfg(not(feature = "std"))]
impl From<String> for Box<dyn Error + Send + Sync> {
    fn from(err: String) -> Self {
        struct StringErr(String);

        impl fmt::Debug for StringErr {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl fmt::Display for StringErr {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl Error for StringErr {}

        Box::new(StringErr(err))
    }
}

#[cfg(not(feature = "std"))]
impl Error for alloc::string::FromUtf8Error {}

#[cfg(not(feature = "std"))]
impl Error for core::str::Utf8Error {}

#[cfg(not(feature = "std"))]
impl Error for object::Error {}

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
    Unimplemented,

    MissingModule(Box<str>),
    MissingSymbol(Box<str>),
    MissingField(Box<str>, Box<str>),

    NullPtr,

    #[cfg(feature = "std")]
    Io(std::io::Error),
    Other(Box<dyn Error + Send + Sync>),
    Context(Box<str>, Option<Box<dyn Error + Send + Sync>>),
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
    pub fn missing_module(sym: &str) -> Self {
        Self::from_repr(Repr::MissingModule(sym.into()))
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
    pub fn deref_null_ptr() -> Self {
        Self::from_repr(Repr::NullPtr)
    }

    #[cold]
    pub fn new(err: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self::from_repr(Repr::Other(err.into()))
    }

    #[cold]
    pub fn with_context(msg: impl ToString, err: impl Into<Box<dyn Error + Send + Sync>>) -> Self {
        Self::from_repr(Repr::Context(msg.to_string().into(), Some(err.into())))
    }

    #[cold]
    pub fn unsupported_architecture() -> Self {
        Self::from_repr(Repr::UnsupportedArchitecture)
    }

    #[cold]
    pub fn unimplemented() -> Self {
        Self::from_repr(Repr::Unimplemented)
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
            Repr::Unimplemented => f.write_str("unimplemented"),
            Repr::MissingModule(name) => {
                f.write_fmt(format_args!("missing required module \"{name}\""))
            }
            Repr::MissingSymbol(sym) => {
                f.write_fmt(format_args!("missing required symbol \"{}\"", sym))
            }
            Repr::MissingField(field, typ) => f.write_fmt(format_args!(
                "missing required field \"{}\" in type \"{}\"",
                field, typ
            )),
            Repr::NullPtr => f.write_str("attempted to deref NULL pointer"),
            #[cfg(feature = "std")]
            Repr::Io(_) => f.write_str("I/O error"),
            Repr::Context(msg, _) => f.write_str(msg),
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
            Repr::Context(_, err) => Some(&**err.as_ref()?),
            Repr::Other(err) => err.source(),
            _ => None,
        }
    }
}

impl From<&str> for IceError {
    #[cold]
    fn from(msg: &str) -> Self {
        Self::from_repr(Repr::Context(msg.into(), None))
    }
}

impl From<String> for IceError {
    #[cold]
    fn from(msg: String) -> Self {
        Self::from_repr(Repr::Context(msg.into(), None))
    }
}

impl From<MemoryAccessError> for IceError {
    #[cold]
    fn from(err: MemoryAccessError) -> Self {
        Self::from_repr(Repr::Memory(err))
    }
}

impl From<core::str::Utf8Error> for IceError {
    #[cold]
    fn from(error: core::str::Utf8Error) -> Self {
        Self::from(error.to_string())
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

    fn with_context<F, S>(self, msg: F) -> IceResult<T>
    where
        F: FnOnce() -> S,
        S: ToString;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: Into<Box<dyn Error + Send + Sync>>,
{
    fn context(self, msg: impl ToString) -> IceResult<T> {
        self.map_err(|err| IceError::with_context(msg.to_string(), err))
    }

    fn with_context<F, S>(self, msg: F) -> IceResult<T>
    where
        F: FnOnce() -> S,
        S: ToString,
    {
        self.map_err(|err| IceError::with_context(msg().to_string(), err))
    }
}

impl<T> ResultExt<T> for Option<T> {
    fn context(self, msg: impl ToString) -> IceResult<T> {
        self.ok_or_else(|| IceError::new(msg.to_string()))
    }

    fn with_context<F, S>(self, msg: F) -> IceResult<T>
    where
        F: FnOnce() -> S,
        S: ToString,
    {
        self.ok_or_else(|| IceError::new(msg().to_string()))
    }
}
