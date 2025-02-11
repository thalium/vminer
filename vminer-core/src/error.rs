use alloc::{
    boxed::Box,
    string::{String, ToString},
};
use core::{error::Error, fmt};

use crate::seal;

// Add a few common conversions for convenience

#[derive(Debug)]
pub enum VcpuError {
    Unsupported,
    InvalidId,
    BadArchitecture,
    UnknownRegister,
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

pub type VcpuResult<T> = Result<T, VcpuError>;

impl fmt::Display for VcpuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("unsupported operation"),
            Self::InvalidId => f.write_str("invalid vCPU ID"),
            Self::BadArchitecture => f.write_str("wrong architecture"),
            Self::UnknownRegister => f.write_str("unknown register"),
            #[cfg(feature = "std")]
            Self::Io(err) => err.fmt(f),
        }
    }
}

impl Error for VcpuError {
    #[inline]
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            #[cfg(feature = "std")]
            Self::Io(err) => err.source(),
            _ => None,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum MemoryAccessError {
    OutOfBounds,
    Unsupported,
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

impl fmt::Display for MemoryAccessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::OutOfBounds => f.write_str("out of bounds memory access"),
            Self::Unsupported => f.write_str("unsupported operation"),
            #[cfg(feature = "std")]
            Self::Io(err) => err.fmt(f),
        }
    }
}

impl Error for MemoryAccessError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            #[cfg(feature = "std")]
            Self::Io(err) => err.source(),
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
            MemoryAccessError::Unsupported => std::io::Error::from(std::io::ErrorKind::Unsupported),
            MemoryAccessError::Io(error) => error,
        }
    }
}

pub type MemoryAccessResult<T> = Result<T, MemoryAccessError>;

#[derive(Debug)]
pub enum TranslationError {
    Memory(MemoryAccessError),
    Invalid(u64),
}

pub type TranslationResult<T> = Result<T, TranslationError>;

impl From<MemoryAccessError> for TranslationError {
    fn from(err: MemoryAccessError) -> Self {
        Self::Memory(err)
    }
}

impl From<TranslationError> for VmError {
    fn from(err: TranslationError) -> Self {
        match err {
            TranslationError::Memory(err) => err.into(),
            TranslationError::Invalid(entry) => VmError::from_repr(Repr::InvalidPage(entry)),
        }
    }
}

impl fmt::Display for TranslationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TranslationError::Memory(err) => err.fmt(f),
            TranslationError::Invalid(_) => f.write_str("invalid MMU entry"),
        }
    }
}

impl Error for TranslationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            TranslationError::Memory(err) => err.source(),
            TranslationError::Invalid(_) => None,
        }
    }
}

#[derive(Debug)]
enum Repr {
    Memory(MemoryAccessError),
    Vcpu(VcpuError),
    #[allow(dead_code)]
    InvalidPage(u64),

    UnsupportedArchitecture,
    Unsupported,
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
pub struct VmError {
    repr: Box<Repr>,
}

pub type VmResult<T> = Result<T, VmError>;

impl VmError {
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
    pub fn unsupported() -> Self {
        Self::from_repr(Repr::Unsupported)
    }

    #[cold]
    pub fn unimplemented() -> Self {
        Self::from_repr(Repr::Unimplemented)
    }

    pub fn print_backtrace(&self) -> String {
        let mut trace = String::new();
        fmt::write(&mut trace, format_args!("{self:#}")).unwrap();
        trace
    }
}

impl fmt::Display for Repr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Repr::Memory(_) => f.write_str("failed to access physical memory"),
            Repr::Vcpu(_) => f.write_str("failed to access registers"),
            Repr::InvalidPage(_) => f.write_str("encountered invalid page"),
            Repr::UnsupportedArchitecture => {
                f.write_str("operation unsupported by the architecture")
            }
            Repr::Unsupported => f.write_str("unsupported operation"),
            Repr::Unimplemented => f.write_str("unimplemented"),
            Repr::MissingModule(name) => {
                f.write_fmt(format_args!("missing required module \"{name}\""))
            }
            Repr::MissingSymbol(sym) => {
                f.write_fmt(format_args!("missing required symbol \"{sym}\""))
            }
            Repr::MissingField(field, typ) => f.write_fmt(format_args!(
                "missing required field \"{field}\" in type \"{typ}\""
            )),
            Repr::NullPtr => f.write_str("attempted to deref NULL pointer"),
            #[cfg(feature = "std")]
            Repr::Io(_) => f.write_str("I/O error"),
            Repr::Context(msg, _) => f.write_str(msg),
            Repr::Other(err) => err.fmt(f),
        }
    }
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            f.write_fmt(format_args!("{}", self.repr))?;

            let mut current = self.source();

            if current.is_some() {
                f.write_str("\n\nCaused by:")?;
            }

            while let Some(cause) = current {
                f.write_fmt(format_args!("\n    {cause}"))?;
                current = cause.source();
            }

            Ok(())
        } else {
            self.repr.fmt(f)
        }
    }
}

impl Error for VmError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &*self.repr {
            Repr::Memory(err) => Some(err),
            Repr::Vcpu(err) => Some(err),
            #[cfg(feature = "std")]
            Repr::Io(err) => Some(err),
            Repr::Context(_, err) => Some(&**err.as_ref()?),
            Repr::Other(err) => err.source(),
            _ => None,
        }
    }
}

impl From<&str> for VmError {
    #[cold]
    fn from(msg: &str) -> Self {
        Self::from_repr(Repr::Context(msg.into(), None))
    }
}

impl From<String> for VmError {
    #[cold]
    fn from(msg: String) -> Self {
        Self::from_repr(Repr::Context(msg.into(), None))
    }
}

impl From<MemoryAccessError> for VmError {
    #[cold]
    fn from(err: MemoryAccessError) -> Self {
        Self::from_repr(Repr::Memory(err))
    }
}

impl From<VcpuError> for VmError {
    #[cold]
    fn from(err: VcpuError) -> Self {
        Self::from_repr(Repr::Vcpu(err))
    }
}

impl From<core::str::Utf8Error> for VmError {
    #[cold]
    fn from(error: core::str::Utf8Error) -> Self {
        Self::from(error.to_string())
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for VmError {
    #[cold]
    fn from(error: std::io::Error) -> Self {
        Self::from_repr(Repr::Io(error))
    }
}

pub trait TranslationResultExt<T>: seal::Sealed {
    fn maybe_invalid(self) -> MemoryAccessResult<Option<T>>;
}

impl<T> TranslationResultExt<T> for TranslationResult<T> {
    fn maybe_invalid(self) -> MemoryAccessResult<Option<T>> {
        match self {
            Ok(x) => Ok(Some(x)),
            Err(TranslationError::Invalid(_)) => Ok(None),
            Err(TranslationError::Memory(err)) => Err(err),
        }
    }
}

pub trait ResultExt<T>: seal::Sealed {
    fn context(self, msg: impl ToString) -> VmResult<T>;

    fn with_context<F, S>(self, msg: F) -> VmResult<T>
    where
        F: FnOnce() -> S,
        S: ToString;
}

impl<T, E> ResultExt<T> for Result<T, E>
where
    E: Into<Box<dyn Error + Send + Sync>>,
{
    fn context(self, msg: impl ToString) -> VmResult<T> {
        self.map_err(|err| VmError::with_context(msg.to_string(), err))
    }

    fn with_context<F, S>(self, msg: F) -> VmResult<T>
    where
        F: FnOnce() -> S,
        S: ToString,
    {
        self.map_err(|err| VmError::with_context(msg().to_string(), err))
    }
}

impl<T> ResultExt<T> for Option<T> {
    fn context(self, msg: impl ToString) -> VmResult<T> {
        self.ok_or_else(|| VmError::new(msg.to_string()))
    }

    fn with_context<F, S>(self, msg: F) -> VmResult<T>
    where
        F: FnOnce() -> S,
        S: ToString,
    {
        self.ok_or_else(|| VmError::new(msg().to_string()))
    }
}
