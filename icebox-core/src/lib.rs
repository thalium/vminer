#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_debug_implementations)]

extern crate alloc;

mod addr;
pub use addr::{PhysicalAddress, VirtualAddress};

pub mod arch;
pub use arch::Architecture;

mod backend;
pub use backend::{Backend, RuntimeBackend};

mod endian;
pub use endian::{BigEndian, Endianness, LittleEndian, RuntimeEndian};

mod error;
pub use error::{
    Error, IceError, IceResult, MemoryAccessError, MemoryAccessResult, ResultExt, TranslationError,
    TranslationResult, TranslationResultExt,
};

mod mem;
#[cfg(feature = "std")]
pub use mem::File;
pub use mem::Memory;

mod os;
pub use os::{Os, Path, Process, StackFrame, Thread, Vma, VmaFlags};

pub mod symbols;
pub use symbols::{ModuleSymbols, SymbolsIndexer};

#[inline]
pub const fn mask(size: u32) -> u64 {
    !(!0 << size)
}

#[inline]
pub const fn mask_range(from: u32, to: u32) -> u64 {
    mask(to - from) << from
}

mod seal {
    pub trait Sealed {}

    impl<T, E> Sealed for Result<T, E> {}
    impl<T> Sealed for Option<T> {}
}
