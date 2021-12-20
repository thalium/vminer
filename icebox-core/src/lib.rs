#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_debug_implementations)]

extern crate alloc;

mod addr;
pub use addr::{MmPte, PhysicalAddress, VirtualAddress};

pub mod arch;
pub use arch::Architecture;

mod backend;
pub use backend::{Backend, RuntimeBackend};

mod error;
pub use error::{
    Error, IceError, IceResult, MemoryAccessError, MemoryAccessResult, MemoryAccessResultExt,
};

mod mem;
#[cfg(feature = "std")]
pub use mem::File;
pub use mem::Memory;

mod os;
pub use os::{Os, Process, Thread, Vma, VmaFlags};

pub mod symbols;
pub use symbols::SymbolsIndexer;

pub const fn mask(size: u32) -> u64 {
    !(!0 << size)
}

mod seal {
    pub trait Sealed {}

    impl<T, E> Sealed for Result<T, E> {}
}
