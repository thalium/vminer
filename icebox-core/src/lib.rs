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
pub use os::{Module, Os, Path, Process, StackFrame, Thread, Vma, VmaFlags};

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

pub fn read_virtual_memory(
    mut addr: VirtualAddress,
    mut buf: &mut [u8],
    read_memory: impl Fn(VirtualAddress, &mut [u8]) -> TranslationResult<()>,
) -> TranslationResult<()> {
    let mut next_page = VirtualAddress((addr.0 & !0xfff) + 0x1000);

    loop {
        let diff = (next_page - addr) as usize;

        if diff >= buf.len() {
            return read_memory(addr, buf);
        }

        let (start, end) = buf.split_at_mut(diff);
        read_memory(addr, start)?;

        buf = end;
        addr = next_page;
        next_page += 0x1000;
    }
}
