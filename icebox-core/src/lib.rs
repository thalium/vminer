#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_debug_implementations)]

extern crate alloc;

mod addr;
pub use addr::{PhysicalAddress, VirtualAddress};

pub mod arch;
pub use arch::{Architecture, HasVcpus, VcpuId};

mod backend;
pub use backend::{Backend, RawBackend, RuntimeBackend};

mod endian;
pub use endian::{BigEndian, Endianness, LittleEndian, RuntimeEndian};

mod error;
pub use error::{
    Error, IceError, IceResult, MemoryAccessError, MemoryAccessResult, ResultExt, TranslationError,
    TranslationResult, TranslationResultExt, VcpuError, VcpuResult,
};

pub mod mem;
pub use mem::Memory;

mod os;
pub use os::{Module, Os, Process, StackFrame, Thread, Vma, VmaFlags};

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

#[inline]
pub fn read_virtual_memory<E>(
    mut addr: VirtualAddress,
    mut buf: &mut [u8],
    read_memory: impl Fn(VirtualAddress, &mut [u8]) -> Result<(), E>,
) -> Result<(), E> {
    let mut next_page = VirtualAddress(addr.0 & !0xfff);

    loop {
        next_page = VirtualAddress(next_page.0.wrapping_add(0x1000));
        let diff = (next_page - addr) as usize;

        if diff >= buf.len() {
            return read_memory(addr, buf);
        }

        let (start, end) = buf.split_at_mut(diff);
        read_memory(addr, start)?;

        buf = end;
        addr = next_page;
    }
}

#[inline]
pub fn try_read_virtual_memory(
    addr: VirtualAddress,
    buf: &mut [u8],
    read_memory: impl Fn(VirtualAddress, &mut [u8]) -> TranslationResult<()>,
) -> MemoryAccessResult<()> {
    read_virtual_memory(addr, buf, |addr, buf| match read_memory(addr, buf) {
        Ok(()) => Ok(()),
        Err(TranslationError::Invalid(mmu)) => {
            log::trace!("Encountered unmapped page: 0x{addr:x} ({mmu:#x})");
            Ok(())
        }
        Err(TranslationError::Memory(err)) => Err(err),
    })
}
