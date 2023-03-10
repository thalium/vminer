#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

#[cfg(feature = "custom_allocator")]
mod allocator;
mod arch;
mod array;
mod backend;
mod cstring;
mod error;
mod logging;
mod os;
mod symbols;

#[repr(C)]
pub struct PhysicalAddress {
    val: u64,
}

#[repr(C)]
pub struct VirtualAddress {
    val: u64,
}

impl From<ibc::PhysicalAddress> for PhysicalAddress {
    fn from(addr: ibc::PhysicalAddress) -> Self {
        Self { val: addr.0 }
    }
}

impl From<PhysicalAddress> for ibc::PhysicalAddress {
    fn from(addr: PhysicalAddress) -> Self {
        Self(addr.val)
    }
}

impl From<ibc::VirtualAddress> for VirtualAddress {
    fn from(addr: ibc::VirtualAddress) -> Self {
        Self { val: addr.0 }
    }
}

impl From<VirtualAddress> for ibc::VirtualAddress {
    fn from(addr: VirtualAddress) -> Self {
        Self(addr.val)
    }
}
