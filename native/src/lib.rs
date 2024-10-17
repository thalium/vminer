#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;
extern crate vminer_core as vmc;

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

impl From<vmc::PhysicalAddress> for PhysicalAddress {
    fn from(addr: vmc::PhysicalAddress) -> Self {
        Self { val: addr.0 }
    }
}

impl From<PhysicalAddress> for vmc::PhysicalAddress {
    fn from(addr: PhysicalAddress) -> Self {
        Self(addr.val)
    }
}

impl From<vmc::VirtualAddress> for VirtualAddress {
    fn from(addr: vmc::VirtualAddress) -> Self {
        Self { val: addr.0 }
    }
}

impl From<VirtualAddress> for vmc::VirtualAddress {
    fn from(addr: VirtualAddress) -> Self {
        Self(addr.val)
    }
}
