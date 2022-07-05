#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;

#[cfg(feature = "custom_allocator")]
mod allocator;
mod arch;
mod array;
mod cstring;
mod error;
mod logging;
mod os;
mod symbols;

use crate::error::Error;
use alloc::{boxed::Box, sync::Arc};
#[cfg(feature = "std")]
use core::mem;

#[allow(non_camel_case_types)]
pub type c_char = u8;
#[allow(non_camel_case_types)]
pub type c_void = u8;

pub struct Backend(Arc<dyn ibc::Backend<Arch = ibc::arch::RuntimeArchitecture> + Send + Sync>);

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

#[repr(C)]
pub struct MemoryMap {
    start: PhysicalAddress,
    end: PhysicalAddress,
}

#[repr(C)]
pub struct MemoryMapping {
    maps: *const MemoryMap,
    len: usize,
}

impl Backend {
    fn new<B>(backend: B) -> Box<Self>
    where
        B: ibc::Backend + Send + Sync + 'static,
    {
        Box::new(Self(Arc::new(ibc::RuntimeBackend(backend))))
    }
}

#[repr(C)]
pub struct X86_64Backend {
    data: *mut c_void,
    read_memory: unsafe extern "C" fn(
        data: *const c_void,
        addr: PhysicalAddress,
        buf: *mut c_void,
        size: usize,
    ) -> i32,
    memory_mapping: unsafe extern "C" fn(data: *const c_void) -> MemoryMapping,
    get_vcpus: unsafe extern "C" fn(data: *const c_void) -> arch::X86_64Vcpus,
    drop: Option<unsafe extern "C" fn(data: *mut c_void)>,
}

unsafe impl Send for X86_64Backend {}
unsafe impl Sync for X86_64Backend {}

impl Drop for X86_64Backend {
    fn drop(&mut self) {
        unsafe {
            if let Some(drop) = self.drop {
                drop(self.data);
            }
        }
    }
}

impl ibc::Memory for X86_64Backend {
    fn mappings(&self) -> &[ibc::mem::MemoryMap] {
        unsafe {
            let MemoryMapping { maps, len } = (self.memory_mapping)(self.data);
            core::slice::from_raw_parts(maps.cast(), len)
        }
    }

    fn read(&self, addr: ibc::PhysicalAddress, buf: &mut [u8]) -> ibc::MemoryAccessResult<()> {
        unsafe {
            let size = buf.len();
            let res = (self.read_memory)(self.data, addr.into(), buf.as_mut_ptr(), size);
            match res {
                0 => Ok(()),
                #[cfg(feature = "std")]
                _ if res > 0 => Err(ibc::MemoryAccessError::Io(
                    std::io::Error::from_raw_os_error(res),
                )),
                _ => Err(ibc::MemoryAccessError::OutOfBounds),
            }
        }
    }
}

impl ibc::RawBackend for X86_64Backend {
    type Arch = ibc::arch::X86_64;
    type Memory = Self;

    fn vcpus(&self) -> <Self::Arch as ibc::Architecture>::Vcpus {
        let vcpus = unsafe { (self.get_vcpus)(self.data).as_vcpus() };
        bytemuck::cast_slice(vcpus)
    }

    fn memory(&self) -> &Self::Memory {
        self
    }
}

#[no_mangle]
pub unsafe extern "C" fn backend_make(backend: X86_64Backend) -> Box<Backend> {
    Backend::new(backend)
}

#[cfg(all(target_os = "linux", feature = "std"))]
#[no_mangle]
pub extern "C" fn kvm_connect(
    pid: i32,
    kvm: Option<&mut mem::MaybeUninit<Box<Backend>>>,
) -> *mut Error {
    error::wrap(kvm, || {
        let kvm = icebox::backends::kvm::Kvm::connect(pid)?;
        Ok(Backend::new(kvm))
    })
}

#[cfg(feature = "std")]
#[no_mangle]
pub unsafe extern "C" fn read_dump(
    path: *const c_char,
    dump: Option<&mut mem::MaybeUninit<Box<Backend>>>,
) -> *mut Error {
    error::wrap(dump, || {
        let path = cstring::from_ut8(path)?;
        let dump = icebox::backends::kvm_dump::DumbDump::read(&*path)?;
        Ok(Backend::new(dump))
    })
}

#[no_mangle]
pub extern "C" fn backend_free(backend: Option<Box<Backend>>) {
    drop(backend);
}
