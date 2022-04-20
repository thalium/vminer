#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "custom_allocator")]
mod allocator;
mod arch;
mod cstring;
mod error;
mod os;

use crate::error::Error;
use alloc::{boxed::Box, sync::Arc};
use core::mem;
use ibc::IceError;

#[allow(non_camel_case_types)]
pub type c_char = u8;
#[allow(non_camel_case_types)]
pub type c_void = u8;

pub struct Backend(Arc<dyn ibc::RuntimeBackend + Send + Sync>);

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

impl Backend {
    fn new<B>(backend: B) -> Box<Self>
    where
        B: ibc::Backend + Send + Sync + 'static,
        B::Memory: Sized,
    {
        Box::new(Self(Arc::new(backend)))
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
    memory_size: unsafe extern "C" fn(data: *const c_void) -> u64,
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
    fn size(&self) -> u64 {
        unsafe { (self.memory_size)(self.data) }
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

impl ibc::Backend for X86_64Backend {
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
    Box::new(Backend(Arc::new(backend)))
}

// #[no_mangle]
// pub extern "C" fn backend_virtual_to_physical(backend: &Backend, mmu_addr: GuestPhysAddr, addr: GuestVirtAddr) -> GuestPhysAddr {
//     backend.0.virtual_to_physical(mmu_addr, addr).valid().unwrap()
// }

#[no_mangle]
#[cfg(target_os = "linux")]
pub extern "C" fn kvm_connect(pid: i32, kvm: &mut mem::MaybeUninit<Box<Backend>>) -> *mut Error {
    let kvm_result = match icebox::backends::kvm::Kvm::connect(pid) {
        Ok(kvm) => Ok(Backend::new(kvm)),
        Err(err) => Err(IceError::new(err)),
    };
    error::wrap_result(kvm_result, kvm)
}

#[no_mangle]
pub unsafe extern "C" fn read_dump(
    path: *const c_char,
    dump: &mut mem::MaybeUninit<Box<Backend>>,
) -> *mut Error {
    let path = cstring::from_ut8_lossy(path);
    let kvm_result = match icebox::backends::kvm_dump::DumbDump::read(&*path) {
        Ok(kvm) => Ok(Backend::new(kvm)),
        Err(err) => Err(IceError::from(err)),
    };
    error::wrap_result(kvm_result, dump)
}

#[no_mangle]
pub extern "C" fn backend_free(backend: Option<Box<Backend>>) {
    drop(backend);
}
