use crate::{arch, c_char, c_void, cstring, error, error::Error};
use alloc::{boxed::Box, sync::Arc};
#[cfg(feature = "std")]
use core::mem;

#[repr(C)]
pub struct MemoryMap {
    start: ibc::PhysicalAddress,
    end: ibc::PhysicalAddress,
}

#[repr(C)]
pub struct MemoryMapping {
    maps: *const MemoryMap,
    len: usize,
}

pub struct Backend(pub Arc<dyn ibc::Backend<Arch = ibc::arch::RuntimeArchitecture> + Send + Sync>);

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
    read_memory: Option<
        unsafe extern "C" fn(
            data: *const c_void,
            addr: ibc::PhysicalAddress,
            buf: *mut c_void,
            size: usize,
        ) -> i32,
    >,
    memory_mappings: Option<unsafe extern "C" fn(data: *const c_void) -> MemoryMapping>,
    vcpus_count: usize,
    registers:
        Option<unsafe extern "C" fn(data: *const c_void, vcpu: usize) -> arch::X86_64Registers>,
    special_registers: Option<
        unsafe extern "C" fn(data: *const c_void, vcpu: usize) -> arch::X86_64SpecialRegisters,
    >,
    other_registers: Option<
        unsafe extern "C" fn(data: *const c_void, vcpu: usize) -> arch::X86_64OtherRegisters,
    >,
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
    fn memory_mappings(&self) -> &[ibc::mem::MemoryMap] {
        match self.memory_mappings {
            Some(mappings) => unsafe {
                let MemoryMapping { maps, len } = mappings(self.data);
                core::slice::from_raw_parts(maps.cast(), len)
            },
            None => &[],
        }
    }

    fn read_physical(
        &self,
        addr: ibc::PhysicalAddress,
        buf: &mut [u8],
    ) -> ibc::MemoryAccessResult<()> {
        match self.read_memory {
            Some(read_memory) => unsafe {
                let size = buf.len();
                match read_memory(self.data, addr, buf.as_mut_ptr(), size) {
                    0 => Ok(()),
                    #[cfg(feature = "std")]
                    res if res > 0 => Err(ibc::MemoryAccessError::Io(
                        std::io::Error::from_raw_os_error(res),
                    )),
                    _ => Err(ibc::MemoryAccessError::OutOfBounds),
                }
            },
            None => Err(ibc::MemoryAccessError::Unsupported),
        }
    }
}

impl ibc::HasVcpus for X86_64Backend {
    type Arch = ibc::arch::X86_64;

    fn arch(&self) -> Self::Arch {
        ibc::arch::X86_64
    }

    fn vcpus_count(&self) -> usize {
        self.vcpus_count
    }

    fn registers(&self, vcpu: ibc::VcpuId) -> ibc::VcpuResult<ibc::arch::x86_64::Registers> {
        if vcpu.0 >= self.vcpus_count {
            return Err(ibc::VcpuError::InvalidId);
        }

        match self.registers {
            Some(registers) => Ok(bytemuck::cast(unsafe { registers(self.data, vcpu.0) })),
            None => Err(ibc::VcpuError::Unsupported),
        }
    }

    fn special_registers(
        &self,
        vcpu: ibc::VcpuId,
    ) -> ibc::VcpuResult<ibc::arch::x86_64::SpecialRegisters> {
        if vcpu.0 >= self.vcpus_count {
            return Err(ibc::VcpuError::InvalidId);
        }

        match self.special_registers {
            Some(registers) => Ok(bytemuck::cast(unsafe { registers(self.data, vcpu.0) })),
            None => Err(ibc::VcpuError::Unsupported),
        }
    }

    fn other_registers(
        &self,
        vcpu: ibc::VcpuId,
    ) -> ibc::VcpuResult<ibc::arch::x86_64::OtherRegisters> {
        if vcpu.0 >= self.vcpus_count {
            return Err(ibc::VcpuError::InvalidId);
        }

        match self.other_registers {
            Some(registers) => Ok(bytemuck::cast(unsafe { registers(self.data, vcpu.0) })),
            None => Err(ibc::VcpuError::Unsupported),
        }
    }
}

impl ibc::Backend for X86_64Backend {}

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
        let dump = icebox::backends::kvm_dump::DumbDump::read(path)?;
        Ok(Backend::new(dump))
    })
}

#[no_mangle]
pub extern "C" fn backend_free(backend: Option<Box<Backend>>) {
    drop(backend);
}
