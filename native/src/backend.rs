use crate::{arch, cstring, error};
use alloc::{boxed::Box, sync::Arc};
use core::ffi::{c_char, c_void};

#[repr(C)]
pub struct MemoryMap {
    start: vmc::PhysicalAddress,
    end: vmc::PhysicalAddress,
}

#[repr(C)]
pub struct MemoryMapping {
    maps: *const MemoryMap,
    len: usize,
}

pub struct Backend(pub Arc<dyn vmc::Backend<Arch = vmc::arch::RuntimeArchitecture> + Send + Sync>);

impl Backend {
    fn new<B>(backend: B) -> Box<Self>
    where
        B: vmc::Backend + Send + Sync + 'static,
    {
        Box::new(Self(Arc::new(vmc::RuntimeBackend(backend))))
    }
}

#[repr(C)]
pub struct X86_64Backend {
    pub data: *mut c_void,

    pub memory_mappings: Option<unsafe extern "C" fn(data: *const c_void) -> MemoryMapping>,
    pub read_physical_memory: Option<
        unsafe extern "C" fn(
            data: *const c_void,
            addr: vmc::PhysicalAddress,
            buf: *mut c_void,
            size: usize,
        ) -> i32,
    >,
    pub read_virtual_memory: Option<
        unsafe extern "C" fn(
            data: *const c_void,
            mmu_addr: vmc::PhysicalAddress,
            addr: vmc::VirtualAddress,
            buf: *mut c_void,
            size: usize,
        ) -> i32,
    >,

    pub vcpus_count: usize,
    pub registers:
        Option<unsafe extern "C" fn(data: *const c_void, vcpu: usize) -> arch::X86_64Registers>,
    pub special_registers: Option<
        unsafe extern "C" fn(data: *const c_void, vcpu: usize) -> arch::X86_64SpecialRegisters,
    >,
    pub other_registers: Option<
        unsafe extern "C" fn(data: *const c_void, vcpu: usize) -> arch::X86_64OtherRegisters,
    >,

    pub drop: Option<unsafe extern "C" fn(data: *mut c_void)>,
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

impl vmc::Memory for X86_64Backend {
    fn memory_mappings(&self) -> &[vmc::mem::MemoryMap] {
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
        addr: vmc::PhysicalAddress,
        buf: &mut [u8],
    ) -> vmc::MemoryAccessResult<()> {
        match self.read_physical_memory {
            Some(read_physical) => unsafe {
                let size = buf.len();
                match read_physical(self.data, addr, buf.as_mut_ptr().cast(), size) {
                    0 => Ok(()),
                    #[cfg(feature = "std")]
                    res if res > 0 => Err(vmc::MemoryAccessError::Io(
                        std::io::Error::from_raw_os_error(res),
                    )),
                    _ => Err(vmc::MemoryAccessError::OutOfBounds),
                }
            },
            None => Err(vmc::MemoryAccessError::Unsupported),
        }
    }
}

impl vmc::HasVcpus for X86_64Backend {
    type Arch = vmc::arch::X86_64;

    fn arch(&self) -> Self::Arch {
        vmc::arch::X86_64
    }

    fn vcpus_count(&self) -> usize {
        self.vcpus_count
    }

    fn registers(&self, vcpu: vmc::VcpuId) -> vmc::VcpuResult<vmc::arch::x86_64::Registers> {
        if vcpu.0 >= self.vcpus_count {
            return Err(vmc::VcpuError::InvalidId);
        }

        match self.registers {
            Some(registers) => Ok(bytemuck::cast(unsafe { registers(self.data, vcpu.0) })),
            None => Err(vmc::VcpuError::Unsupported),
        }
    }

    fn special_registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<vmc::arch::x86_64::SpecialRegisters> {
        if vcpu.0 >= self.vcpus_count {
            return Err(vmc::VcpuError::InvalidId);
        }

        match self.special_registers {
            Some(registers) => Ok(bytemuck::cast(unsafe { registers(self.data, vcpu.0) })),
            None => Err(vmc::VcpuError::Unsupported),
        }
    }

    fn other_registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<vmc::arch::x86_64::OtherRegisters> {
        if vcpu.0 >= self.vcpus_count {
            return Err(vmc::VcpuError::InvalidId);
        }

        match self.other_registers {
            Some(registers) => Ok(bytemuck::cast(unsafe { registers(self.data, vcpu.0) })),
            None => Err(vmc::VcpuError::Unsupported),
        }
    }
}

impl vmc::Backend for X86_64Backend {
    fn read_virtual_memory(
        &self,
        mmu_addr: vmc::PhysicalAddress,
        addr: vmc::VirtualAddress,
        buf: &mut [u8],
    ) -> vmc::TranslationResult<()> {
        match self.read_virtual_memory {
            Some(read_virtual) => unsafe {
                let size = buf.len();
                match read_virtual(self.data, mmu_addr, addr, buf.as_mut_ptr().cast(), size) {
                    0 => Ok(()),
                    #[cfg(feature = "std")]
                    res if res > 0 => Err(vmc::TranslationError::Memory(
                        vmc::MemoryAccessError::Io(std::io::Error::from_raw_os_error(res)),
                    )),
                    _ => Err(vmc::TranslationError::Memory(
                        vmc::MemoryAccessError::OutOfBounds,
                    )),
                }
            },
            None => vmc::backend::default_read_virtual_memory(self, mmu_addr, addr, buf),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn backend_make(backend: X86_64Backend) -> Box<Backend> {
    Backend::new(backend)
}

#[cfg(all(target_os = "linux", feature = "std"))]
#[no_mangle]
pub extern "C" fn kvm_connect(pid: i32) -> Option<Box<Backend>> {
    error::wrap_box(|| {
        let kvm = vminer::backends::kvm::Kvm::connect(pid)?;
        Ok(Backend::new(kvm))
    })
}

#[cfg(feature = "std")]
#[no_mangle]
pub unsafe extern "C" fn read_dump(path: *const c_char) -> Option<Box<Backend>> {
    error::wrap_box(|| {
        let path = cstring::from_ut8(path)?;
        let dump = vminer::backends::kvm_dump::DumbDump::read(path)?;
        Ok(Backend::new(dump))
    })
}

#[no_mangle]
pub extern "C" fn backend_free(backend: Option<Box<Backend>>) {
    drop(backend);
}
