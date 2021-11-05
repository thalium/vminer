use super::{Architecture, RuntimeArchitecture};

use bytemuck::{Pod, Zeroable};

#[derive(Debug, Clone, Copy)]
pub struct Aarch64;

impl Architecture for Aarch64 {
    type Registers = Registers;
    type Vcpu = Vcpu;

    #[inline]
    fn runtime_arch(&self) -> RuntimeArchitecture {
        RuntimeArchitecture::Aarch64(*self)
    }

    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        _memory: &M,
        _mmu_addr: crate::GuestPhysAddr,
        _addr: crate::GuestVirtAddr,
    ) -> crate::MemoryAccessResult<Option<crate::GuestPhysAddr>> {
        todo!()
    }
}

pub struct Vcpu {
    pub registers: Registers,
}

impl super::Vcpu for Vcpu {
    type Arch = Aarch64;

    #[inline]
    fn get_regs(&self) -> Registers {
        self.registers
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Registers {}
