use crate::{GuestPhysAddr, GuestVirtAddr};

use super::runtime;

use bytemuck::{Pod, Zeroable};

#[derive(Debug, Clone, Copy)]
pub struct Aarch64;

#[derive(Debug, Clone)]
pub struct Vcpu {
    pub registers: Registers,
}

impl<'a> super::Vcpu<'a> for &'a Vcpu {
    type Arch = Aarch64;

    #[inline]
    fn arch(&self) -> Aarch64 {
        Aarch64
    }

    #[inline]
    fn get_regs(&self) -> Registers {
        self.registers
    }

    #[inline]
    fn into_runtime(self) -> runtime::Vcpu<'a> {
        runtime::Vcpu::Aarch64(self)
    }

    #[inline]
    fn kernel_per_cpu(&self, _check: impl Fn(GuestVirtAddr) -> bool) -> Option<GuestVirtAddr> {
        None
    }
}

impl<'a> super::Vcpus<'a> for &'a [Vcpu] {
    type Arch = Aarch64;

    #[inline]
    fn arch(&self) -> Aarch64 {
        Aarch64
    }

    #[inline]
    fn count(&self) -> usize {
        self.len()
    }

    #[inline]
    fn get(&self, id: usize) -> &'a Vcpu {
        &self[id]
    }

    #[inline]
    fn find_kernel_pgd(&self, test: impl Fn(GuestPhysAddr) -> bool) -> Option<GuestPhysAddr> {
        super::try_all_addresses(test)
    }

    #[inline]
    fn into_runtime(self) -> runtime::Vcpus<'a> {
        runtime::Vcpus::Aarch64(self)
    }
}

impl<'a> super::Architecture<'a> for Aarch64 {
    type Registers = Registers;
    type Vcpu = &'a Vcpu;
    type Vcpus = &'a [Vcpu];

    #[inline]
    fn into_runtime(self) -> runtime::Architecture {
        runtime::Architecture::Aarch64(self)
    }

    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        _memory: &M,
        _mmu_addr: GuestPhysAddr,
        _addr: GuestVirtAddr,
    ) -> crate::MemoryAccessResult<Option<GuestPhysAddr>> {
        todo!()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Registers {}
