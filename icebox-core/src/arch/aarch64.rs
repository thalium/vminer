use bytemuck::{Pod, Zeroable};

use super::runtime;
use crate::{LittleEndian, PhysicalAddress, VirtualAddress};

#[derive(Debug, Clone, Copy)]
pub struct Aarch64;

#[derive(Debug, Clone)]
pub struct Vcpu {
    pub registers: Registers,
    pub special_registers: SpecialRegisters,
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
    fn instruction_pointer(&self) -> VirtualAddress {
        VirtualAddress(self.registers.pc)
    }

    #[inline]
    fn stack_pointer(&self) -> VirtualAddress {
        VirtualAddress(self.registers.sp)
    }

    #[inline]
    fn kernel_per_cpu(&self) -> Option<VirtualAddress> {
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
    fn find_kernel_pgd<M: crate::Memory + ?Sized>(&self, _memory: &M) -> Option<PhysicalAddress> {
        for vcpu in *self {
            if VirtualAddress(vcpu.registers.pc).is_kernel() {
                let addr = PhysicalAddress(vcpu.special_registers.ttbr1_el1 & crate::mask(48));
                return Some(addr);
            }
        }

        None
    }

    #[inline]
    fn into_runtime(self) -> runtime::Vcpus<'a> {
        runtime::Vcpus::Aarch64(self)
    }
}

struct MmuDesc;

impl super::MmuDesc for MmuDesc {
    const MEM_OFFSET: u64 = 1 << 30;

    #[inline]
    fn is_valid(mmu_entry: crate::addr::MmuEntry) -> bool {
        mmu_entry.0 & 1 != 0
    }

    #[inline]
    fn is_large(mmu_entry: crate::addr::MmuEntry) -> bool {
        mmu_entry.0 & 0b10 == 0
    }
}

impl<'a> super::Architecture<'a> for Aarch64 {
    type Registers = Registers;
    type Vcpu = &'a Vcpu;
    type Vcpus = &'a [Vcpu];
    type Endian = LittleEndian;

    #[inline]
    fn into_runtime(self) -> runtime::Architecture {
        runtime::Architecture::Aarch64(self)
    }

    #[inline]
    fn endianness(&self) -> LittleEndian {
        LittleEndian
    }

    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        _memory: &M,
        _mmu_addr: PhysicalAddress,
        _addr: VirtualAddress,
    ) -> crate::MemoryAccessResult<Option<PhysicalAddress>> {
        todo!()
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Registers {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// A curated list of additionnal useful registers
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct SpecialRegisters {
    pub sp_el1: u64,
    pub ttbr0_el1: u64,
    pub ttbr1_el1: u64,
}
