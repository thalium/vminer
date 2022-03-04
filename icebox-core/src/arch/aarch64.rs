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

impl Vcpu {
    fn cleaned_ttbr0(&self) -> PhysicalAddress {
        use super::MmuDesc as _;
        PhysicalAddress(self.special_registers.ttbr0_el1 & crate::mask(MmuDesc::ADDR_BITS))
            - MmuDesc::MEM_OFFSET
    }

    fn cleaned_ttbr1(&self) -> PhysicalAddress {
        use super::MmuDesc as _;
        PhysicalAddress(self.special_registers.ttbr1_el1 & crate::mask(MmuDesc::ADDR_BITS))
            - MmuDesc::MEM_OFFSET
    }
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
        if self.instruction_pointer().is_kernel() {
            VirtualAddress(self.special_registers.sp_el1)
        } else {
            VirtualAddress(self.registers.sp)
        }
    }

    fn base_pointer(&self) -> Option<VirtualAddress> {
        None
    }

    fn pgd(&self) -> PhysicalAddress {
        if self.instruction_pointer().is_kernel() {
            self.cleaned_ttbr1()
        } else {
            self.cleaned_ttbr0()
        }
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
    fn find_kernel_pgd<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        use_per_cpu: bool,
        additionnal: &[VirtualAddress],
    ) -> Option<PhysicalAddress> {
        use super::Vcpu;

        for vcpu in *self {
            if vcpu.instruction_pointer().is_kernel() {
                return Some(vcpu.cleaned_ttbr1());
            }
        }

        // To check if a TTBR is valid, try to translate valid kernel addresses with it
        let addresses = &[additionnal];
        let test = super::make_address_test(self, memory, use_per_cpu, addresses);

        // Try pages near a "wrong" TTBR1
        if let Some(vcpu) = self
            .iter()
            .find(|vcpu| vcpu.instruction_pointer().is_kernel())
        {
            for i in -5..6 {
                let ttbr1 = vcpu.cleaned_ttbr1() + i * 4096i64;
                if test(ttbr1) {
                    return Some(ttbr1);
                }
            }
        }

        super::try_all_addresses(test)
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
        memory: &M,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> crate::MemoryAccessResult<Option<PhysicalAddress>> {
        super::virtual_to_physical::<MmuDesc, M>(memory, mmu_addr, addr)
    }

    fn find_in_kernel_memory<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> crate::MemoryAccessResult<Option<VirtualAddress>> {
        super::find_in_kernel_memory::<MmuDesc, M>(memory, mmu_addr, needle)
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
    pub vbar_el1: u64,
}
