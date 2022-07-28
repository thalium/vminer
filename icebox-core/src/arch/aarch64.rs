use bytemuck::{Pod, Zeroable};

use super::runtime;
use crate::{LittleEndian, PhysicalAddress, VcpuResult, VirtualAddress};

#[derive(Debug, Clone, Copy)]
pub struct Aarch64;

#[derive(Debug, Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
pub struct Vcpu {
    pub registers: Registers,
    pub special_registers: SpecialRegisters,
    pub other_registers: OtherRegisters,
}

struct MmuDesc;

impl super::MmuDesc for MmuDesc {
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
    type Endian = LittleEndian;

    type Registers = Registers;
    type SpecialRegisters = SpecialRegisters;
    type OtherRegisters = OtherRegisters;

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
    ) -> crate::TranslationResult<PhysicalAddress> {
        super::virtual_to_physical::<MmuDesc, M>(memory, mmu_addr, addr)
    }

    fn find_kernel_pgd<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        vcpus: &(impl super::HasVcpus<Arch = Self> + ?Sized),
        use_per_cpu: bool,
        additionnal: &[VirtualAddress],
    ) -> crate::IceResult<Option<PhysicalAddress>> {
        for vcpu in vcpus.iter_vcpus() {
            if vcpus.instruction_pointer(vcpu)?.is_kernel() {
                return Ok(Some(vcpus.pgd(vcpu)?));
            }
        }

        // To check if a TTBR is valid, try to translate valid kernel addresses with it
        let addresses = &[additionnal];
        let test = super::make_address_test(vcpus, memory, use_per_cpu, addresses);

        // // Try pages near a "wrong" TTBR1
        // if let Some(vcpu) = vcpus
        //     .iter_vcpus()
        //     .find(|vcpu| vcpus.instruction_pointer( vcpu).is_kernel())
        // {
        //     for i in -5..6 {
        //         let ttbr1 = vcpu.cleaned_ttbr1() + i * 4096i64;
        //         if test(ttbr1) {
        //             return Some(ttbr1);
        //         }
        //     }
        // }

        Ok(super::try_all_addresses(test))
    }

    fn find_in_kernel_memory_raw<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        base_search_addr: VirtualAddress,
        finder: &memchr::memmem::Finder,
        buf: &mut [u8],
    ) -> crate::MemoryAccessResult<Option<VirtualAddress>> {
        super::find_in_kernel_memory_raw::<MmuDesc, M>(
            memory,
            mmu_addr,
            base_search_addr,
            finder,
            buf,
        )
    }

    fn find_in_kernel_memory<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> crate::MemoryAccessResult<Option<VirtualAddress>> {
        super::find_in_kernel_memory::<MmuDesc, M>(memory, mmu_addr, needle, self.kernel_base())
    }

    #[inline]
    fn kernel_base(&self) -> VirtualAddress {
        VirtualAddress(0xffff_a000_0000_0000)
    }

    fn instruction_pointer<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> VcpuResult<VirtualAddress> {
        let registers = vcpus.registers(vcpu)?;
        Ok(VirtualAddress(registers.pc))
    }

    fn stack_pointer<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> VcpuResult<VirtualAddress> {
        let sp = if self.instruction_pointer(vcpus, vcpu)?.is_kernel() {
            vcpus.special_registers(vcpu)?.sp_el1
        } else {
            vcpus.registers(vcpu)?.sp
        };
        Ok(VirtualAddress(sp))
    }

    fn base_pointer<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        _vcpus: &Vcpus,
        _vcpu: crate::VcpuId,
    ) -> VcpuResult<Option<VirtualAddress>> {
        Ok(None)
    }

    fn pgd<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> VcpuResult<PhysicalAddress> {
        use super::MmuDesc as _;

        let s_registers = vcpus.special_registers(vcpu)?;

        let ttbr = if self.instruction_pointer(vcpus, vcpu)?.is_kernel() {
            s_registers.ttbr1_el1
        } else {
            s_registers.ttbr0_el1
        };
        Ok(PhysicalAddress(ttbr & crate::mask(MmuDesc::ADDR_BITS)))
    }

    fn kernel_per_cpu<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        _vcpus: &Vcpus,
        _vcpu: crate::VcpuId,
    ) -> VcpuResult<Option<VirtualAddress>> {
        Ok(None)
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

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct OtherRegisters;

impl From<Registers> for super::runtime::Registers {
    #[inline]
    fn from(regs: Registers) -> Self {
        Self::Aarch64(regs)
    }
}

impl From<SpecialRegisters> for super::runtime::SpecialRegisters {
    #[inline]
    fn from(regs: SpecialRegisters) -> Self {
        Self::Aarch64(regs)
    }
}

impl From<OtherRegisters> for super::runtime::OtherRegisters {
    #[inline]
    fn from(regs: OtherRegisters) -> Self {
        Self::Aarch64(regs)
    }
}
