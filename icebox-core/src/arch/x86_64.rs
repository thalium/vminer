use super::runtime;
use crate::{endian::LittleEndian, PhysicalAddress, VirtualAddress};
use bytemuck::{Pod, Zeroable};

#[derive(Debug, Clone, Copy)]
pub struct X86_64;

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
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
        mmu_entry.0 & (1 << 7) != 0
    }
}

impl super::Architecture for X86_64 {
    type Endian = LittleEndian;

    type Registers = Registers;
    type SpecialRegisters = SpecialRegisters;
    type OtherRegisters = OtherRegisters;

    #[inline]
    fn into_runtime(self) -> runtime::Architecture {
        runtime::Architecture::X86_64(self)
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
        // To check if a CR3 is valid, try to translate addresses with it
        let lstar = VirtualAddress(vcpus.other_registers(crate::VcpuId(0))?.lstar);
        let addresses = &[additionnal, &[lstar]];
        let test = super::make_address_test(vcpus, memory, use_per_cpu, addresses);

        // First, try cr3 registers
        for vcpu in vcpus.iter_vcpus() {
            let addr = vcpus.pgd(vcpu)?;
            if test(addr) {
                return Ok(Some(addr));
            }
        }

        // If it didn't work, try all addresses !
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
        VirtualAddress(0xffff_f800_0000_0000)
    }

    fn instruction_pointer<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> crate::VcpuResult<VirtualAddress> {
        let regs = vcpus.registers(vcpu)?;
        Ok(VirtualAddress(regs.rip))
    }

    fn stack_pointer<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> crate::VcpuResult<VirtualAddress> {
        let regs = vcpus.registers(vcpu)?;
        Ok(VirtualAddress(regs.rsp))
    }

    fn base_pointer<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> crate::VcpuResult<Option<VirtualAddress>> {
        let regs = vcpus.registers(vcpu)?;
        Ok(Some(VirtualAddress(regs.rbp)))
    }

    fn pgd<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> crate::VcpuResult<PhysicalAddress> {
        let regs = vcpus.special_registers(vcpu)?;
        Ok(PhysicalAddress(regs.cr3))
    }

    fn kernel_per_cpu<Vcpus: super::HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> crate::VcpuResult<Option<VirtualAddress>> {
        let per_cpu = VirtualAddress(vcpus.special_registers(vcpu)?.gs.base);
        if per_cpu.is_kernel() {
            return Ok(Some(per_cpu));
        }

        let per_cpu = VirtualAddress(vcpus.other_registers(vcpu)?.gs_kernel_base);
        if per_cpu.is_kernel() {
            return Ok(Some(per_cpu));
        }

        Ok(None)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    pub avl: u8,
    pub unusable: u8,
    pub padding: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct Dtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct SpecialRegisters {
    pub cs: Segment,
    pub ds: Segment,
    pub es: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub ss: Segment,
    pub tr: Segment,
    pub ldt: Segment,
    pub gdt: Dtable,
    pub idt: Dtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct OtherRegisters {
    pub lstar: u64,
    pub gs_kernel_base: u64,
}

impl From<Registers> for super::runtime::Registers {
    #[inline]
    fn from(regs: Registers) -> Self {
        Self::X86_64(regs)
    }
}

impl From<SpecialRegisters> for super::runtime::SpecialRegisters {
    #[inline]
    fn from(regs: SpecialRegisters) -> Self {
        Self::X86_64(regs)
    }
}

impl From<OtherRegisters> for super::runtime::OtherRegisters {
    #[inline]
    fn from(regs: OtherRegisters) -> Self {
        Self::X86_64(regs)
    }
}
