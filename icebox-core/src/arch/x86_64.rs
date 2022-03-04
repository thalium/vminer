use bytemuck::{Pod, Zeroable};

use super::runtime;
use crate::{LittleEndian, PhysicalAddress, VirtualAddress};

#[derive(Debug, Clone, Copy)]
pub struct X86_64;

#[derive(Debug, Clone)]
pub struct Vcpu {
    pub registers: Registers,
    pub special_registers: SpecialRegisters,
    pub lstar: u64,
    pub gs_kernel_base: u64,
}

impl<'a> super::Vcpu<'a> for &'a Vcpu {
    type Arch = X86_64;

    #[inline]
    fn arch(&self) -> X86_64 {
        X86_64
    }

    #[inline]
    fn get_regs(&self) -> Registers {
        self.registers
    }

    #[inline]
    fn into_runtime(self) -> runtime::Vcpu<'a> {
        runtime::Vcpu::X86_64(self)
    }

    #[inline]
    fn instruction_pointer(&self) -> VirtualAddress {
        VirtualAddress(self.registers.rip)
    }

    #[inline]
    fn stack_pointer(&self) -> VirtualAddress {
        VirtualAddress(self.registers.rsp)
    }

    fn base_pointer(&self) -> Option<VirtualAddress> {
        Some(VirtualAddress(self.registers.rbp))
    }

    fn pgd(&self) -> PhysicalAddress {
        PhysicalAddress(self.special_registers.cr3 & crate::mask_range(12, 48))
    }

    #[inline]
    fn kernel_per_cpu(&self) -> Option<VirtualAddress> {
        let per_cpu = VirtualAddress(self.special_registers.gs.base);
        if per_cpu.is_kernel() {
            return Some(per_cpu);
        }

        let per_cpu = VirtualAddress(self.gs_kernel_base);
        if per_cpu.is_kernel() {
            return Some(per_cpu);
        }

        None
    }
}

impl<'a> super::Vcpus<'a> for &'a [Vcpu] {
    type Arch = X86_64;

    #[inline]
    fn arch(&self) -> X86_64 {
        X86_64
    }

    #[inline]
    fn count(&self) -> usize {
        self.len()
    }

    #[inline]
    fn get(&self, id: usize) -> &'a Vcpu {
        &self[id]
    }

    fn find_kernel_pgd<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        use_per_cpu: bool,
        additionnal: &[VirtualAddress],
    ) -> Option<PhysicalAddress> {
        // To check if a CR3 is valid, try to translate addresses with it
        let addresses = &[additionnal, &[VirtualAddress(self[0].lstar)]];
        let test = super::make_address_test(self, memory, use_per_cpu, addresses);

        // First, try cr3 registers
        for vcpu in *self {
            let addr = PhysicalAddress(vcpu.special_registers.cr3);
            if test(addr) {
                return Some(addr);
            }
        }

        // If it didn't work, try all addresses !
        super::try_all_addresses(test)
    }

    #[inline]
    fn into_runtime(self) -> runtime::Vcpus<'a> {
        runtime::Vcpus::X86_64(self)
    }
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

impl<'a> super::Architecture<'a> for X86_64 {
    type Registers = Registers;
    type Vcpu = &'a Vcpu;
    type Vcpus = &'a [Vcpu];
    type Endian = LittleEndian;

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
    ) -> crate::MemoryAccessResult<Option<PhysicalAddress>> {
        super::virtual_to_physical::<MmuDesc, M>(memory, mmu_addr, addr)
    }

    fn find_in_kernel_memory<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> crate::MemoryAccessResult<Option<VirtualAddress>> {
        let base_search_addr = VirtualAddress(0xffff_f800_0000_0000);
        super::find_in_kernel_memory::<MmuDesc, M>(memory, mmu_addr, needle, base_search_addr)
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
