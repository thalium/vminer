use bytemuck::{Pod, Zeroable};

use super::runtime;
use crate::{LittleEndian, PhysicalAddress, VirtualAddress};

#[derive(Debug, Clone, Copy)]
pub struct X86_64;

#[derive(Debug, Clone)]
pub struct Vcpu {
    pub registers: Registers,
    pub special_registers: SpecialRegisters,
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

    fn find_kernel_pgd<M: crate::Memory + ?Sized>(&self, memory: &M) -> Option<PhysicalAddress> {
        use super::{Architecture, Vcpu};

        // Collect some valid kernel addresses
        let test_addrs: alloc::vec::Vec<_> = self
            .iter()
            .filter_map(|vcpu| vcpu.kernel_per_cpu())
            .collect();
        let mem_size = memory.size();

        if test_addrs.is_empty() {
            return None;
        }

        // To check if a CR3 is valid, try to translate addresses with it
        let test = |addr| {
            test_addrs.iter().all(|test_addr| {
                match X86_64.virtual_to_physical(memory, addr, *test_addr) {
                    Ok(Some(addr)) => addr.0 < mem_size,
                    _ => false,
                }
            })
        };

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
        super::find_in_kernel_memory::<MmuDesc, M>(memory, mmu_addr, needle)
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
