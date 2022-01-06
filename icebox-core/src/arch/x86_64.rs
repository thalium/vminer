use crate::{PhysicalAddress, VirtualAddress};

use super::runtime;

use bytemuck::{Pod, Zeroable};

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
    fn kernel_per_cpu(&self, check: impl Fn(VirtualAddress) -> bool) -> Option<VirtualAddress> {
        let per_cpu = VirtualAddress(self.special_registers.gs.base);
        if check(per_cpu) {
            return Some(per_cpu);
        }

        let per_cpu = VirtualAddress(self.gs_kernel_base);
        if check(per_cpu) {
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

    #[inline]
    fn find_kernel_pgd(&self, test: impl Fn(PhysicalAddress) -> bool) -> Option<PhysicalAddress> {
        // First, try to find one in a cr3 register
        for vcpu in *self {
            let addr = PhysicalAddress(vcpu.special_registers.cr3);
            if test(addr) {
                return Some(addr);
            }
        }

        // If it didn't work, try them all !
        super::try_all_addresses(test)
    }

    #[inline]
    fn into_runtime(self) -> runtime::Vcpus<'a> {
        runtime::Vcpus::X86_64(self)
    }
}

impl<'a> super::Architecture<'a> for X86_64 {
    type Registers = Registers;
    type Vcpu = &'a Vcpu;
    type Vcpus = &'a [Vcpu];

    #[inline]
    fn into_runtime(self) -> runtime::Architecture {
        runtime::Architecture::X86_64(self)
    }

    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> crate::MemoryAccessResult<Option<PhysicalAddress>> {
        let mut mmu_entry = crate::MmPte(0);

        let pml4e_addr = PhysicalAddress(mmu_addr.0 & (crate::mask(40) << 12)) + 8 * addr.pml4e();
        memory.read(pml4e_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
        if !mmu_entry.is_valid() {
            return Ok(None);
        }

        let pdpe_addr = mmu_entry.page_frame() + 8 * addr.pdpe();
        memory.read(pdpe_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
        if !mmu_entry.is_valid() {
            return Ok(None);
        }

        if mmu_entry.is_large() {
            let phys_addr = mmu_entry.huge_page_frame() + addr.huge_page_offset();
            return Ok(Some(phys_addr));
        }

        let pde_addr = mmu_entry.page_frame() + 8 * addr.pde();
        memory.read(pde_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
        if !mmu_entry.is_valid() {
            return Ok(None);
        }

        if mmu_entry.is_large() {
            let phys_addr = mmu_entry.large_page_frame() + addr.large_page_offset();
            return Ok(Some(phys_addr));
        }

        let pte_addr = mmu_entry.page_frame() + 8 * addr.pte();
        memory.read(pte_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
        if !mmu_entry.is_valid() {
            return Ok(None);
        }

        let phys_addr = mmu_entry.page_frame() + addr.page_offset();
        Ok(Some(phys_addr))
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
