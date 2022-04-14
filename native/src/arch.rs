use bytemuck::{Pod, Zeroable};
use core::mem;

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct X86_64Vcpu {
    pub registers: X86_64Registers,
    pub special_registers: X86_64SpecialRegisters,
    pub lstar: u64,
    pub gs_kernel_base: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct X86_64Vcpus {
    pointer: *const X86_64Vcpu,
    len: usize,
}

const _: () = {
    assert!(mem::size_of::<X86_64Vcpu>() == mem::size_of::<ibc::arch::x86_64::Vcpu>());
    assert!(mem::size_of::<X86_64Registers>() == mem::size_of::<ibc::arch::x86_64::Registers>());
    assert!(
        mem::size_of::<X86_64SpecialRegisters>()
            == mem::size_of::<ibc::arch::x86_64::SpecialRegisters>()
    );
};

impl X86_64Vcpus {
    pub unsafe fn as_vcpus<'a>(self) -> &'a [X86_64Vcpu] {
        core::slice::from_raw_parts(self.pointer, self.len)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct X86_64Registers {
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
pub struct X86_64Segment {
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
pub struct X86_64Dtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct X86_64SpecialRegisters {
    pub cs: X86_64Segment,
    pub ds: X86_64Segment,
    pub es: X86_64Segment,
    pub fs: X86_64Segment,
    pub gs: X86_64Segment,
    pub ss: X86_64Segment,
    pub tr: X86_64Segment,
    pub ldt: X86_64Segment,
    pub gdt: X86_64Dtable,
    pub idt: X86_64Dtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}
