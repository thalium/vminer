use bytemuck::{Pod, Zeroable};
use std::{io, mem};

macro_rules! check {
    ($e:expr) => {
        match $e {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    };
}

pub const KVM_GET_REGS: u64 = 2156965505;
pub const KVM_GET_SREGS: u64 = 2167975555;
pub const KVM_GET_MSRS: u64 = 3221794440;

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct kvm_regs {
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
pub struct kvm_segment {
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
pub struct kvm_dtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct kvm_sregs {
    pub cs: kvm_segment,
    pub ds: kvm_segment,
    pub es: kvm_segment,
    pub fs: kvm_segment,
    pub gs: kvm_segment,
    pub ss: kvm_segment,
    pub tr: kvm_segment,
    pub ldt: kvm_segment,
    pub gdt: kvm_dtable,
    pub idt: kvm_dtable,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
    pub interrupt_bitmap: [u64; 4],
}

#[inline]
pub fn get_regs(vcpu_fd: i32) -> io::Result<kvm_regs> {
    unsafe {
        let mut regs = mem::MaybeUninit::uninit();
        check!(libc::ioctl(vcpu_fd, KVM_GET_REGS, regs.as_mut_ptr()))?;
        Ok(regs.assume_init())
    }
}

#[inline]
pub fn get_sregs(vcpu_fd: i32) -> io::Result<kvm_sregs> {
    unsafe {
        let mut sregs = mem::MaybeUninit::uninit();
        check!(libc::ioctl(vcpu_fd, KVM_GET_SREGS, sregs.as_mut_ptr()))?;
        Ok(sregs.assume_init())
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
struct kvm_msrs {
    nmsrs: u32,
    pad: u32,

    entries: [kvm_msr_entry; 1],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
struct kvm_msr_entry {
    index: u32,
    reserved: u32,
    data: u64,
}

pub fn get_kernel_gs_base(vcpu_fd: i32) -> io::Result<u64> {
    let mut msrs = kvm_msrs::zeroed();
    msrs.nmsrs = 1;
    msrs.entries[0].index = 0xC0000102;

    unsafe {
        check!(libc::ioctl(vcpu_fd, KVM_GET_MSRS, &mut msrs))?;
    }

    Ok(msrs.entries[0].data)
}
