use bytemuck::{Pod, Zeroable};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{fmt, io};

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
pub const KVM_TRANSLATE: u64 = 3222843013;

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct kvm_dtable {
    pub base: u64,
    pub limit: u16,
    pub padding: [u16; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
pub unsafe fn get_regs(vcpu_fd: i32) -> io::Result<kvm_regs> {
    let mut regs = kvm_regs::zeroed();
    check!(libc::ioctl(vcpu_fd, KVM_GET_REGS, &mut regs))?;
    Ok(regs)
}

#[inline]
pub unsafe fn get_sregs(vcpu_fd: i32) -> io::Result<kvm_sregs> {
    let mut sregs = kvm_sregs::zeroed();
    check!(libc::ioctl(vcpu_fd, KVM_GET_SREGS, &mut sregs))?;
    Ok(sregs)
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct kvm_translation {
    pub linear_address: u64,
    pub physical_address: u64,
    pub valid: u8,
    pub writeable: u8,
    pub usermode: u8,
    pub pad: [u8; 5],
}

impl fmt::Debug for kvm_translation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct Hex(u64);
        impl fmt::Debug for Hex {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_fmt(format_args!("0x{:016x}", self.0))
            }
        }

        f.debug_struct("kvm_translation")
            .field("linear_address", &Hex(self.linear_address))
            .field("physical_address", &Hex(self.physical_address))
            .field("valid", &self.valid)
            .field("writeable", &self.writeable)
            .field("usermode", &self.usermode)
            .finish()
    }
}

#[inline]
pub unsafe fn translate_virtual_address(vcpu_fd: i32, address: u64) -> io::Result<kvm_translation> {
    let mut translation = kvm_translation::zeroed();
    translation.linear_address = address;
    check!(libc::ioctl(vcpu_fd, KVM_TRANSLATE, &mut translation))?;
    Ok(translation)
}
