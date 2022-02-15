use bytemuck::{Pod, Zeroable};
use std::io;

macro_rules! check {
    ($e:expr) => {
        match $e {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    };
}

pub const KVM_GET_REG_LIST: u64 = 3221794480;
pub const KVM_GET_ONE_REG: u64 = 1074835115;

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct kvm_regs {
    regs: user_pt_regs,

    sp_el1: u64,
    elr_el1: u64,

    spsr: [u64; 5],

    _pad: u64,

    fp_regs: user_fpsimd_state,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
struct user_fpsimd_state {
    vregs: [u128; 32],
    fpsr: u32,
    fpcr: u32,
    __reserved: [u32; 2],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct user_pt_regs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct special_regs {
    sp_el1: u64,
    ttbr0_el1: u64,
    ttbr1_el1: u64,
    vbar_el1: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
struct kvm_one_reg {
    id: u64,
    addr: u64,
}
#[repr(C)]
#[derive(Debug, Clone, Copy, Pod, Zeroable)]
pub struct kvm_reg_list {
    pub len: u64,
    pub reg: [u64; 512],
}

#[allow(dead_code)]
pub fn write_reg_list(vcpu_fd: i32) -> io::Result<kvm_reg_list> {
    use std::io::Write;
    let mut f = std::fs::File::create(format!("/tmp/reg_list_{vcpu_fd}"))?;
    unsafe {
        let mut regs = kvm_reg_list::zeroed();
        regs.len = regs.reg.len() as _;
        check!(libc::ioctl(vcpu_fd, KVM_GET_REG_LIST, &mut regs))?;

        for id in regs.reg.into_iter().take(regs.len as _) {
            let reg = get_one_reg(vcpu_fd, id)?;
            writeln!(f, "{id:x}\t{reg:x}")?;
        }

        Ok(regs)
    }
}

pub fn get_regs(vcpu_fd: i32) -> io::Result<user_pt_regs> {
    let mut regs = user_pt_regs::zeroed();
    let regs_slice = bytemuck::cast_slice_mut(std::slice::from_mut(&mut regs));

    for (i, reg) in regs_slice.iter_mut().enumerate() {
        let id = 0x6030000000100000 + 2 * (i as u64);
        *reg = get_one_reg(vcpu_fd, id)?;
    }

    Ok(regs)
}

pub fn get_special_regs(vcpu_fd: i32) -> io::Result<special_regs> {
    Ok(special_regs {
        sp_el1: get_one_reg(vcpu_fd, 0x6030000000100044)?,
        ttbr0_el1: get_one_reg(vcpu_fd, 0x603000000013c100)?,
        ttbr1_el1: get_one_reg(vcpu_fd, 0x603000000013c101)?,
        vbar_el1: get_one_reg(vcpu_fd, 0x603000000013c600)?,
    })
}

fn get_one_reg(vcpu_fd: i32, id: u64) -> io::Result<u64> {
    unsafe {
        let mut reg = 0u64;
        let mut kvm_id = kvm_one_reg {
            id,
            addr: &mut reg as *mut u64 as u64,
        };

        check!(libc::ioctl(vcpu_fd, KVM_GET_ONE_REG, &mut kvm_id))?;

        Ok(reg)
    }
}
