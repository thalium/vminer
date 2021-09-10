use std::{
    io::{self, Write},
    mem,
    os::unix::{net::UnixStream, prelude::*},
};

macro_rules! check {
    ($e:expr) => {
        match $e {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    };
}
#[repr(C)]
#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct kvm_regs {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rsp: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    rflags: u64,
}

const KVM_GET_REGS: u64 = 2156965505;

#[no_mangle]
pub extern "C" fn payload() -> libc::c_int {
    match send_fds(21) {
        Ok(()) => 0,
        Err(e) => e.raw_os_error().unwrap_or(777),
    }
}

fn send_fds(vcpu1: RawFd) -> io::Result<()> {
    let regs = unsafe {
        let mut regs = mem::zeroed::<kvm_regs>();
        let res = libc::ioctl(vcpu1, KVM_GET_REGS, &mut regs as *mut _ as u64);
        check!(res)?;
        regs
    };

    let buf = bytemuck::bytes_of(&regs);

    let mut socket = UnixStream::connect("/tmp/get_fds")?;
    socket.write_all(buf)?;

    Ok(())
}
