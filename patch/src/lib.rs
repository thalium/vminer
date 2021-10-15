#![cfg(target_os = "linux")]

use std::{
    io::{self, Write},
    os::unix::{net::UnixStream, prelude::*},
};

mod kvm;

#[no_mangle]
pub extern "C" fn payload() -> libc::c_int {
    match send_fds(23) {
        Ok(()) => 0,
        Err(e) => e.raw_os_error().unwrap_or(777),
    }
}

fn send_fds(vcpu1: RawFd) -> io::Result<()> {
    let regs = unsafe { kvm::get_regs(vcpu1)? };
    let sregs = unsafe { kvm::get_sregs(vcpu1)? };

    let mut socket = UnixStream::connect("/tmp/get_fds")?;

    let buf = bytemuck::bytes_of(&regs);
    socket.write_all(buf)?;
    let buf = bytemuck::bytes_of(&sregs);
    socket.write_all(buf)?;

    Ok(())
}
