#![cfg(target_os = "linux")]

use std::{
    io::{self, Write},
    os::unix::net::UnixStream,
    slice,
};

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod kvm;

#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod kvm;

#[no_mangle]
#[allow(clippy::missing_safety_doc)]
pub unsafe extern "C" fn payload(vcpus: *const i32, n: usize) -> libc::c_int {
    let vcpus = slice::from_raw_parts(vcpus, n);
    match send_fds(vcpus) {
        Ok(()) => 0,
        Err(e) => e.raw_os_error().unwrap_or(777),
    }
}

fn send_fds(vcpus: &[i32]) -> io::Result<()> {
    let mut socket = UnixStream::connect("/tmp/get_fds")?;

    #[cfg(target_arch = "x86_64")]
    for &vcpu in vcpus {
        let regs = kvm::get_regs(vcpu)?;
        let sregs = kvm::get_sregs(vcpu)?;
        let gs_kernel_base = kvm::get_kernel_gs_base(vcpu)?;

        socket.write_all(bytemuck::bytes_of(&regs))?;
        socket.write_all(bytemuck::bytes_of(&sregs))?;
        socket.write_all(bytemuck::bytes_of(&gs_kernel_base))?;
    }

    #[cfg(target_arch = "aarch64")]
    for &vcpu in vcpus {
        let regs = kvm::get_regs(vcpu)?;
        let sregs = kvm::get_special_regs(vcpu)?;

        socket.write_all(bytemuck::bytes_of(&regs))?;
        socket.write_all(bytemuck::bytes_of(&sregs))?;
    }

    Ok(())
}
