use std::{
    io,
    os::unix::{net::UnixStream, prelude::*},
};

use passfd::FdPassingExt;

#[no_mangle]
pub extern "C" fn payload2() -> libc::c_int {
    send_fds(&[15, 21, 22]).is_err() as _
}

fn send_fds(fds: &[RawFd]) -> io::Result<()> {
    let socket = UnixStream::connect("/run/get_fds")?;
    for &fd in fds {
        socket.send_fd(fd)?;
    }

    Ok(())
}

#[no_mangle]
pub extern "C" fn payload() -> libc::c_int {
    println!("It works !");
    0
}
