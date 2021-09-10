use std::{
    io,
    os::unix::{net::UnixStream, prelude::*},
};

use passfd::FdPassingExt;

#[no_mangle]
pub extern "C" fn payload() -> libc::c_int {
    match send_fds(&[15, 21, 22]) {
        Ok(()) => 0,
        Err(e) => e.raw_os_error().unwrap_or(777),
    }
}

fn send_fds(fds: &[RawFd]) -> io::Result<()> {
    let socket = UnixStream::connect("/tmp/get_fds")?;
    for &fd in fds {
        socket.send_fd(fd)?;
    }

    Ok(())
}
