use ice::{IceError, IceResult, ResultExt};
use std::{
    fs,
    io::{self, BufRead, Read},
    os::unix::{net::UnixListener, prelude::*},
    thread,
};

use crate::core::{self as ice, Backend};

mod ptrace;

// Architecture-dependant code goes in these module

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod arch;

#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod arch;

const LIB_PATH: &[u8] = b"/usr/lib/test.so\0";
const FUN_NAME: &[u8] = b"payload\0";
const TOTAL_LEN: usize = LIB_PATH.len() + FUN_NAME.len();

/// Finds the loading address of a library's text in a process' address space
fn find_lib(pid: libc::pid_t, name: &str) -> IceResult<u64> {
    let path = format!("/proc/{}/maps", pid);
    let file = fs::File::open(&path)?;
    let file = io::BufReader::new(file);

    for line in file.lines() {
        let line = line?;

        if line.contains(name) && line.contains("r-xp ") {
            let end = line.find('-').unwrap();
            return u64::from_str_radix(&line[..end], 16)
                .with_context(|| format!("failed to parse {path}"));
        }
    }

    Err(IceError::new(format!(
        "failed to find address of \"{name}\""
    )))
}

/// Calls `dlerror` in a traced process
///
/// This is quite useful for debugging, but hopefully should never get called
#[cold]
fn get_dlerror(tracee: &ptrace::Tracee, dlerror: u64) -> IceError {
    let error: IceResult<_> = (|| {
        // char *error = dlerror();
        let mut addr = tracee.funcall0(dlerror)?;

        if addr == 0 {
            return Ok(String::from("Success"));
        }

        let mut error = Vec::with_capacity(128);
        let mut buf = [0];

        loop {
            tracee.peek_data(addr, &mut buf)?;

            match buf {
                [0] => break,
                [n] => error.push(n),
            }
            addr = addr.wrapping_add(1);
        }

        Ok(String::from_utf8_lossy(&error).into_owned())
    })();
    match error {
        Ok(error) => IceError::new(error),
        Err(err) => IceError::with_context("failed to get dlerror", err),
    }
}

/// Gets `errno` from a traced process
///
/// This is quite useful for debugging, but hopefully should never get called
#[cold]
fn get_errno(tracee: &ptrace::Tracee, errno: u64) -> IceError {
    let errno: IceResult<_> = (|| {
        // int *errno = __errno_location();
        let addr = tracee.funcall0(errno)?;

        let mut errno: libc::c_int = 0;
        tracee.peek_data(addr, bytemuck::bytes_of_mut(&mut errno))?;
        Ok(errno)
    })();
    match errno {
        Ok(errno) => io::Error::from_raw_os_error(errno).into(),
        Err(err) => IceError::with_context("failed to get errno", err),
    }
}

struct OnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// Attach to a process, and make it execute our payload
#[allow(clippy::fn_to_numeric_cast)]
fn attach(pid: libc::pid_t, fds: &[i32]) -> IceResult<()> {
    // Find remote function addresses so we can call them.
    // Use our own functions to get the offset within the lib, and read /proc
    // to bypass the ASLR.
    let our_libdl = find_lib(std::process::id() as _, "libdl-2")?;
    let their_libdl = find_lib(pid, "libdl-2")?;
    let their_dlopen = their_libdl + (libc::dlopen as u64 - our_libdl);
    let their_dlclose = their_libdl + (libc::dlclose as u64 - our_libdl);
    let their_dlsym = their_libdl + (libc::dlsym as u64 - our_libdl);
    let their_dlerror = their_libdl + (libc::dlerror as u64 - our_libdl);

    let our_libc = find_lib(std::process::id() as _, "libc-2")?;
    let their_libc = find_lib(pid, "libc-2")?;
    let their_mmap = their_libc + (libc::mmap as u64 - our_libc);
    let their_errno = their_libc + (libc::__errno_location as u64 - our_libc);

    let tracee = ptrace::Tracee::attach(pid).context("failed to attach to KVM")?;
    log::trace!("Attached to KVM");

    // mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    let mmap_addr = tracee.funcall6(
        their_mmap,
        0,
        0x1000,
        (libc::PROT_READ) as _,
        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as _,
        -1i64 as _,
        0,
    )?;
    if mmap_addr as i32 == -1 {
        let err = get_errno(&tracee, their_errno);
        return Err(IceError::with_context("remote mmap failed", err));
    }
    log::trace!("mmap at 0x{mmap_addr:x}");

    // Copy arguments of dlopen and dlsym
    let mut buffer = [0u8; TOTAL_LEN];
    buffer[..LIB_PATH.len()].copy_from_slice(LIB_PATH);
    buffer[LIB_PATH.len()..].copy_from_slice(FUN_NAME);

    tracee.poke_data(mmap_addr, &buffer)?;

    // void *handle = dlopen(LIB_PATH, RTLD_NOW);
    let handle = tracee.funcall2(their_dlopen, mmap_addr, libc::RTLD_NOW as _)?;
    if handle == 0 {
        let err = get_dlerror(&tracee, their_dlerror);
        return Err(IceError::with_context("remote dlopen failed", err));
    }
    log::trace!("dlopen handle at 0x{handle:x}");

    let _do_dlclose = OnDrop(|| {
        // dlclose(handle);
        match tracee.funcall1(their_dlclose, handle) {
            Ok(0) => (),
            Ok(_) => {
                let err = get_dlerror(&tracee, their_dlerror);
                log::error!("Remote dlclose failed: {err}");
            }
            Err(err) => log::error!("Failed to call dlclose: {err}"),
        }
    });

    // payload = dlsym(handle, FUN_NAME);
    let payload = tracee.funcall2(their_dlsym, handle, mmap_addr + LIB_PATH.len() as u64)?;
    if payload == 0 {
        let err = get_dlerror(&tracee, their_dlerror);
        return Err(IceError::with_context("remote dlsym failed", err));
    }
    log::trace!("payload at 0x{payload:x}");

    // payload(fds)
    tracee.poke_data(mmap_addr, bytemuck::cast_slice(fds))?;

    let error = tracee.funcall2(payload, mmap_addr, fds.len() as u64)?;
    if error != 0 {
        let err = io::Error::from_raw_os_error(error as _);
        return Err(IceError::with_context("payload failed", err));
    }

    Ok(())
}

/// Guess KVM vCPU file descriptors from their names in `/proc`
fn get_vcpus_fds(pid: libc::pid_t) -> IceResult<Vec<i32>> {
    fn read_one(entry: io::Result<fs::DirEntry>) -> Option<i32> {
        let (path, fd_name) = entry
            .and_then(|entry| {
                let path = entry.path();
                let fd_name = path.read_link()?;
                Ok((path, fd_name))
            })
            .map_err(|e| log::warn!("Failed to read fd: {}", e))
            .ok()?;

        let fd_name = fd_name.to_str()?;

        // KVM vCPUs fds look like "anon_inode:kvm-vcpu:1"
        if fd_name.starts_with("anon_inode:kvm-vcpu:") {
            let num = path.file_name()?.to_str()?;
            return num.parse().ok();
        }

        None
    }

    let fds = fs::read_dir(format!("/proc/{}/fd", pid))?
        .filter_map(read_one)
        .collect();
    log::debug!("Found KVM vCPU files: {fds:?}");
    Ok(fds)
}

fn start_listener(
    socket_path: &str,
    fds: &[i32],
) -> IceResult<thread::JoinHandle<IceResult<Vec<arch::Vcpu>>>> {
    let fds_len = fds.len();

    let _ = fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).context("failed to bind listener socket")?;
    // FIXME: is 777 mode really required ?
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o777))?;

    Ok(thread::spawn(move || {
        let mut registers = bytemuck::Zeroable::zeroed();
        let mut special_registers = bytemuck::Zeroable::zeroed();
        #[cfg(target_arch = "x86_64")]
        let mut msrs = [0; 2];

        let (mut socket, _) = listener.accept()?;

        (0..fds_len)
            .map(|_| {
                #[cfg(target_arch = "x86_64")]
                {
                    socket.read_exact(bytemuck::bytes_of_mut(&mut registers))?;
                    socket.read_exact(bytemuck::bytes_of_mut(&mut special_registers))?;
                    socket.read_exact(bytemuck::bytes_of_mut(&mut msrs))?;
                    Ok(arch::Vcpu {
                        registers,
                        special_registers,
                        lstar: msrs[0],
                        gs_kernel_base: msrs[1],
                    })
                }
                #[cfg(target_arch = "aarch64")]
                {
                    socket.read_exact(bytemuck::bytes_of_mut(&mut registers))?;
                    socket.read_exact(bytemuck::bytes_of_mut(&mut special_registers))?;
                    Ok(arch::Vcpu {
                        registers,
                        special_registers,
                    })
                }
            })
            .collect()
    }))
}

fn get_regs(pid: libc::pid_t) -> IceResult<Vec<arch::Vcpu>> {
    let fds = get_vcpus_fds(pid)?;
    let socket_path = "/tmp/get_fds";
    let handle = start_listener(socket_path, &fds)?;

    attach(pid, &fds)?;
    log::info!("Payload succeded");

    let regs = handle.join().unwrap()?;
    Ok(regs)
}

pub struct Kvm {
    mem: ice::File,
    vcpus: Vec<arch::Vcpu>,
}

impl Kvm {
    pub fn connect(pid: libc::pid_t) -> IceResult<Kvm> {
        // Parse /proc/pid/maps file to find the adress of the VM memory
        //
        // This is pretty sure to be the largest mapping
        let (mem_offset, mem_size) = {
            let mut maps = io::BufReader::new(fs::File::open(format!("/proc/{}/maps", pid))?);
            let mut line = String::with_capacity(200);

            let mut map_guess = 0;
            let mut map_size = 0;

            while maps.read_line(&mut line)? != 0 {
                (|| {
                    let i = line.find('-')?;
                    let (start_addr, line) = line.split_at(i);
                    let start_addr = u64::from_str_radix(start_addr, 16).ok()?;
                    let i = line.find(' ')?;

                    let (end_addr, line) = line.split_at(i);
                    let end_addr = u64::from_str_radix(&end_addr[1..], 16).ok()?;

                    // Avoid loaded libs
                    if line.contains("/usr/") {
                        return None;
                    }

                    let cur_size = end_addr - start_addr;
                    if cur_size > map_size {
                        map_size = cur_size;
                        map_guess = start_addr;
                    }

                    Some(())
                })();

                line.clear();
            }

            if map_guess == 0 {
                return Err(IceError::new("failed to find VM memory"));
            }

            log::debug!("Found KVM memory of size 0x{map_size:x} at address 0x{map_guess:x}",);
            (map_guess, map_size)
        };

        // Map VM memory in our address space
        let mem = ice::File::open(
            format!("/proc/{}/mem", pid),
            mem_offset,
            mem_offset + mem_size,
        )?;
        let vcpus = get_regs(pid)?;

        Ok(Kvm { mem, vcpus })
    }
}

impl Backend for Kvm {
    type Arch = arch::Arch;
    type Memory = ice::File;

    #[inline]
    fn vcpus(&self) -> &[arch::Vcpu] {
        &self.vcpus
    }

    #[inline]
    fn memory(&self) -> &Self::Memory {
        &self.mem
    }
}
