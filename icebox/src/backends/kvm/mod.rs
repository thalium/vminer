#![allow(clippy::too_many_arguments)]

use ibc::{IceError, IceResult, ResultExt};
use std::{
    fs,
    io::{self, BufRead, Read},
    os::unix::{net::UnixListener, prelude::*},
    thread,
};

mod ptrace;

// Architecture-dependant code goes in these module

#[cfg_attr(target_arch = "x86_64", path = "x86_64.rs")]
#[cfg_attr(target_arch = "aarch64", path = "aarch64.rs")]
mod arch;

const LIB_PATH: &[u8] = b"/usr/lib/test.so\0";
const FUN_NAME: &[u8] = b"payload\0";
const TOTAL_LEN: usize = LIB_PATH.len() + FUN_NAME.len();

/// Finds the loading address of a library's text in a process' address space
fn find_lib(pid: libc::pid_t, name: &str) -> IceResult<u64> {
    let path = format!("/proc/{pid}/maps");
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
    let our_libc = find_lib(std::process::id() as _, "libc.so")?;
    let their_libc = find_lib(pid, "libc.so")?;

    let their_dlopen = their_libc + (libc::dlopen as u64 - our_libc);
    let their_dlclose = their_libc + (libc::dlclose as u64 - our_libc);
    let their_dlsym = their_libc + (libc::dlsym as u64 - our_libc);
    let their_dlerror = their_libc + (libc::dlerror as u64 - our_libc);

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
            Ok(0) => log::trace!("dlclose"),
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

    let error = tracee.funcall2(payload, mmap_addr, fds.len() as u64)? as i32;
    if error != 0 {
        let err = io::Error::from_raw_os_error(error);
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

    let fds = fs::read_dir(format!("/proc/{pid}/fd"))?
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
        let mut other_registers = bytemuck::Zeroable::zeroed();

        let (mut socket, _) = listener.accept()?;

        (0..fds_len)
            .map(|_| {
                socket.read_exact(bytemuck::bytes_of_mut(&mut registers))?;
                socket.read_exact(bytemuck::bytes_of_mut(&mut special_registers))?;
                socket.read_exact(bytemuck::bytes_of_mut(&mut other_registers))?;
                Ok(arch::Vcpu {
                    registers,
                    special_registers,
                    other_registers,
                })
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
    mem: ibc::mem::MemRemap<ibc::mem::File>,
    vcpus: Vec<arch::Vcpu>,
}

impl Kvm {
    /// Parse /proc/pid/maps file to find the adress of the VM memory
    ///
    /// This is pretty sure to be the largest mapping
    fn find_memory(pid: libc::pid_t) -> IceResult<ibc::mem::File> {
        let mut maps = io::BufReader::new(fs::File::open(format!("/proc/{pid}/maps"))?);
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

        Ok(ibc::mem::File::open(
            format!("/proc/{pid}/mem"),
            map_guess,
            map_guess + map_size,
        )?)
    }

    pub fn connect(pid: libc::pid_t) -> IceResult<Kvm> {
        Self::create(pid, |size| {
            (
                vec![ibc::mem::MemoryMap {
                    start: ibc::PhysicalAddress(0),
                    end: ibc::PhysicalAddress(size),
                }],
                vec![ibc::PhysicalAddress(0)],
            )
        })
    }

    pub fn with_default_qemu_mappings(pid: libc::pid_t) -> IceResult<Kvm> {
        let default_qemu_mappings = |size| {
            if cfg!(target_arch = "x86_64") {
                if size <= 2 << 30 {
                    (
                        vec![ibc::mem::MemoryMap {
                            start: ibc::PhysicalAddress(0),
                            end: ibc::PhysicalAddress(size),
                        }],
                        vec![ibc::PhysicalAddress(0)],
                    )
                } else {
                    (
                        vec![
                            ibc::mem::MemoryMap {
                                start: ibc::PhysicalAddress(0),
                                end: ibc::PhysicalAddress(2 << 30),
                            },
                            ibc::mem::MemoryMap {
                                start: ibc::PhysicalAddress(4 << 30),
                                end: ibc::PhysicalAddress(size + (2 << 30)),
                            },
                        ],
                        vec![ibc::PhysicalAddress(0), ibc::PhysicalAddress(2 << 30)],
                    )
                }
            } else if cfg!(target_arch = "aarch64") {
                (
                    vec![ibc::mem::MemoryMap {
                        start: ibc::PhysicalAddress(1 << 30),
                        end: ibc::PhysicalAddress(size + (1 << 30)),
                    }],
                    vec![ibc::PhysicalAddress(0)],
                )
            } else {
                unreachable!()
            }
        };

        Self::create(pid, default_qemu_mappings)
    }

    pub fn with_memory_mappings(
        pid: libc::pid_t,
        mappings: Vec<ibc::mem::MemoryMap>,
        remap_at: Vec<ibc::PhysicalAddress>,
    ) -> IceResult<Kvm> {
        Self::create(pid, |_| (mappings, remap_at))
    }

    fn create<F>(pid: libc::pid_t, make_mappings: F) -> IceResult<Kvm>
    where
        F: FnOnce(u64) -> (Vec<ibc::mem::MemoryMap>, Vec<ibc::PhysicalAddress>),
    {
        let mem = Self::find_memory(pid)?;
        let vcpus = get_regs(pid)?;
        let (mappings, remap_at) = make_mappings(mem.size());
        let mem = ibc::mem::MemRemap::new(mem, mappings, remap_at);

        Ok(Kvm { mem, vcpus })
    }
}

impl ibc::Memory for Kvm {
    #[inline]
    fn memory_mappings(&self) -> &[ibc::mem::MemoryMap] {
        self.mem.memory_mappings()
    }

    #[inline]
    fn read_physical(
        &self,
        addr: ibc::PhysicalAddress,
        buf: &mut [u8],
    ) -> ibc::MemoryAccessResult<()> {
        self.mem.read_physical(addr, buf)
    }
}

impl ibc::HasVcpus for Kvm {
    type Arch = arch::Arch;

    fn arch(&self) -> Self::Arch {
        arch::Arch
    }

    fn vcpus_count(&self) -> usize {
        self.vcpus.len()
    }

    fn registers(
        &self,
        vcpu: ibc::VcpuId,
    ) -> ibc::VcpuResult<<Self::Arch as ibc::Architecture>::Registers> {
        Ok(self
            .vcpus
            .get(vcpu.0)
            .ok_or(ibc::VcpuError::InvalidId)?
            .registers)
    }

    fn special_registers(
        &self,
        vcpu: ibc::VcpuId,
    ) -> ibc::VcpuResult<<Self::Arch as ibc::Architecture>::SpecialRegisters> {
        Ok(self
            .vcpus
            .get(vcpu.0)
            .ok_or(ibc::VcpuError::InvalidId)?
            .special_registers)
    }

    fn other_registers(
        &self,
        vcpu: ibc::VcpuId,
    ) -> ibc::VcpuResult<<Self::Arch as ibc::Architecture>::OtherRegisters> {
        Ok(self
            .vcpus
            .get(vcpu.0)
            .ok_or(ibc::VcpuError::InvalidId)?
            .other_registers)
    }
}

impl ibc::Backend for Kvm {}
