use anyhow::{bail, ensure, Context};
use bytemuck::Zeroable;
use std::{
    fs,
    io::{self, BufRead, Read},
    mem,
    os::unix::{net::UnixListener, prelude::*},
    ptr,
};

use crate::core::{self as ice, Backend};

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod arch;

#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod arch;

const LIB_PATH: &[u8] = b"/usr/lib/test.so\0";
const FUN_NAME: &[u8] = b"payload\0";
const TOTAL_LEN: usize = LIB_PATH.len() + FUN_NAME.len();

fn find_lib(pid: libc::pid_t, name: &str) -> io::Result<u64> {
    let file = fs::File::open(format!("/proc/{}/maps", pid))?;
    let file = io::BufReader::new(file);

    for line in file.lines() {
        let line = line?;

        if line.contains(name) && line.contains("r-xp ") {
            let end = line.find('-').unwrap();
            return u64::from_str_radix(&line[..end], 16).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{:?}: {}", e, line))
            });
        }
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Could not find address",
    ))
}

macro_rules! check {
    ($e:expr) => {
        match $e {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    };
}

pub struct Tracee {
    pid: libc::pid_t,
    mem: fs::File,
}

impl Tracee {
    fn wait(&mut self) -> io::Result<()> {
        unsafe { check!(libc::waitpid(self.pid, ptr::null_mut(), libc::WSTOPPED)) }
    }

    fn attach(pid: libc::pid_t) -> io::Result<Self> {
        unsafe {
            check!(libc::ptrace(libc::PTRACE_ATTACH, pid))?;
        }
        let mem = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{}/mem", pid))?;
        let mut this = Self { pid, mem };
        this.wait()?;
        Ok(this)
    }

    unsafe fn raw_detach(&mut self) -> io::Result<()> {
        check!(libc::ptrace(libc::PTRACE_DETACH, self.pid))
    }

    pub fn detach(self) -> io::Result<()> {
        let mut this = mem::ManuallyDrop::new(self);
        unsafe { this.raw_detach() }
    }

    fn registers(&mut self) -> io::Result<arch::Registers> {
        let mut regs = arch::Registers::zeroed();
        let mut iovec = std::io::IoSliceMut::new(bytemuck::bytes_of_mut(&mut regs));

        unsafe {
            check!(libc::ptrace(
                libc::PTRACE_GETREGSET,
                self.pid,
                libc::NT_PRSTATUS,
                &mut iovec,
            ))?;
        }

        if iovec.len() == mem::size_of::<arch::Registers>() {
            Ok(regs)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to fill registers",
            ))
        }
    }

    fn set_registers(&mut self, regs: &arch::Registers) -> io::Result<()> {
        let mut iovec = std::io::IoSlice::new(bytemuck::bytes_of(regs));

        unsafe {
            check!(libc::ptrace(
                libc::PTRACE_SETREGSET,
                self.pid,
                libc::NT_PRSTATUS,
                &mut iovec,
            ))?;
        }

        if iovec.len() == mem::size_of::<arch::Registers>() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::Other,
                "Failed to set registers",
            ))
        }
    }

    fn peek_data(&mut self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.mem.read_exact_at(buf, addr as _)
    }

    fn poke_data(&mut self, addr: u64, buf: &[u8]) -> io::Result<()> {
        self.mem.write_all_at(buf, addr as _)
    }

    #[allow(dead_code)]
    fn single_step(&mut self) -> io::Result<()> {
        unsafe {
            check!(libc::ptrace(
                libc::PTRACE_SINGLESTEP,
                self.pid,
                ptr::null_mut::<libc::c_void>(),
                0usize
            ))?;
        }
        self.wait()?;
        Ok(())
    }

    fn restart(&mut self) -> io::Result<()> {
        self.continu()?;
        self.wait()?;
        Ok(())
    }

    fn continu(&mut self) -> io::Result<()> {
        unsafe {
            check!(libc::ptrace(
                libc::PTRACE_CONT,
                self.pid,
                ptr::null_mut::<libc::c_void>(),
                0usize
            ))?;
        }
        Ok(())
    }
}

impl Drop for Tracee {
    fn drop(&mut self) {
        unsafe {
            let _ = self.raw_detach();
        }
    }
}

#[cold]
fn get_dlerror(
    tracee: &mut Tracee,
    regs: &mut arch::Registers,
    dlerror: u64,
    rip: u64,
) -> anyhow::Result<String> {
    // char *error = dlerror();
    regs.prepare_funcall0(rip, dlerror);
    tracee.set_registers(regs).context("p")?;
    tracee.restart().context("qsd")?;
    let res = tracee.registers().context("er")?;

    let mut addr = res.return_value();
    let mut error = Vec::with_capacity(32);
    let mut buf = [0];

    loop {
        tracee.peek_data(addr, &mut buf).context("os")?;

        match buf {
            [0] => break,
            [n] => error.push(n),
        }
        addr = addr.wrapping_add(1);
    }

    Ok(String::from_utf8_lossy(&error).into_owned())
}

#[allow(clippy::fn_to_numeric_cast, clippy::unnecessary_cast)]
fn attach(pid: libc::pid_t, fds: &[i32]) -> anyhow::Result<()> {
    let our_libdl = find_lib(std::process::id() as _, "libdl-2").context("our libdl")?;
    let their_libdl = find_lib(pid, "libdl-2").context("their libdl")?;
    let their_dlopen = their_libdl + (libc::dlopen as u64 - our_libdl);
    let their_dlsym = their_libdl + (libc::dlsym as u64 - our_libdl);
    let their_dlerror = their_libdl + (libc::dlerror as u64 - our_libdl);

    let our_libc = find_lib(std::process::id() as _, "libc-2")?;
    let their_libc = find_lib(pid, "libc-2")?;
    let their_mmap = their_libc + (libc::mmap as u64 - our_libc);

    let mut tracee = Tracee::attach(pid).context("attach")?;

    let old_regs = tracee.registers().context("regs1")?;
    let mut new_regs = old_regs;
    let rip = old_regs.instruction_pointer();

    let mut old_instrs = [0; arch::INSTRUCTIONS.len()];
    tracee.peek_data(rip, &mut old_instrs).context("peek")?;
    tracee.poke_data(rip, &arch::INSTRUCTIONS).context("poke")?;

    new_regs.move_stack(0x100);

    // mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    new_regs.prepare_funcall6(
        rip,
        their_mmap,
        0,
        0x1000,
        (libc::PROT_READ) as _,
        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as _,
        -1 as _,
        0,
    );
    tracee.set_registers(&new_regs)?;
    tracee.restart()?;

    let mut new_regs = tracee.registers().context("regs2")?;
    let mmap_addr = new_regs.return_value();
    ensure!(mmap_addr != -1 as _, "mmap failed");
    log::trace!("mmap at 0x{mmap_addr:x}");

    let mut buffer = [0u8; TOTAL_LEN];
    buffer[..LIB_PATH.len()].copy_from_slice(LIB_PATH);
    buffer[LIB_PATH.len()..].copy_from_slice(FUN_NAME);

    tracee
        .poke_data(mmap_addr, &buffer)
        .context("copy_buffer")?;

    // void *handle = dlopen(LIB_PATH, RTLD_NOW);
    new_regs.prepare_funcall2(rip, their_dlopen, mmap_addr, libc::RTLD_NOW as _);
    tracee.set_registers(&new_regs).context("set regs1")?;
    tracee.restart()?;

    new_regs = tracee.registers().context("regs3")?;
    let handle = new_regs.return_value();
    if handle == 0 {
        let err = get_dlerror(&mut tracee, &mut new_regs, their_dlerror, rip)?;

        tracee.poke_data(rip, &old_instrs).context("a")?;
        tracee.set_registers(&old_regs).context("b")?;
        tracee.continu().context("v")?;

        anyhow::bail!("dlopen failed: {}", err);
    }
    log::trace!("dlopen handle at 0x{handle:x}");

    // payload = dlsym(handle, FUN_NAME);
    new_regs.prepare_funcall2(rip, their_dlsym, handle, mmap_addr + LIB_PATH.len() as u64);
    tracee.set_registers(&new_regs).context("set regs2")?;
    tracee.restart().context("continue 1")?;

    new_regs = tracee.registers().context("regs4")?;
    let payload = new_regs.return_value();
    if payload == 0 {
        let err = get_dlerror(&mut tracee, &mut new_regs, their_dlerror, rip)?;

        tracee.poke_data(rip, &old_instrs)?;
        tracee.set_registers(&old_regs)?;
        tracee.continu()?;

        anyhow::bail!("dlsym failed: {}", err);
    }
    log::trace!("payload at 0x{payload:x}");

    // payload(fds)
    tracee.poke_data(mmap_addr, bytemuck::cast_slice(fds))?;

    new_regs.prepare_funcall2(rip, payload, mmap_addr, fds.len() as u64);
    tracee.set_registers(&new_regs).context("set regs3")?;
    tracee.restart().context("continue 2")?;

    new_regs = tracee.registers()?;
    let error = new_regs.return_value();

    tracee.poke_data(rip, &old_instrs)?;
    tracee.set_registers(&old_regs)?;
    tracee.continu()?;

    if error != 0 {
        let err = io::Error::from_raw_os_error(error as _);
        bail!("Payload failed: {}", err);
    }

    Ok(())
}

fn get_vcpus_fds(pid: libc::pid_t) -> anyhow::Result<Vec<i32>> {
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

fn get_regs(pid: libc::pid_t) -> anyhow::Result<Vec<arch::Vcpu>> {
    let fds = get_vcpus_fds(pid)?;
    let n_fds = fds.len();

    let socket_path = "/tmp/get_fds";
    let _ = fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path).context("bind").unwrap();
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o777)).unwrap();

    let handle = std::thread::spawn(move || -> anyhow::Result<_> {
        let mut registers = bytemuck::Zeroable::zeroed();
        #[cfg(target_arch = "x86_64")]
        let mut special_registers = bytemuck::Zeroable::zeroed();
        #[cfg(target_arch = "x86_64")]
        let mut gs_kernel_base = 0;

        let (mut socket, _) = listener.accept().context("accept")?;

        (0..n_fds)
            .map(|_| {
                #[cfg(target_arch = "x86_64")]
                {
                    socket.read_exact(bytemuck::bytes_of_mut(&mut registers))?;
                    socket.read_exact(bytemuck::bytes_of_mut(&mut special_registers))?;
                    socket.read_exact(bytemuck::bytes_of_mut(&mut gs_kernel_base))?;
                    Ok(arch::Vcpu {
                        registers,
                        special_registers,
                        gs_kernel_base,
                    })
                }
                #[cfg(target_arch = "aarch64")]
                {
                    socket.read_exact(bytemuck::bytes_of_mut(&mut registers))?;
                    Ok(arch::Vcpu { registers })
                }
            })
            .collect()
    });

    attach(pid, &fds).unwrap();
    log::info!("Payload succeded");

    let regs = handle.join().unwrap()?;
    Ok(regs)
}

pub struct Kvm {
    mem: ice::File,
    vcpus: Vec<arch::Vcpu>,
}

impl Kvm {
    pub fn connect(pid: libc::pid_t) -> anyhow::Result<Kvm> {
        // Parse /proc/pid/maps file to find the adress of the VM memory
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

            ensure!(map_guess != 0, "Could not find VM memory");
            log::debug!(
                "Found KVM memory at of size 0x{:x} at address 0x{:x}",
                map_size,
                map_guess
            );
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
