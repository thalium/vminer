#![allow(clippy::fn_to_numeric_cast, clippy::unnecessary_cast)]

use anyhow::{ensure, Context};
use std::{
    fs,
    io::{self, BufRead},
    mem, ptr,
};

const LIB_PATH: &[u8] = b"/tmp/test.so\0";
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

struct Tracee {
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

    fn detach(self) -> io::Result<()> {
        let mut this = mem::ManuallyDrop::new(self);
        unsafe { this.raw_detach() }
    }

    fn registers(&mut self) -> io::Result<libc::user_regs_struct> {
        unsafe {
            let mut regs = mem::zeroed::<libc::user_regs_struct>();
            libc::ptrace(
                libc::PTRACE_GETREGS,
                self.pid,
                ptr::null_mut::<libc::c_void>(),
                &mut regs,
            );
            Ok(regs)
        }
    }

    fn set_registers(&mut self, regs: &libc::user_regs_struct) -> io::Result<()> {
        unsafe {
            check!(libc::ptrace(
                libc::PTRACE_SETREGS,
                self.pid,
                ptr::null_mut::<libc::c_void>(),
                regs
            ))
        }
    }

    fn peek_data(&mut self, addr: *mut libc::c_void, buf: &mut [u8]) -> io::Result<()> {
        use std::os::unix::prelude::FileExt;
        self.mem.read_exact_at(buf, addr as _)
    }

    fn poke_data(&mut self, addr: *mut libc::c_void, buf: &[u8]) -> io::Result<()> {
        use std::os::unix::prelude::FileExt;
        self.mem.write_all_at(buf, addr as _)
    }

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

    fn continu(&mut self) -> io::Result<()> {
        unsafe {
            check!(libc::ptrace(
                libc::PTRACE_CONT,
                self.pid,
                ptr::null_mut::<libc::c_void>(),
                0usize
            ))?;
        }
        self.wait()?;
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

fn attach(pid: libc::pid_t, _fds: &[i32]) -> anyhow::Result<()> {
    let our_libdl = find_lib(std::process::id() as _, "libdl-2").context("our libdl")?;
    let their_libdl = find_lib(pid, "libdl-2").context("their libdl")?;
    let their_dlopen = their_libdl + (libc::dlopen as u64 - our_libdl);
    let their_dlsym = their_libdl + (libc::dlsym as u64 - our_libdl);

    let mut tracee = Tracee::attach(pid).context("attach")?;

    let old_regs = tracee.registers().context("regs1")?;
    let rip = old_regs.rip as *mut libc::c_void;

    // mmap(NULL, PAGE_SIZE, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)
    let mut new_regs = old_regs;
    new_regs.rax = libc::SYS_mmap as _;
    new_regs.rdi = 0;
    new_regs.rsi = 0x1000;
    new_regs.rdx = (libc::PROT_READ) as _;
    new_regs.r10 = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as _;
    new_regs.r8 = -1 as _;
    new_regs.r9 = 0;
    tracee.set_registers(&new_regs)?;

    let new_instrs = [
        0x0f, 0x05, // syscall
        0xff, 0xd0, // call rax
        0xcc, // trap
    ];
    let mut old_instrs = [0; 5];
    assert_eq!(new_instrs.len(), old_instrs.len());

    tracee.peek_data(rip, &mut old_instrs).context("peek")?;
    tracee.poke_data(rip, &new_instrs).context("poke")?;

    // Call mmap
    tracee.single_step().context("step 1")?;
    let mut new_regs = tracee.registers().context("regs2")?;
    ensure!(new_regs.rax != -1 as _, "mmap failed");

    let mmap_addr = new_regs.rax as *mut libc::c_void;

    let mut buffer = [0u8; TOTAL_LEN];
    buffer[..LIB_PATH.len()].copy_from_slice(LIB_PATH);
    buffer[LIB_PATH.len()..].copy_from_slice(FUN_NAME);

    tracee
        .poke_data(mmap_addr, &buffer)
        .context("copy_buffer")?;

    // void *handle = dlopen(LIB_PATH, RTLD_NOW);
    new_regs.rax = their_dlopen;
    new_regs.rdi = mmap_addr as _;
    new_regs.rsi = libc::RTLD_NOW as _;
    tracee.set_registers(&new_regs).context("set regs1")?;
    tracee.continu()?;

    new_regs = tracee.registers().context("regs3")?;
    let handle = new_regs.rax;
    ensure!(handle != 0, "dlopen failed");

    // dlsym(handle, FUN_NAME);
    new_regs.rip = (rip as u64) + 2;
    new_regs.rax = their_dlsym;
    new_regs.rdi = handle;
    new_regs.rsi = mmap_addr as u64 + LIB_PATH.len() as u64;
    tracee.set_registers(&new_regs).context("set regs2")?;
    tracee.continu().context("continue 1")?;

    new_regs = tracee.registers().context("regs4")?;
    let payload = new_regs.rax;
    ensure!(payload != 0, "dlsyl failed");

    // payload
    new_regs.rip = (rip as u64) + 2;
    new_regs.rax = payload;
    tracee.set_registers(&new_regs).context("set regs3")?;
    tracee.continu().context("continue 2")?;

    new_regs = tracee.registers()?;
    ensure!(new_regs.rax == 0, "payload failed");

    tracee.poke_data(rip, &old_instrs)?;
    tracee.set_registers(&old_regs)?;
    tracee.detach().context("detach")?;
    Ok(())
}

fn main() {
    let pid = std::env::args().nth(1).expect("missing pid");
    let pid = pid.parse().unwrap();

    attach(pid, &[]).unwrap();
}
