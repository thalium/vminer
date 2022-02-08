use ibc::{IceError, IceResult, ResultExt};
use std::{fs, io, mem, os::unix::prelude::FileExt, ptr};

use super::arch;

macro_rules! check {
    ($e:expr) => {
        match $e {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        }
    };
}

/// This is not in [`Tracee`] to make sure KVM doesn't stop if `Tracee`'s
/// initialization fail
struct RawTracee {
    pid: libc::pid_t,
}

/// See `man ptrace` for all of these
impl RawTracee {
    fn attach(pid: libc::pid_t) -> io::Result<Self> {
        unsafe {
            check!(libc::ptrace(libc::PTRACE_ATTACH, pid))?;
        }
        let this = Self { pid };
        this.wait()?;
        Ok(this)
    }

    fn wait(&self) -> io::Result<()> {
        unsafe { check!(libc::waitpid(self.pid, ptr::null_mut(), libc::WSTOPPED)) }
    }

    pub fn continu(&self) -> io::Result<()> {
        unsafe {
            check!(libc::ptrace(
                libc::PTRACE_CONT,
                self.pid,
                ptr::null_mut::<libc::c_void>(),
                0usize,
            ))?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn single_step(&self) -> io::Result<()> {
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

    fn detach(&self) -> io::Result<()> {
        unsafe {
            check!(libc::ptrace(
                libc::PTRACE_DETACH,
                self.pid,
                ptr::null_mut::<libc::c_void>(),
                0usize,
            ))
        }
    }

    fn get_registers(&self, registers: &mut arch::Registers) -> IceResult<()> {
        let mut iovec = std::io::IoSliceMut::new(bytemuck::bytes_of_mut(registers));

        unsafe {
            check!(libc::ptrace(
                libc::PTRACE_GETREGSET,
                self.pid,
                libc::NT_PRSTATUS,
                &mut iovec,
            ))
            .context("failed to get registers")?;
        }

        if iovec.len() == mem::size_of::<arch::Registers>() {
            Ok(())
        } else {
            Err(IceError::new("failed to fill registers"))
        }
    }

    fn set_registers(&self, registers: &arch::Registers) -> IceResult<()> {
        let mut iovec = std::io::IoSlice::new(bytemuck::bytes_of(registers));

        unsafe {
            check!(libc::ptrace(
                libc::PTRACE_SETREGSET,
                self.pid,
                libc::NT_PRSTATUS,
                &mut iovec,
            ))
            .context("failed to set registers")?;
        }

        if iovec.len() == mem::size_of::<arch::Registers>() {
            Ok(())
        } else {
            Err(IceError::new("failed to set registers"))
        }
    }
}

impl Drop for RawTracee {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}

/// Represents a ptraced process, ready to execute some functions for us.
///
/// Cleans up everything behind dropped. Do not leak !
pub struct Tracee {
    raw: RawTracee,
    mem: fs::File,
    registers: arch::Registers,
    instrs: [u8; arch::INSTRUCTIONS.len()],
}

impl Tracee {
    pub fn attach(pid: libc::pid_t) -> IceResult<Self> {
        // We write directly to `/proc/{pid}/mem` instead of using
        // `PTRACE_PEEKDATA` and `PTRACE_PEEKTEXT` because this far more
        // flexible
        let mem = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/proc/{pid}/mem"))?;

        let raw = RawTracee::attach(pid)?;

        // Save remote registers
        let mut registers = bytemuck::Zeroable::zeroed();
        raw.get_registers(&mut registers)?;
        let ip = registers.instruction_pointer();

        // Save current instructions and replace them with an indirect call and
        // a trap
        let mut instrs = [0; arch::INSTRUCTIONS.len()];
        mem.read_exact_at(&mut instrs, ip)?;
        mem.write_all_at(&arch::INSTRUCTIONS, ip)?;

        Ok(Self {
            raw,
            mem,
            registers,
            instrs,
        })
    }

    pub fn peek_data(&self, addr: u64, buf: &mut [u8]) -> io::Result<()> {
        self.mem.read_exact_at(buf, addr)
    }

    pub fn poke_data(&self, addr: u64, buf: &[u8]) -> io::Result<()> {
        self.mem.write_all_at(buf, addr)
    }

    fn do_funcall(&self, registers: &mut arch::Registers) -> IceResult<u64> {
        registers.move_stack(0x100);
        self.raw.set_registers(registers)?;
        self.raw.continu()?;
        self.raw.wait()?;
        self.raw.get_registers(registers)?;
        Ok(registers.return_value())
    }

    pub fn funcall0(&self, addr: u64) -> IceResult<u64> {
        let mut registers = self.registers;
        registers.prepare_funcall0(addr);
        self.do_funcall(&mut registers)
    }

    pub fn funcall2(&self, addr: u64, a: u64, b: u64) -> IceResult<u64> {
        let mut registers = self.registers;
        registers.prepare_funcall2(addr, a, b);
        self.do_funcall(&mut registers)
    }

    pub fn funcall6(
        &self,
        addr: u64,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
    ) -> IceResult<u64> {
        let mut registers = self.registers;
        registers.prepare_funcall6(addr, a, b, c, d, e, f);
        self.do_funcall(&mut registers)
    }
}

impl Drop for Tracee {
    fn drop(&mut self) {
        // Restore modified data
        let res: IceResult<()> = (|| {
            let ip = self.registers.instruction_pointer();
            self.poke_data(ip, &self.instrs)?;
            self.raw.set_registers(&self.registers)?;
            Ok(())
        })();

        if let Err(err) = res {
            log::error!("Failed to detach from tracee: {err:?}");
        }

        // Detach is done automatically
    }
}
