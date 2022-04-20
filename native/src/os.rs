use core::{
    fmt,
    mem::{self, MaybeUninit},
    num::NonZeroUsize,
};

use crate::{c_char, cstring, error, Backend, Error, PhysicalAddress, VirtualAddress};
use alloc::boxed::Box;
use ibc::{IceError, IceResult};

#[repr(C)]
pub struct Process {
    addr: VirtualAddress,
}

impl From<ibc::Process> for Process {
    fn from(proc: ibc::Process) -> Self {
        Self {
            addr: proc.0.into(),
        }
    }
}

impl From<Process> for ibc::Process {
    fn from(proc: Process) -> Self {
        Self(proc.addr.into())
    }
}

#[repr(C)]
pub struct Thread {
    addr: VirtualAddress,
}

impl From<ibc::Thread> for Thread {
    fn from(thread: ibc::Thread) -> Self {
        Self {
            addr: thread.0.into(),
        }
    }
}

impl From<Thread> for ibc::Thread {
    fn from(thread: Thread) -> Self {
        Self(thread.addr.into())
    }
}

#[repr(C)]
pub struct Vma {
    addr: VirtualAddress,
}

impl From<ibc::Vma> for Vma {
    fn from(vma: ibc::Vma) -> Self {
        Self { addr: vma.0.into() }
    }
}

impl From<Vma> for ibc::Vma {
    fn from(vma: Vma) -> Self {
        Self(vma.addr.into())
    }
}

pub struct Os(Box<dyn ibc::Os + Send + Sync>);

impl Os {
    fn new(backend: Backend) -> IceResult<Box<Self>> {
        use icebox::os::OsBuilder;

        match icebox::os::Linux::quick_check(&backend.0) {
            Ok(true) => {
                #[allow(unused_mut)]
                let mut syms = ibc::SymbolsIndexer::new();

                #[cfg(feature = "std")]
                {
                    let kallsyms = std::io::BufReader::new(std::fs::File::open(
                        "../data/linux-5.10-x86_64/System.map",
                    )?);
                    icebox::os::linux::profile::parse_symbol_file(
                        kallsyms,
                        syms.get_lib_mut("System.map".into()),
                    )?;
                    syms.read_object_file("../data/linux-5.10-x86_64/module.ko")?;
                }
                let profile = icebox::os::linux::Profile::new(syms)?;
                let linux = icebox::os::Linux::create(backend.0, profile)?;
                return Ok(Box::new(Self(Box::new(linux))));
            }
            Err(e) => log::warn!("Error while guessing OS: {}", e),
            Ok(false) => (),
        }

        Err(IceError::from("Failed to guess host OS"))
    }
}

#[no_mangle]
pub unsafe extern "C" fn os_new(
    backend: Box<Backend>,
    os: &mut mem::MaybeUninit<Box<Os>>,
) -> *mut Error {
    error::wrap_result(Os::new(*backend), os)
}

#[no_mangle]
pub extern "C" fn os_free(os: Option<Box<Os>>) {
    drop(os);
}

#[no_mangle]
pub unsafe extern "C" fn os_current_process(
    os: &Os,
    cpuid: usize,
    proc: &mut MaybeUninit<Process>,
) -> *mut Error {
    error::wrap_result(os.0.current_process(cpuid), proc)
}

#[no_mangle]
pub unsafe extern "C" fn os_current_thread(
    os: &Os,
    cpuid: usize,
    proc: &mut MaybeUninit<Thread>,
) -> *mut Error {
    error::wrap_result(os.0.current_thread(cpuid), proc)
}

#[no_mangle]
pub unsafe extern "C" fn os_processes(
    os: &Os,
    mut procs: *mut Process,
    n_procs: *mut usize,
) -> *mut Error {
    let mut n = 0;
    let res = os.0.for_each_process(&mut |proc| {
        if *n_procs > n {
            procs.write(proc.into());
            procs = procs.add(1);
            n += 1;
        }
        Ok(())
    });
    *n_procs = n;
    error::wrap_unit_result(res)
}

#[no_mangle]
pub unsafe extern "C" fn process_id(
    os: &Os,
    proc: Process,
    pid: &mut mem::MaybeUninit<u64>,
) -> *mut Error {
    error::wrap_result(os.0.process_pid(proc.into()), pid)
}

#[no_mangle]
pub unsafe extern "C" fn process_name(
    os: &Os,
    proc: Process,
    name: *mut c_char,
    max_len: usize,
) -> *mut Error {
    let res = os.0.process_name(proc.into()).map(|n| {
        let max_len = match NonZeroUsize::new(max_len) {
            Some(l) => l,
            None => return,
        };

        let mut fmt = cstring::Formatter::new(name, max_len);
        let _ = fmt::write(&mut fmt, format_args!("{n}"));
        fmt.finish();
    });
    error::wrap_unit_result(res)
}

#[no_mangle]
pub unsafe extern "C" fn process_pgd(
    os: &Os,
    proc: Process,
    pgd: &mut mem::MaybeUninit<PhysicalAddress>,
) -> *mut Error {
    error::wrap_result(os.0.process_pgd(proc.into()), pgd)
}

#[no_mangle]
pub unsafe extern "C" fn process_parent(
    os: &Os,
    proc: Process,
    parent: &mut mem::MaybeUninit<Process>,
) -> *mut Error {
    error::wrap_result(os.0.process_parent(proc.into()), parent)
}

#[no_mangle]
pub unsafe extern "C" fn thread_id(
    os: &Os,
    thread: Thread,
    tid: &mut mem::MaybeUninit<u64>,
) -> *mut Error {
    error::wrap_result(os.0.thread_id(thread.into()), tid)
}

#[no_mangle]
pub unsafe extern "C" fn thread_name(
    os: &Os,
    thread: Thread,
    name: *mut c_char,
    max_len: usize,
) -> *mut Error {
    let res = os.0.thread_name(thread.into()).map(|n| {
        let max_len = match NonZeroUsize::new(max_len) {
            Some(l) => l,
            None => return,
        };

        let mut fmt = cstring::Formatter::new(name, max_len);
        if let Some(name) = n {
            let _ = fmt::write(&mut fmt, format_args!("{name}"));
        }
        fmt.finish();
    });
    error::wrap_unit_result(res)
}

#[no_mangle]
pub unsafe extern "C" fn thread_process(
    os: &Os,
    thread: Thread,
    proc: &mut mem::MaybeUninit<Process>,
) -> *mut Error {
    error::wrap_result(os.0.thread_process(thread.into()), proc)
}

#[no_mangle]
pub unsafe extern "C" fn vma_start(
    os: &Os,
    vma: Vma,
    proc: &mut mem::MaybeUninit<VirtualAddress>,
) -> *mut Error {
    error::wrap_result(os.0.vma_start(vma.into()), proc)
}

#[no_mangle]
pub unsafe extern "C" fn vma_end(
    os: &Os,
    vma: Vma,
    proc: &mut mem::MaybeUninit<VirtualAddress>,
) -> *mut Error {
    error::wrap_result(os.0.vma_end(vma.into()), proc)
}
