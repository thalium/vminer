#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod allocator;
mod cstring;
mod error;

use crate::error::Error;
use alloc::{boxed::Box, sync::Arc};
use core::{
    fmt,
    mem::{self, MaybeUninit},
    num::NonZeroUsize,
};
use ibc::{IceError, IceResult};

#[allow(non_camel_case_types)]
pub type c_char = u8;
#[allow(non_camel_case_types)]
pub type c_void = u8;

pub struct Backend(Arc<dyn ibc::RuntimeBackend + Send + Sync>);

pub struct Os(Box<dyn ibc::Os + Send + Sync>);

#[repr(C)]
pub struct Process {
    addr: GuestPhysAddr,
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
pub struct GuestPhysAddr {
    val: u64,
}

impl From<ibc::PhysicalAddress> for GuestPhysAddr {
    fn from(addr: ibc::PhysicalAddress) -> Self {
        Self { val: addr.0 }
    }
}

impl From<GuestPhysAddr> for ibc::PhysicalAddress {
    fn from(addr: GuestPhysAddr) -> Self {
        Self(addr.val)
    }
}

impl Backend {
    fn new<B>(backend: B) -> Box<Self>
    where
        B: ibc::Backend + Send + Sync + 'static,
        B::Memory: Sized,
    {
        Box::new(Self(Arc::new(backend)))
    }
}

// #[no_mangle]
// pub extern "C" fn backend_virtual_to_physical(backend: &Backend, mmu_addr: GuestPhysAddr, addr: GuestVirtAddr) -> GuestPhysAddr {
//     backend.0.virtual_to_physical(mmu_addr, addr).valid().unwrap()
// }

#[no_mangle]
#[cfg(target_os = "linux")]
pub extern "C" fn kvm_connect(pid: i32, kvm: &mut mem::MaybeUninit<Box<Backend>>) -> *mut Error {
    let kvm_result = match icebox::backends::kvm::Kvm::connect(pid) {
        Ok(kvm) => Ok(Backend::new(kvm)),
        Err(err) => Err(IceError::new(err)),
    };
    error::wrap_result(kvm_result, kvm)
}

#[no_mangle]
pub unsafe extern "C" fn read_dump(
    path: *const c_char,
    dump: &mut mem::MaybeUninit<Box<Backend>>,
) -> *mut Error {
    let path = cstring::from_ut8_lossy(path);
    let kvm_result = match icebox::backends::kvm_dump::DumbDump::read(&*path) {
        Ok(kvm) => Ok(Backend::new(kvm)),
        Err(err) => Err(IceError::from(err)),
    };
    error::wrap_result(kvm_result, dump)
}

impl Os {
    fn new(backend: Backend) -> IceResult<Box<Self>> {
        use icebox::os::OsBuilder;

        match icebox::os::Linux::quick_check(&backend.0) {
            Ok(true) => {
                #[allow(unused_mut)]
                let mut syms = ibc::SymbolsIndexer::new();

                #[cfg(feature = "std")]
                {
                    let kallsyms = std::io::BufReader::new(std::fs::File::open("../kallsyms")?);
                    icebox::os::linux::profile::parse_kallsyms(kallsyms, &mut syms)?;
                    syms.read_object_file("../elf")?;
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
pub unsafe extern "C" fn os_current_process(
    os: &Os,
    cpuid: usize,
    proc: &mut MaybeUninit<Process>,
) -> *mut Error {
    error::wrap_result(os.0.current_process(cpuid).map(Into::into), proc)
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
        let _ = fmt::write(&mut fmt, format_args!("{}", n));
        fmt.finish();
    });
    error::wrap_unit_result(res)
}

#[no_mangle]
pub unsafe extern "C" fn process_pid(
    os: &Os,
    proc: Process,
    pid: &mut mem::MaybeUninit<u32>,
) -> *mut Error {
    let res = os.0.process_pid(proc.into());
    error::wrap_result(res, pid)
}

#[no_mangle]
pub extern "C" fn backend_free(backend: Option<Box<Backend>>) {
    drop(backend);
}

#[no_mangle]
pub extern "C" fn os_free(os: Option<Box<Os>>) {
    drop(os);
}
