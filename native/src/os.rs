use core::{
    fmt,
    mem::{self, MaybeUninit},
    num::NonZeroUsize,
};

use crate::{c_char, cstring, error, Backend, Error, Process};
use alloc::boxed::Box;
use ibc::{IceError, IceResult};

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
        let _ = fmt::write(&mut fmt, format_args!("{n}"));
        fmt.finish();
    });
    error::wrap_unit_result(res)
}

#[no_mangle]
pub unsafe extern "C" fn process_pid(
    os: &Os,
    proc: Process,
    pid: &mut mem::MaybeUninit<u64>,
) -> *mut Error {
    let res = os.0.process_pid(proc.into());
    error::wrap_result(res, pid)
}
