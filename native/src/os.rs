use core::{fmt::Write as _, mem};

use crate::{
    c_char, cstring, error, symbols::Symbols, Backend, Error, PhysicalAddress, VirtualAddress,
};
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
pub struct Module {
    addr: VirtualAddress,
}

impl From<ibc::Module> for Module {
    fn from(module: ibc::Module) -> Self {
        Self {
            addr: module.0.into(),
        }
    }
}

impl From<Module> for ibc::Module {
    fn from(module: Module) -> Self {
        Self(module.addr.into())
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

#[repr(C)]
pub struct StackFrame {
    ip: VirtualAddress,
    sp: VirtualAddress,
}

impl From<&ibc::StackFrame> for StackFrame {
    fn from(frame: &ibc::StackFrame) -> Self {
        Self {
            ip: frame.instruction_pointer.into(),
            sp: frame.stack_pointer.into(),
        }
    }
}

pub struct Os(Box<dyn ibc::Os<Arch = ibc::arch::RuntimeArchitecture> + Send + Sync>);

impl Os {
    fn new(backend: Backend) -> IceResult<Box<Self>> {
        use icebox::os::Buildable;

        if let Some(builder) = icebox::os::Linux::quick_check(&backend.0) {
            let mut symbols = ibc::SymbolsIndexer::new();
            #[cfg(feature = "std")]
            symbols.load_dir("../data/linux-x86-64")?;
            let linux = builder
                .with_symbols(symbols)
                .build::<_, icebox::os::Linux<_>>(backend.0)?;
            return Ok(Box::new(Self(Box::new(linux))));
        }

        Err(IceError::from("Failed to guess host OS"))
    }
}

#[no_mangle]
pub extern "C" fn os_new(
    backend: Box<Backend>,
    os: Option<&mut mem::MaybeUninit<Box<Os>>>,
) -> *mut Error {
    error::wrap_result(os, Os::new(*backend))
}

#[no_mangle]
pub extern "C" fn os_new_linux(
    backend: Box<Backend>,
    profile: Box<Symbols>,
    os: Option<&mut mem::MaybeUninit<Box<Os>>>,
) -> *mut Error {
    error::wrap(os, || {
        let linux = icebox::os::Linux::create(backend.0, profile.0)?;
        Ok(Box::new(Os(Box::new(linux))))
    })
}

#[no_mangle]
pub extern "C" fn os_free(os: Option<Box<Os>>) {
    drop(os);
}

#[no_mangle]
pub unsafe extern "C" fn read_virtual_memory(
    os: &Os,
    mmu_addr: PhysicalAddress,
    addr: VirtualAddress,
    buf: *mut u8,
    buf_size: usize,
) -> *mut Error {
    let buf = core::slice::from_raw_parts_mut(buf, buf_size);
    error::wrap_unit_result(os.0.read_virtual_memory(mmu_addr.into(), addr.into(), buf))
}

#[no_mangle]
pub unsafe extern "C" fn try_read_virtual_memory(
    os: &Os,
    mmu_addr: PhysicalAddress,
    addr: VirtualAddress,
    buf: *mut u8,
    buf_size: usize,
) -> *mut Error {
    let buf = core::slice::from_raw_parts_mut(buf, buf_size);
    error::wrap_unit_result(os.0.try_read_virtual_memory(mmu_addr.into(), addr.into(), buf))
}

#[no_mangle]
pub unsafe extern "C" fn read_process_memory(
    os: &Os,
    mmu_addr: PhysicalAddress,
    addr: VirtualAddress,
    proc: Process,
    buf: *mut u8,
    buf_size: usize,
) -> *mut Error {
    let buf = core::slice::from_raw_parts_mut(buf, buf_size);
    error::wrap_unit_result(os.0.read_process_memory(
        proc.into(),
        mmu_addr.into(),
        addr.into(),
        buf,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn try_read_process_memory(
    os: &Os,
    mmu_addr: PhysicalAddress,
    addr: VirtualAddress,
    proc: Process,
    buf: *mut u8,
    buf_size: usize,
) -> *mut Error {
    let buf = core::slice::from_raw_parts_mut(buf, buf_size);
    error::wrap_unit_result(os.0.try_read_process_memory(
        proc.into(),
        mmu_addr.into(),
        addr.into(),
        buf,
    ))
}

#[no_mangle]
pub extern "C" fn os_current_process(
    os: &Os,
    vcpu: usize,
    proc: Option<&mut mem::MaybeUninit<Process>>,
) -> *mut Error {
    error::wrap_result(proc, os.0.current_process(ibc::VcpuId(vcpu)))
}

#[no_mangle]
pub extern "C" fn os_current_thread(
    os: &Os,
    vcpu: usize,
    proc: Option<&mut mem::MaybeUninit<Thread>>,
) -> *mut Error {
    error::wrap_result(proc, os.0.current_thread(ibc::VcpuId(vcpu)))
}

#[no_mangle]
pub unsafe extern "C" fn os_processes(
    os: &Os,
    procs: *mut Process,
    n_procs: *mut usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let mut procs = crate::array::Array::new(procs, n_procs);
        os.0.for_each_process(&mut |proc| Ok(procs.push(proc.into())))
    })
}

#[no_mangle]
pub extern "C" fn process_id(
    os: &Os,
    proc: Process,
    pid: Option<&mut mem::MaybeUninit<u64>>,
) -> *mut Error {
    error::wrap_result(pid, os.0.process_id(proc.into()))
}

#[no_mangle]
pub unsafe extern "C" fn process_name(
    os: &Os,
    proc: Process,
    name: *mut c_char,
    max_len: usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let n = os.0.process_name(proc.into())?;
        let mut fmt = cstring::Formatter::new(name, max_len);
        let _ = fmt.write_str(&n);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn process_pgd(
    os: &Os,
    proc: Process,
    pgd: Option<&mut mem::MaybeUninit<PhysicalAddress>>,
) -> *mut Error {
    error::wrap_result(pgd, os.0.process_pgd(proc.into()))
}

#[no_mangle]
pub unsafe extern "C" fn process_path(
    os: &Os,
    proc: Process,
    name: *mut c_char,
    max_len: usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let path = os.0.process_path(proc.into())?;
        let mut fmt = cstring::Formatter::new(name, max_len);
        if let Some(path) = path {
            let _ = fmt.write_str(&path);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn process_parent(
    os: &Os,
    proc: Process,
    parent: Option<&mut mem::MaybeUninit<Process>>,
) -> *mut Error {
    error::wrap_result(parent, os.0.process_parent(proc.into()))
}

#[no_mangle]
pub unsafe extern "C" fn process_vmas(
    os: &Os,
    proc: Process,
    vmas: *mut Vma,
    n_vmas: *mut usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let mut vmas = crate::array::Array::new(vmas, n_vmas);
        os.0.process_for_each_vma(proc.into(), &mut |vma| Ok(vmas.push(vma.into())))
    })
}

#[no_mangle]
pub unsafe extern "C" fn process_threads(
    os: &Os,
    proc: Process,
    threads: *mut Thread,
    n_threads: *mut usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let mut threads = crate::array::Array::new(threads, n_threads);
        os.0.process_for_each_thread(proc.into(), &mut |thread| Ok(threads.push(thread.into())))
    })
}

#[no_mangle]
pub unsafe extern "C" fn process_children(
    os: &Os,
    proc: Process,
    children: *mut Process,
    n_children: *mut usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let mut children = crate::array::Array::new(children, n_children);
        os.0.process_for_each_child(proc.into(), &mut |child| Ok(children.push(child.into())))
    })
}

#[no_mangle]
pub unsafe extern "C" fn process_modules(
    os: &Os,
    proc: Process,
    modules: *mut Module,
    n_modules: *mut usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let mut modules = crate::array::Array::new(modules, n_modules);
        os.0.process_for_each_module(proc.into(), &mut |module| Ok(modules.push(module.into())))
    })
}

#[no_mangle]
pub unsafe extern "C" fn process_callstack(
    os: &Os,
    proc: Process,
    frames: *mut StackFrame,
    n_frames: *mut usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let mut frames = crate::array::Array::new(frames, n_frames);
        os.0.process_callstack(proc.into(), &mut |frame| Ok(frames.push(frame.into())))
    })
}

#[no_mangle]
pub extern "C" fn thread_id(
    os: &Os,
    thread: Thread,
    tid: Option<&mut mem::MaybeUninit<u64>>,
) -> *mut Error {
    error::wrap_result(tid, os.0.thread_id(thread.into()))
}

#[no_mangle]
pub unsafe extern "C" fn thread_name(
    os: &Os,
    thread: Thread,
    name: *mut c_char,
    max_len: usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let n = os.0.thread_name(thread.into())?;
        let mut fmt = cstring::Formatter::new(name, max_len);
        if let Some(name) = n {
            let _ = fmt.write_str(&name);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn thread_process(
    os: &Os,
    thread: Thread,
    proc: Option<&mut mem::MaybeUninit<Process>>,
) -> *mut Error {
    error::wrap_result(proc, os.0.thread_process(thread.into()))
}

#[no_mangle]
pub extern "C" fn vma_start(
    os: &Os,
    vma: Vma,
    proc: Option<&mut mem::MaybeUninit<VirtualAddress>>,
) -> *mut Error {
    error::wrap_result(proc, os.0.vma_start(vma.into()))
}

#[no_mangle]
pub extern "C" fn vma_end(
    os: &Os,
    vma: Vma,
    proc: Option<&mut mem::MaybeUninit<VirtualAddress>>,
) -> *mut Error {
    error::wrap_result(proc, os.0.vma_end(vma.into()))
}

#[no_mangle]
pub unsafe extern "C" fn vma_path(
    os: &Os,
    vma: Vma,
    path: *mut c_char,
    max_len: usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let p = os.0.vma_path(vma.into())?;
        let mut fmt = cstring::Formatter::new(path, max_len);
        if let Some(path) = p {
            let _ = fmt.write_str(&path);
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn module_start(
    os: &Os,
    module: Module,
    proc: Process,
    start: Option<&mut mem::MaybeUninit<VirtualAddress>>,
) -> *mut Error {
    error::wrap(start, || {
        let (start, _) = os.0.module_span(module.into(), proc.into())?;
        Ok(start.into())
    })
}

#[no_mangle]
pub extern "C" fn module_end(
    os: &Os,
    module: Module,
    proc: Process,
    end: Option<&mut mem::MaybeUninit<VirtualAddress>>,
) -> *mut Error {
    error::wrap(end, || {
        let (_, end) = os.0.module_span(module.into(), proc.into())?;
        Ok(end.into())
    })
}

#[no_mangle]
pub unsafe extern "C" fn module_name(
    os: &Os,
    module: Module,
    proc: Process,
    name: *mut c_char,
    max_len: usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let n = os.0.module_name(module.into(), proc.into())?;
        let mut fmt = cstring::Formatter::new(name, max_len);
        let _ = fmt.write_str(&n);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn module_path(
    os: &Os,
    module: Module,
    proc: Process,
    path: *mut c_char,
    max_len: usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let p = os.0.module_path(module.into(), proc.into())?;
        let mut fmt = cstring::Formatter::new(path, max_len);
        let _ = fmt.write_str(&p);
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn resolve_symbol(
    os: &Os,
    proc: Process,
    addr: VirtualAddress,
    symbol: *mut c_char,
    max_len: usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let sym = os.0.resolve_symbol(addr.into(), proc.into())?;
        let mut fmt = cstring::Formatter::new(symbol, max_len);
        if let Some((sym, _)) = sym {
            let _ = fmt.write_str(sym);
        }
        Ok(())
    })
}
