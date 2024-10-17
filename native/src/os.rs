use crate::{
    array, backend::Backend, cstring, error, symbols::Symbols, PhysicalAddress, VirtualAddress,
};
use alloc::boxed::Box;
use core::{
    ffi::{c_char, c_int},
    fmt::Write as _,
    mem,
};
use vmc::{VmError, VmResult};

#[repr(C)]
pub struct Process {
    addr: VirtualAddress,
}

impl From<vmc::Process> for Process {
    fn from(proc: vmc::Process) -> Self {
        Self {
            addr: proc.0.into(),
        }
    }
}

impl From<Process> for vmc::Process {
    fn from(proc: Process) -> Self {
        Self(proc.addr.into())
    }
}

#[repr(C)]
pub struct Module {
    addr: VirtualAddress,
}

impl From<vmc::Module> for Module {
    fn from(module: vmc::Module) -> Self {
        Self {
            addr: module.0.into(),
        }
    }
}

impl From<Module> for vmc::Module {
    fn from(module: Module) -> Self {
        Self(module.addr.into())
    }
}

#[repr(C)]
pub struct Thread {
    addr: VirtualAddress,
}

impl From<vmc::Thread> for Thread {
    fn from(thread: vmc::Thread) -> Self {
        Self {
            addr: thread.0.into(),
        }
    }
}

impl From<Thread> for vmc::Thread {
    fn from(thread: Thread) -> Self {
        Self(thread.addr.into())
    }
}

#[repr(C)]
pub struct Vma {
    addr: VirtualAddress,
}

impl From<vmc::Vma> for Vma {
    fn from(vma: vmc::Vma) -> Self {
        Self { addr: vma.0.into() }
    }
}

impl From<Vma> for vmc::Vma {
    fn from(vma: Vma) -> Self {
        Self(vma.addr.into())
    }
}

#[repr(C)]
pub struct StackFrame {
    ip: VirtualAddress,
    sp: VirtualAddress,
}

impl From<&vmc::StackFrame> for StackFrame {
    fn from(frame: &vmc::StackFrame) -> Self {
        Self {
            ip: frame.instruction_pointer.into(),
            sp: frame.stack_pointer.into(),
        }
    }
}

pub struct Os(Box<dyn vmc::Os<Arch = vmc::arch::RuntimeArchitecture> + Send + Sync>);

impl Os {
    fn new(backend: Backend, symbols: vmc::SymbolsIndexer) -> VmResult<Box<Self>> {
        use vminer::os::Buildable;

        if let Some(builder) = vminer::os::Linux::quick_check(&backend.0) {
            let linux = builder
                .with_symbols(symbols)
                .build::<_, vminer::os::Linux<_>>(backend.0)?;
            return Ok(Box::new(Self(Box::new(linux))));
        }

        if let Some(builder) = vminer::os::Windows::quick_check(&backend.0) {
            let windows = builder
                .with_symbols(symbols)
                .build::<_, vminer::os::Windows<_>>(backend.0)?;
            return Ok(Box::new(Self(Box::new(windows))));
        }

        Err(VmError::from("Failed to guess host OS"))
    }
}

#[no_mangle]
pub extern "C" fn os_new(backend: Box<Backend>, symbols: Option<Box<Symbols>>) -> Option<Box<Os>> {
    error::wrap_box(|| {
        let symbols = symbols.map_or_else(vmc::SymbolsIndexer::new, |s| s.0);
        Os::new(*backend, symbols)
    })
}

#[no_mangle]
pub extern "C" fn os_new_linux(
    backend: Box<Backend>,
    symbols: Option<Box<Symbols>>,
) -> Option<Box<Os>> {
    error::wrap_box(|| {
        let symbols = symbols.map_or_else(vmc::SymbolsIndexer::new, |s| s.0);
        let linux = vminer::os::Linux::create(backend.0, symbols)?;
        Ok(Box::new(Os(Box::new(linux))))
    })
}

#[no_mangle]
pub extern "C" fn os_new_windows(
    backend: Box<Backend>,
    symbols: Option<Box<Symbols>>,
) -> Option<Box<Os>> {
    error::wrap_box(|| {
        let symbols = symbols.map_or_else(vmc::SymbolsIndexer::new, |s| s.0);
        let linux = vminer::os::Windows::create(backend.0, symbols)?;
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
) -> c_int {
    let buf = core::slice::from_raw_parts_mut(buf, buf_size);
    error::wrap_unit(|| os.0.read_virtual_memory(mmu_addr.into(), addr.into(), buf))
}

#[no_mangle]
pub unsafe extern "C" fn try_read_virtual_memory(
    os: &Os,
    mmu_addr: PhysicalAddress,
    addr: VirtualAddress,
    buf: *mut u8,
    buf_size: usize,
) -> c_int {
    let buf = core::slice::from_raw_parts_mut(buf, buf_size);
    error::wrap_unit(|| {
        os.0.try_read_virtual_memory(mmu_addr.into(), addr.into(), buf)
    })
}

#[no_mangle]
pub unsafe extern "C" fn read_process_memory(
    os: &Os,
    mmu_addr: PhysicalAddress,
    addr: VirtualAddress,
    proc: Process,
    buf: *mut u8,
    buf_size: usize,
) -> c_int {
    let buf = core::slice::from_raw_parts_mut(buf, buf_size);
    error::wrap_unit(|| {
        os.0.read_process_memory(proc.into(), mmu_addr.into(), addr.into(), buf)
    })
}

#[no_mangle]
pub unsafe extern "C" fn try_read_process_memory(
    os: &Os,
    mmu_addr: PhysicalAddress,
    addr: VirtualAddress,
    proc: Process,
    buf: *mut u8,
    buf_size: usize,
) -> c_int {
    let buf = core::slice::from_raw_parts_mut(buf, buf_size);
    error::wrap_unit(|| {
        os.0.try_read_process_memory(proc.into(), mmu_addr.into(), addr.into(), buf)
    })
}

#[no_mangle]
pub extern "C" fn os_current_process(
    os: &Os,
    vcpu: usize,
    proc: Option<&mut mem::MaybeUninit<Process>>,
) -> c_int {
    error::wrap(proc, || os.0.current_process(vmc::VcpuId(vcpu)))
}

#[no_mangle]
pub extern "C" fn os_current_thread(
    os: &Os,
    vcpu: usize,
    proc: Option<&mut mem::MaybeUninit<Thread>>,
) -> c_int {
    error::wrap(proc, || os.0.current_thread(vmc::VcpuId(vcpu)))
}

#[no_mangle]
pub unsafe extern "C" fn os_processes(os: &Os, procs: *mut Process, n_procs: usize) -> isize {
    array::fill(procs, n_procs, |procs| {
        os.0.for_each_process(&mut |proc| Ok(procs.push(proc.into())))
    })
}

#[no_mangle]
pub extern "C" fn process_id(
    os: &Os,
    proc: Process,
    pid: Option<&mut mem::MaybeUninit<u64>>,
) -> c_int {
    error::wrap(pid, || os.0.process_id(proc.into()))
}

#[no_mangle]
pub unsafe extern "C" fn process_name(
    os: &Os,
    proc: Process,
    name: *mut c_char,
    max_len: usize,
) -> isize {
    cstring::with_formatter(name, max_len, |fmt| {
        let n = os.0.process_name(proc.into())?;
        let _ = fmt.write_str(&n);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn process_pgd(
    os: &Os,
    proc: Process,
    pgd: Option<&mut mem::MaybeUninit<PhysicalAddress>>,
) -> c_int {
    error::wrap(pgd, || os.0.process_pgd(proc.into()))
}

#[no_mangle]
pub unsafe extern "C" fn process_path(
    os: &Os,
    proc: Process,
    name: *mut c_char,
    max_len: usize,
) -> isize {
    cstring::with_formatter(name, max_len, |fmt| {
        let path = os.0.process_path(proc.into())?;
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
) -> c_int {
    error::wrap(parent, || os.0.process_parent(proc.into()))
}

#[no_mangle]
pub unsafe extern "C" fn process_vmas(
    os: &Os,
    proc: Process,
    vmas: *mut Vma,
    n_vmas: usize,
) -> isize {
    array::fill(vmas, n_vmas, |vmas| {
        os.0.process_for_each_vma(proc.into(), &mut |vma| Ok(vmas.push(vma.into())))
    })
}

#[no_mangle]
pub unsafe extern "C" fn process_threads(
    os: &Os,
    proc: Process,
    threads: *mut Thread,
    n_threads: usize,
) -> isize {
    array::fill(threads, n_threads, |threads| {
        os.0.process_for_each_thread(proc.into(), &mut |thread| Ok(threads.push(thread.into())))
    })
}

#[no_mangle]
pub unsafe extern "C" fn process_children(
    os: &Os,
    proc: Process,
    children: *mut Process,
    n_children: usize,
) -> isize {
    array::fill(children, n_children, |children| {
        os.0.process_for_each_child(proc.into(), &mut |child| Ok(children.push(child.into())))
    })
}

#[no_mangle]
pub unsafe extern "C" fn process_modules(
    os: &Os,
    proc: Process,
    modules: *mut Module,
    n_modules: usize,
) -> isize {
    array::fill(modules, n_modules, |modules| {
        os.0.process_for_each_module(proc.into(), &mut |module| Ok(modules.push(module.into())))
    })
}

#[no_mangle]
pub unsafe extern "C" fn process_callstack(
    os: &Os,
    proc: Process,
    frames: *mut StackFrame,
    n_frames: usize,
) -> isize {
    array::fill(frames, n_frames, |frames| {
        os.0.process_callstack(proc.into(), &mut |frame| Ok(frames.push(frame.into())))
    })
}

#[no_mangle]
pub extern "C" fn thread_id(
    os: &Os,
    thread: Thread,
    tid: Option<&mut mem::MaybeUninit<u64>>,
) -> c_int {
    error::wrap(tid, || os.0.thread_id(thread.into()))
}

#[no_mangle]
pub unsafe extern "C" fn thread_name(
    os: &Os,
    thread: Thread,
    name: *mut c_char,
    max_len: usize,
) -> isize {
    cstring::with_formatter(name, max_len, |fmt| {
        let n = os.0.thread_name(thread.into())?;
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
) -> c_int {
    error::wrap(proc, || os.0.thread_process(thread.into()))
}

#[no_mangle]
pub extern "C" fn vma_start(
    os: &Os,
    vma: Vma,
    proc: Option<&mut mem::MaybeUninit<VirtualAddress>>,
) -> c_int {
    error::wrap(proc, || os.0.vma_start(vma.into()))
}

#[no_mangle]
pub extern "C" fn vma_end(
    os: &Os,
    vma: Vma,
    proc: Option<&mut mem::MaybeUninit<VirtualAddress>>,
) -> c_int {
    error::wrap(proc, || os.0.vma_end(vma.into()))
}

#[no_mangle]
pub unsafe extern "C" fn vma_path(os: &Os, vma: Vma, path: *mut c_char, max_len: usize) -> isize {
    cstring::with_formatter(path, max_len, |fmt| {
        let p = os.0.vma_path(vma.into())?;
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
) -> c_int {
    error::wrap(start, || {
        let (start, _) = os.0.module_span(module.into(), proc.into())?;
        Ok(start)
    })
}

#[no_mangle]
pub extern "C" fn module_end(
    os: &Os,
    module: Module,
    proc: Process,
    end: Option<&mut mem::MaybeUninit<VirtualAddress>>,
) -> c_int {
    error::wrap(end, || {
        let (_, end) = os.0.module_span(module.into(), proc.into())?;
        Ok(end)
    })
}

#[no_mangle]
pub unsafe extern "C" fn module_name(
    os: &Os,
    module: Module,
    proc: Process,
    name: *mut c_char,
    max_len: usize,
) -> isize {
    cstring::with_formatter(name, max_len, |fmt| {
        let n = os.0.module_name(module.into(), proc.into())?;
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
) -> isize {
    cstring::with_formatter(path, max_len, |fmt| {
        let p = os.0.module_path(module.into(), proc.into())?;
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
) -> isize {
    cstring::with_formatter(symbol, max_len, |fmt| {
        let sym = os.0.resolve_symbol(addr.into(), proc.into())?;
        if let Some((sym, _)) = sym {
            let _ = fmt.write_str(sym);
        }
        Ok(())
    })
}
