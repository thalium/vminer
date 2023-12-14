use ibc::{Backend as _, IceError, IceResult, ResultExt};
use pyo3::{
    exceptions,
    once_cell::GILOnceCell,
    prelude::*,
    types::{PyBytes, PyString},
};
use std::{ops::ControlFlow, sync::Arc};

pyo3::create_exception!(icebox, IceboxError, pyo3::exceptions::PyException);

trait ToPyResult<T> {
    fn convert_err(self) -> PyResult<T>;
}

impl<T> ToPyResult<T> for IceResult<T> {
    fn convert_err(self) -> PyResult<T> {
        self.map_err(|err| IceboxError::new_err(err.print_backtrace()))
    }
}

impl<T> ToPyResult<T> for ibc::MemoryAccessResult<T> {
    fn convert_err(self) -> PyResult<T> {
        self.map_err(|err| IceboxError::new_err(err.to_string()))
    }
}

impl<T> ToPyResult<T> for ibc::TranslationResult<T> {
    fn convert_err(self) -> PyResult<T> {
        self.map_err(|err| IceboxError::new_err(err.to_string()))
    }
}

#[derive(pyo3::FromPyObject)]
struct VirtualAddress(u64);

impl From<VirtualAddress> for ibc::VirtualAddress {
    fn from(addr: VirtualAddress) -> Self {
        Self(addr.0)
    }
}

#[derive(pyo3::FromPyObject)]
struct PhysicalAddress(u64);

impl From<PhysicalAddress> for ibc::PhysicalAddress {
    fn from(addr: PhysicalAddress) -> Self {
        Self(addr.0)
    }
}

struct PyOwned<T>(Option<Py<T>>);

impl<T: pyo3::PyClass> PyOwned<T> {
    fn new(py: Python, value: impl Into<PyClassInitializer<T>>) -> PyResult<Self> {
        Ok(Self(Some(Py::new(py, value)?)))
    }

    fn borrow<'py>(&'py self, py: Python<'py>) -> PyResult<PyRef<'py, T>> {
        match &self.0 {
            Some(os) => Ok(os.try_borrow(py)?),
            None => Err(exceptions::PyRuntimeError::new_err(
                "Tried to access GC'ed ref",
            )),
        }
    }

    fn clone_ref(&self, py: Python) -> Self {
        Self(self.0.as_ref().map(|obj| obj.clone_ref(py)))
    }

    fn traverse(&self, visit: pyo3::PyVisit) -> Result<(), pyo3::PyTraverseError> {
        match &self.0 {
            Some(obj) => visit.call(obj),
            None => Ok(()),
        }
    }

    fn clear(&mut self) {
        self.0 = None;
    }
}

#[pyclass(subclass)]
#[derive(Clone)]
struct Backend(Arc<dyn ibc::Backend<Arch = ibc::arch::RuntimeArchitecture> + Send + Sync>);

#[pymethods]
impl Backend {
    fn virtual_to_physical(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> PyResult<u64> {
        let addr = self
            .0
            .virtual_to_physical(mmu_addr.into(), addr.into())
            .convert_err()?;
        Ok(addr.0)
    }

    fn read_memory<'py>(
        &self,
        py: Python<'py>,
        addr: PhysicalAddress,
        len: usize,
    ) -> PyResult<&'py PyBytes> {
        PyBytes::new_with(py, len, |buf| {
            self.0.read_physical(addr.into(), buf).convert_err()
        })
    }

    fn read_virtual_memory<'py>(
        &self,
        py: Python<'py>,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        len: usize,
    ) -> PyResult<&'py PyBytes> {
        PyBytes::new_with(py, len, |buf| {
            self.0
                .read_virtual_memory(mmu_addr.into(), addr.into(), buf)
                .convert_err()
        })
    }
}

#[pyclass(extends=Backend)]
struct Kvm;

#[pymethods]
impl Kvm {
    #[new]
    fn new(_pid: i32) -> PyResult<(Self, Backend)> {
        #[cfg(target_os = "linux")]
        {
            let kvm = icebox::backends::kvm::Kvm::connect(_pid).convert_err()?;
            Ok((Kvm, Backend(Arc::new(ibc::RuntimeBackend(kvm)))))
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(IceError::from(
                "This backend is not available on your platform",
            ))
            .convert_err()
        }
    }
}

#[pyclass(extends=Backend)]
struct Dump;

#[pymethods]
impl Dump {
    #[new]
    fn new(path: &str) -> PyResult<(Self, Backend)> {
        let dump = icebox::backends::kvm_dump::DumbDump::read(path).convert_err()?;
        Ok((Dump, Backend(Arc::new(dump))))
    }
}

#[derive(Clone, Copy)]
enum RequestedOs {
    Linux,
    Windows,
}

#[pyclass]
struct RawOs(Box<dyn ibc::Os<Arch = ibc::arch::RuntimeArchitecture> + Send + Sync>);

impl RawOs {
    fn new(backend: Backend, path: Option<&str>, os: Option<RequestedOs>) -> IceResult<Self> {
        let (mut builder, os) = Self::detect(&backend.0, os).context("failed to guess guest OS")?;

        if let Some(path) = path {
            let mut symbols = ibc::SymbolsIndexer::new();
            symbols.load_dir(path)?;
            builder = builder.with_symbols(symbols);
        }

        match os {
            RequestedOs::Linux => Ok(RawOs(Box::new(
                builder.build::<_, icebox::os::Linux<_>>(backend.0)?,
            ))),
            RequestedOs::Windows => Ok(RawOs(Box::new(
                builder.build::<_, icebox::os::Windows<_>>(backend.0)?,
            ))),
        }
    }

    fn detect(
        backend: &impl ibc::Backend,
        os: Option<RequestedOs>,
    ) -> Option<(icebox::os::OsBuilder, RequestedOs)> {
        use icebox::os::Buildable;

        if let Some(RequestedOs::Linux) | None = os {
            if let Some(builder) = icebox::os::Linux::quick_check(backend) {
                return Some((builder, RequestedOs::Linux));
            }
        }

        if let Some(RequestedOs::Windows) | None = os {
            if let Some(builder) = icebox::os::Windows::quick_check(backend) {
                return Some((builder, RequestedOs::Windows));
            }
        }

        None
    }
}

#[pyclass]
struct Os(PyOwned<RawOs>);

impl Os {
    fn make_proc(&self, py: Python, proc: ibc::Process) -> Process {
        Process::new(py, proc, &self.0)
    }
}

#[pymethods]
impl Os {
    fn __traverse__(&self, visit: pyo3::PyVisit) -> Result<(), pyo3::PyTraverseError> {
        self.0.traverse(visit)
    }

    fn __clear__(&mut self) {
        self.0.clear()
    }

    #[new]
    fn new(py: Python, backend: Backend, path: Option<&str>, kind: Option<&str>) -> PyResult<Self> {
        let request = match kind {
            Some("linux") => Some(RequestedOs::Linux),
            Some("windows") => Some(RequestedOs::Windows),
            Some(_) => Err(IceError::new("Unknown OS")).convert_err()?,
            None => None,
        };
        let raw = RawOs::new(backend, path, request).convert_err()?;
        Ok(Os(PyOwned::new(py, raw)?))
    }

    fn init_process(&self, py: Python) -> PyResult<Process> {
        let init = self.0.borrow(py)?.0.init_process().convert_err()?;
        Ok(self.make_proc(py, init))
    }

    fn current_thread(&self, py: Python, vcpu: usize) -> PyResult<Thread> {
        let os = self.0.borrow(py)?;
        let thread = os.0.current_thread(ibc::VcpuId(vcpu)).convert_err()?;
        Ok(Thread::new(py, thread, &self.0))
    }

    fn current_process(&self, py: Python, vcpu: usize) -> PyResult<Process> {
        let os = self.0.borrow(py)?;
        let proc = os.0.current_process(ibc::VcpuId(vcpu)).convert_err()?;
        Ok(self.make_proc(py, proc))
    }

    fn procs(&self, py: Python) -> PyResult<ProcessIter> {
        let os = self.0.borrow(py)?;
        let procs = os.0.collect_processes().convert_err()?.into_iter();

        Ok(ProcessIter {
            procs,
            os: self.0.clone_ref(py),
        })
    }

    fn find_process_by_name(&self, py: Python, name: &str) -> PyResult<Option<Process>> {
        let os = self.0.borrow(py)?;
        let proc = os.0.find_process_by_name(name).convert_err()?;
        Ok(proc.map(|p| self.make_proc(py, p)))
    }

    fn find_process_by_pid(&self, py: Python, pid: u64) -> PyResult<Option<Process>> {
        let os = self.0.borrow(py)?;
        let proc = os.0.find_process_by_id(pid).convert_err()?;
        Ok(proc.map(|p| self.make_proc(py, p)))
    }
}

#[pyclass]
struct Process {
    proc: ibc::Process,
    os: PyOwned<RawOs>,
}

impl Process {
    fn new(py: Python, proc: ibc::Process, os: &PyOwned<RawOs>) -> Self {
        Self {
            proc,
            os: os.clone_ref(py),
        }
    }
}

#[pymethods]
impl Process {
    fn __traverse__(&self, visit: pyo3::PyVisit) -> Result<(), pyo3::PyTraverseError> {
        self.os.traverse(visit)
    }

    fn __clear__(&mut self) {
        self.os.clear()
    }

    #[getter]
    fn pid(&self, py: Python) -> PyResult<u64> {
        let os = self.os.borrow(py)?;
        let pid = os.0.process_id(self.proc).convert_err()?;
        Ok(pid)
    }

    #[getter]
    fn name(&self, py: Python) -> PyResult<String> {
        let os = self.os.borrow(py)?;
        let name = os.0.process_name(self.proc).convert_err()?;
        Ok(name)
    }

    #[getter]
    fn is_kernel(&self, py: Python) -> PyResult<bool> {
        let os = self.os.borrow(py)?;
        let flags = os.0.process_is_kernel(self.proc).convert_err()?;
        Ok(flags)
    }

    #[getter]
    fn pgd(&self, py: Python) -> PyResult<u64> {
        let os = self.os.borrow(py)?;
        let pgd = os.0.process_pgd(self.proc).convert_err()?;
        Ok(pgd.0)
    }

    #[getter]
    fn exe(&self, py: Python) -> PyResult<Option<String>> {
        let os = self.os.borrow(py)?;
        os.0.process_path(self.proc).convert_err()
    }

    fn parent(&self, py: Python) -> PyResult<Process> {
        let os = self.os.borrow(py)?;
        let parent = os.0.process_parent(self.proc).convert_err()?;
        Ok(Process {
            proc: parent,
            os: self.os.clone_ref(py),
        })
    }

    fn children(&self, py: Python) -> PyResult<ProcessIter> {
        let os = self.os.borrow(py)?;
        let procs =
            os.0.process_collect_children(self.proc)
                .convert_err()?
                .into_iter();

        Ok(ProcessIter {
            procs,
            os: self.os.clone_ref(py),
        })
    }

    fn threads(&self, py: Python) -> PyResult<ThreadIter> {
        let os = self.os.borrow(py)?;
        let threads =
            os.0.process_collect_threads(self.proc)
                .convert_err()?
                .into_iter();

        Ok(ThreadIter {
            threads,
            os: self.os.clone_ref(py),
        })
    }

    fn modules(&self, py: Python) -> PyResult<ModuleIter> {
        let os = self.os.borrow(py)?;
        let modules =
            os.0.process_collect_modules(self.proc)
                .convert_err()?
                .into_iter();

        Ok(ModuleIter {
            modules,
            proc: self.proc,
            os: self.os.clone_ref(py),
        })
    }

    fn vmas(&self, py: Python) -> PyResult<VmaIter> {
        let os = self.os.borrow(py)?;
        let vmas =
            os.0.process_collect_vmas(self.proc)
                .convert_err()?
                .into_iter();

        Ok(VmaIter {
            vmas,
            os: self.os.clone_ref(py),
        })
    }

    fn callstack(&self, py: Python) -> PyResult<CallStackIter> {
        let os = self.os.borrow(py)?;

        let mut frames = Vec::new();
        let error = os.0.process_callstack(self.proc, &mut |frame| {
            frames.push(StackFrame {
                frame: frame.clone(),

                os: self.os.clone_ref(py),
                proc: self.proc,
                module: GILOnceCell::new(),
                symbol: GILOnceCell::new(),
            });
            Ok(ControlFlow::Continue(()))
        });

        Ok(CallStackIter {
            frames: frames.into_iter(),
            error,
        })
    }
}

#[pyclass]
struct Thread {
    thread: ibc::Thread,
    os: PyOwned<RawOs>,
}

impl Thread {
    fn new(py: Python, thread: ibc::Thread, os: &PyOwned<RawOs>) -> Self {
        Self {
            thread,
            os: os.clone_ref(py),
        }
    }
}

#[pymethods]
impl Thread {
    fn __traverse__(&self, visit: pyo3::PyVisit) -> Result<(), pyo3::PyTraverseError> {
        self.os.traverse(visit)
    }

    fn __clear__(&mut self) {
        self.os.clear()
    }

    #[getter]
    fn tid(&self, py: Python) -> PyResult<u64> {
        let os = self.os.borrow(py)?;
        let pid = os.0.thread_id(self.thread).convert_err()?;
        Ok(pid)
    }

    #[getter]
    fn name(&self, py: Python) -> PyResult<Option<String>> {
        let os = self.os.borrow(py)?;
        let name = os.0.thread_name(self.thread).convert_err()?;
        Ok(name)
    }

    fn process(&self, py: Python) -> PyResult<Process> {
        let os = self.os.borrow(py)?;
        let proc = os.0.thread_process(self.thread).convert_err()?;
        Ok(Process::new(py, proc, &self.os))
    }
}

#[pyclass]
struct Vma {
    start: u64,
    end: u64,
    file: Option<Py<PyString>>,
}

impl Vma {
    fn new(py: Python, vma: ibc::Vma, os: &RawOs) -> IceResult<Self> {
        let start = os.0.vma_start(vma)?.0;
        let end = os.0.vma_end(vma)?.0;
        let file =
            os.0.vma_path(vma)?
                .map(|file| PyString::new(py, &file).into());

        Ok(Self { start, end, file })
    }
}

#[pymethods]
impl Vma {
    #[getter]
    fn start(&self) -> u64 {
        self.start
    }

    #[getter]
    fn end(&self) -> u64 {
        self.end
    }

    #[getter]
    fn file(&self) -> Option<&Py<PyString>> {
        self.file.as_ref()
    }

    fn __contains__(&self, addr: u64) -> bool {
        self.start <= addr && addr < self.end
    }
}

#[pyclass]
struct Module {
    start: ibc::VirtualAddress,
    end: ibc::VirtualAddress,

    #[pyo3(get)]
    name: Py<PyString>,

    #[pyo3(get)]
    path: Py<PyString>,
}

impl Module {
    fn new(py: Python, module: ibc::Module, proc: ibc::Process, os: &RawOs) -> IceResult<Self> {
        let (start, end) = os.0.module_span(module, proc)?;

        let name = PyString::new(py, &os.0.module_name(module, proc)?).into();
        let path = PyString::new(py, &os.0.module_path(module, proc)?).into();

        Ok(Self {
            start,
            end,

            name,
            path,
        })
    }
}

#[pymethods]
impl Module {
    #[getter]
    fn start(&self) -> u64 {
        self.start.0
    }

    #[getter]
    fn end(&self) -> u64 {
        self.end.0
    }

    fn __contains__(&self, addr: u64) -> bool {
        (self.start.0..self.end.0).contains(&addr)
    }
}

#[pyclass]
struct StackFrame {
    frame: ibc::StackFrame,

    os: PyOwned<RawOs>,
    proc: ibc::Process,
    module: GILOnceCell<Option<Py<Module>>>,

    symbol: GILOnceCell<Py<PyString>>,
}

#[pymethods]
impl StackFrame {
    #[getter]
    fn start(&self) -> Option<u64> {
        self.frame.start.map(|start| start.0)
    }

    #[getter]
    fn size(&self) -> Option<u64> {
        self.frame.size
    }

    #[getter]
    fn stack_pointer(&self) -> u64 {
        self.frame.stack_pointer.0
    }

    #[getter]
    fn instruction_pointer(&self) -> u64 {
        self.frame.instruction_pointer.0
    }

    #[getter]
    fn module(&self, py: Python) -> PyResult<Option<&Py<Module>>> {
        self.module
            .get_or_try_init(py, || match self.frame.module {
                Some(module) => {
                    let os = &self.os.borrow(py)?;
                    let module = Module::new(py, module, self.proc, os).convert_err()?;
                    Ok(Some(Py::new(py, module)?))
                }
                None => Ok(None),
            })
            .map(|m| m.as_ref())
    }

    #[getter]
    fn symbol(&self, py: Python) -> PyResult<&Py<PyString>> {
        self.symbol.get_or_try_init(py, || {
            let os = &self.os.borrow(py)?;
            let s =
                os.0.format_stackframe_symbol(self.proc, &self.frame)
                    .convert_err()?;
            Ok(PyString::new(py, &s).into())
        })
    }
}

#[pyclass]
struct ProcessIter {
    procs: std::vec::IntoIter<ibc::Process>,
    os: PyOwned<RawOs>,
}

#[pymethods]
impl ProcessIter {
    fn __iter__(this: PyRef<Self>) -> PyRef<Self> {
        this
    }

    fn __next__(mut this: PyRefMut<Self>) -> PyResult<Option<Process>> {
        let proc = this.procs.next();
        Ok(proc.map(|proc| Process::new(this.py(), proc, &this.os)))
    }
}

#[pyclass]
struct ThreadIter {
    threads: std::vec::IntoIter<ibc::Thread>,
    os: PyOwned<RawOs>,
}

#[pymethods]
impl ThreadIter {
    fn __iter__(this: PyRef<Self>) -> PyRef<Self> {
        this
    }

    fn __next__(mut this: PyRefMut<Self>) -> PyResult<Option<Thread>> {
        let thread = this.threads.next();
        Ok(thread.map(|thread| Thread::new(this.py(), thread, &this.os)))
    }
}

#[pyclass]
struct ModuleIter {
    modules: std::vec::IntoIter<ibc::Module>,
    proc: ibc::Process,
    os: PyOwned<RawOs>,
}

#[pymethods]
impl ModuleIter {
    fn __iter__(this: PyRef<Self>) -> PyRef<Self> {
        this
    }

    fn __next__(&mut self, py: Python) -> PyResult<Option<Module>> {
        let os = &self.os.borrow(py)?;
        self.modules
            .next()
            .map(|module| Module::new(py, module, self.proc, os))
            .transpose()
            .convert_err()
    }
}

#[pyclass]
struct VmaIter {
    vmas: std::vec::IntoIter<ibc::Vma>,
    os: PyOwned<RawOs>,
}

#[pymethods]
impl VmaIter {
    fn __iter__(this: PyRef<Self>) -> PyRef<Self> {
        this
    }

    fn __next__(&mut self, py: Python) -> PyResult<Option<Vma>> {
        let os = self.os.borrow(py)?;
        self.vmas
            .next()
            .map(|vma| Vma::new(py, vma, &os))
            .transpose()
            .convert_err()
    }
}

#[pyclass]
struct CallStackIter {
    frames: std::vec::IntoIter<StackFrame>,
    error: IceResult<()>,
}

#[pymethods]
impl CallStackIter {
    fn __iter__(this: PyRef<Self>) -> PyRef<Self> {
        this
    }

    fn __next__(&mut self) -> PyResult<Option<StackFrame>> {
        Ok(match self.frames.next() {
            Some(frame) => Some(frame),
            None => {
                std::mem::replace(&mut self.error, Ok(())).convert_err()?;
                None
            }
        })
    }
}

/// Python module for Icebox
#[pymodule]
#[pyo3(name = "icebox")]
fn icebox_module(py: Python, m: &PyModule) -> PyResult<()> {
    let logger = pyo3_log::Logger::new(py, pyo3_log::Caching::Loggers)?;
    if let Err(err) = logger.install() {
        log::error!("{}", err);
    }

    m.add_class::<Backend>()?;
    m.add_class::<Dump>()?;
    m.add_class::<Kvm>()?;

    m.add_class::<Module>()?;
    m.add_class::<Os>()?;
    m.add_class::<Process>()?;
    m.add_class::<StackFrame>()?;
    m.add_class::<Thread>()?;
    m.add_class::<Vma>()?;

    Ok(())
}
