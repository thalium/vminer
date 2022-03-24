use std::sync::Arc;

use ibc::{IceError, IceResult, MemoryAccessResultExt};
use icebox::os::OsBuilder;
use pyo3::{exceptions, gc::PyGCProtocol, prelude::*, types::PyBytes};

use icebox_core::{self as ibc, Backend as _};

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
struct Backend(Arc<dyn ibc::RuntimeBackend + Send + Sync>);

#[pymethods]
impl Backend {
    fn read_u64(&self, addr: PhysicalAddress) -> PyResult<u64> {
        self.0.read_value(addr.into()).convert_err()
    }

    fn virtual_to_physical(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> PyResult<u64> {
        let addr = self
            .0
            .virtual_to_physical(mmu_addr.into(), addr.into())
            .valid()
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
            self.0.read_memory(addr.into(), buf).convert_err()
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
    fn new(pid: i32) -> PyResult<(Self, Backend)> {
        #[cfg(target_os = "linux")]
        {
            let kvm = icebox::backends::kvm::Kvm::connect(pid).convert_err()?;
            Ok((Kvm, Backend(Arc::new(kvm))))
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
        let dump = icebox::backends::kvm_dump::DumbDump::read(path)?;
        Ok((Dump, Backend(Arc::new(dump))))
    }
}

#[pyclass]
struct RawOs(Box<dyn ibc::Os + Send + Sync>);

impl RawOs {
    fn new(backend: Backend, path: &str) -> IceResult<Self> {
        match icebox::os::Linux::quick_check(&backend.0) {
            Ok(true) => {
                let profile = icebox::os::linux::Profile::read_from_dir(path)?;
                let linux = icebox::os::Linux::create(backend.0, profile)?;
                return Ok(RawOs(Box::new(linux)));
            }
            Err(e) => log::warn!("Error while guessing OS: {}", e),
            Ok(false) => (),
        }

        Err(IceError::from("Failed to guess host OS"))
    }
}

#[pyclass(gc)]
struct Os(PyOwned<RawOs>);

impl Os {
    fn make_proc(&self, py: Python, proc: ibc::Process) -> Process {
        Process::new(py, proc, &self.0)
    }
}

#[pymethods]
impl Os {
    #[new]
    fn new(py: Python, backend: Backend, path: &str) -> PyResult<Self> {
        let raw = RawOs::new(backend, path).convert_err()?;
        Ok(Os(PyOwned::new(py, raw)?))
    }

    fn init_process(&self, py: Python) -> PyResult<Process> {
        let init = self.0.borrow(py)?.0.init_process().convert_err()?;
        Ok(self.make_proc(py, init))
    }

    fn current_thread(&self, py: Python, cpuid: usize) -> PyResult<Thread> {
        let thread = self.0.borrow(py)?.0.current_thread(cpuid).convert_err()?;
        Ok(Thread::new(py, thread, &self.0))
    }

    fn current_process(&self, py: Python, cpuid: usize) -> PyResult<Process> {
        let proc = self.0.borrow(py)?.0.current_process(cpuid).convert_err()?;
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
        let proc = os.0.find_process_by_pid(pid).convert_err()?;
        Ok(proc.map(|p| self.make_proc(py, p)))
    }
}

#[pyproto]
impl<'p> PyGCProtocol<'p> for Os {
    fn __traverse__(&'p self, visit: pyo3::PyVisit) -> Result<(), pyo3::PyTraverseError> {
        self.0.traverse(visit)
    }

    fn __clear__(&'p mut self) {
        self.0.clear()
    }
}

#[pyclass(gc)]
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
    #[getter]
    fn pid(&self, py: Python) -> PyResult<u64> {
        let os = self.os.borrow(py)?;
        let pid = os.0.process_pid(self.proc).convert_err()?;
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
        let path = os.0.process_exe(self.proc).convert_err()?;
        Ok(path
            .map(|path| os.0.path_to_string(path))
            .transpose()
            .convert_err()?)
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
        os.0.process_callstack(self.proc, &mut |frame| {
            let file = match frame.file {
                Some(file) => Some(os.0.path_to_string(file)?),
                None => None,
            };

            frames.push(StackFrame {
                frame: frame.clone(),
                file,
            });
            Ok(())
        })
        .convert_err()?;

        Ok(CallStackIter {
            frames: frames.into_iter(),
        })
    }
}

#[pyproto]
impl<'p> PyGCProtocol<'p> for Process {
    fn __traverse__(&'p self, visit: pyo3::PyVisit) -> Result<(), pyo3::PyTraverseError> {
        self.os.traverse(visit)
    }

    fn __clear__(&'p mut self) {
        self.os.clear()
    }
}

#[pyclass(gc)]
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
    #[getter]
    fn tid(&self, py: Python) -> PyResult<u64> {
        let os = self.os.borrow(py)?;
        let pid = os.0.thread_id(self.thread).convert_err()?;
        Ok(pid)
    }

    #[getter]
    fn name(&self, py: Python) -> PyResult<String> {
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

#[pyproto]
impl<'p> PyGCProtocol<'p> for Thread {
    fn __traverse__(&'p self, visit: pyo3::PyVisit) -> Result<(), pyo3::PyTraverseError> {
        self.os.traverse(visit)
    }

    fn __clear__(&'p mut self) {
        self.os.clear()
    }
}

#[pyclass(gc)]
struct Vma {
    vma: ibc::Vma,
    os: PyOwned<RawOs>,
}

impl Vma {
    fn new(py: Python, vma: ibc::Vma, os: &PyOwned<RawOs>) -> Self {
        Self {
            vma,
            os: os.clone_ref(py),
        }
    }
}

#[pymethods]
impl Vma {
    #[getter]
    fn start(&self, py: Python) -> PyResult<u64> {
        let os = self.os.borrow(py)?;
        let start = os.0.vma_start(self.vma).convert_err()?;
        Ok(start.0)
    }

    #[getter]
    fn end(&self, py: Python) -> PyResult<u64> {
        let os = self.os.borrow(py)?;
        let end = os.0.vma_end(self.vma).convert_err()?;
        Ok(end.0)
    }

    #[getter]
    fn file(&self, py: Python) -> PyResult<Option<String>> {
        let os = self.os.borrow(py)?;
        let path = os.0.vma_file(self.vma).convert_err()?;
        Ok(path
            .map(|path| os.0.path_to_string(path))
            .transpose()
            .convert_err()?)
    }
}

#[pyproto]
impl<'p> PyGCProtocol<'p> for Vma {
    fn __traverse__(&'p self, visit: pyo3::PyVisit) -> Result<(), pyo3::PyTraverseError> {
        self.os.traverse(visit)
    }

    fn __clear__(&'p mut self) {
        self.os.clear()
    }
}

#[pyclass]
struct StackFrame {
    frame: ibc::StackFrame,
    file: Option<String>,
}

#[pymethods]
impl StackFrame {
    #[getter]
    fn start(&self) -> Option<u64> {
        self.frame.range.map(|(start, _)| start.0)
    }

    #[getter]
    fn size(&self) -> Option<u64> {
        self.frame.range.map(|(_, size)| size)
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
    fn file(&self) -> Option<String> {
        self.file.clone()
    }
}

#[pyclass]
struct ProcessIter {
    procs: std::vec::IntoIter<ibc::Process>,
    os: PyOwned<RawOs>,
}

#[pyproto]
impl pyo3::PyIterProtocol for ProcessIter {
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

#[pyproto]
impl pyo3::PyIterProtocol for ThreadIter {
    fn __iter__(this: PyRef<Self>) -> PyRef<Self> {
        this
    }

    fn __next__(mut this: PyRefMut<Self>) -> PyResult<Option<Thread>> {
        let thread = this.threads.next();
        Ok(thread.map(|thread| Thread::new(this.py(), thread, &this.os)))
    }
}

#[pyclass]
struct VmaIter {
    vmas: std::vec::IntoIter<ibc::Vma>,
    os: PyOwned<RawOs>,
}

#[pyproto]
impl pyo3::PyIterProtocol for VmaIter {
    fn __iter__(this: PyRef<Self>) -> PyRef<Self> {
        this
    }

    fn __next__(mut this: PyRefMut<Self>) -> PyResult<Option<Vma>> {
        let vma = this.vmas.next();
        Ok(vma.map(|vma| Vma::new(this.py(), vma, &this.os)))
    }
}

#[pyclass]
struct CallStackIter {
    frames: std::vec::IntoIter<StackFrame>,
}

#[pyproto]
impl pyo3::PyIterProtocol for CallStackIter {
    fn __iter__(this: PyRef<Self>) -> PyRef<Self> {
        this
    }

    fn __next__(mut this: PyRefMut<Self>) -> Option<StackFrame> {
        this.frames.next()
    }
}

/// Python module for Icebox
#[pymodule]
fn icebox(py: Python, m: &PyModule) -> PyResult<()> {
    let logger = pyo3_log::Logger::new(py, pyo3_log::Caching::Loggers)?;
    if let Err(err) = logger.install() {
        log::error!("{}", err);
    }

    m.add_class::<Backend>()?;
    m.add_class::<Dump>()?;
    m.add_class::<Kvm>()?;

    m.add_class::<Os>()?;
    m.add_class::<Process>()?;

    Ok(())
}
