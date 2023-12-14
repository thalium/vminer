extern crate vminer_core as vmc;

use pyo3::{
    exceptions,
    prelude::*,
    sync::GILOnceCell,
    types::{PyBytes, PyInt, PyString},
};
use std::{convert::Infallible, ops::ControlFlow, sync::Arc};
use vmc::{ResultExt, VmError, VmResult};

pyo3::create_exception!(vminer, VminerError, pyo3::exceptions::PyException);

trait ToPyResult<T> {
    fn convert_err(self) -> PyResult<T>;
}

impl<T> ToPyResult<T> for VmResult<T> {
    fn convert_err(self) -> PyResult<T> {
        self.map_err(|err| VminerError::new_err(err.print_backtrace()))
    }
}

impl<T> ToPyResult<T> for vmc::MemoryAccessResult<T> {
    fn convert_err(self) -> PyResult<T> {
        self.map_err(|err| VminerError::new_err(err.to_string()))
    }
}

impl<T> ToPyResult<T> for vmc::TranslationResult<T> {
    fn convert_err(self) -> PyResult<T> {
        self.map_err(|err| VminerError::new_err(err.to_string()))
    }
}

impl<T> ToPyResult<T> for vmc::VcpuResult<T> {
    fn convert_err(self) -> PyResult<T> {
        self.map_err(|err| VminerError::new_err(err.to_string()))
    }
}

#[derive(pyo3::FromPyObject)]
struct VirtualAddress(u64);

impl From<VirtualAddress> for vmc::VirtualAddress {
    fn from(addr: VirtualAddress) -> Self {
        Self(addr.0)
    }
}

impl From<vmc::VirtualAddress> for VirtualAddress {
    fn from(addr: vmc::VirtualAddress) -> Self {
        Self(addr.0)
    }
}

impl<'py> pyo3::IntoPyObject<'py> for VirtualAddress {
    type Target = PyInt;
    type Output = Bound<'py, PyInt>;
    type Error = Infallible;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        self.0.into_pyobject(py)
    }
}

#[derive(pyo3::FromPyObject)]
struct PhysicalAddress(u64);

impl From<PhysicalAddress> for vmc::PhysicalAddress {
    fn from(addr: PhysicalAddress) -> Self {
        Self(addr.0)
    }
}

impl From<vmc::PhysicalAddress> for PhysicalAddress {
    fn from(addr: vmc::PhysicalAddress) -> Self {
        Self(addr.0)
    }
}

impl<'py> pyo3::IntoPyObject<'py> for PhysicalAddress {
    type Target = PyInt;
    type Output = Bound<'py, PyInt>;
    type Error = Infallible;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        self.0.into_pyobject(py)
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

enum BackendImpl {
    Rust(Arc<dyn vmc::Backend<Arch = vmc::arch::RuntimeArchitecture> + Send + Sync>),
    Python,
}

#[pyclass(subclass, frozen)]
struct Backend(BackendImpl);

impl Backend {
    fn with_backend<R>(
        this: PyRef<Self>,
        f: impl FnOnce(&dyn vmc::Backend<Arch = vmc::arch::RuntimeArchitecture>) -> R,
    ) -> R {
        match &this.0 {
            BackendImpl::Rust(b) => f(&**b),
            BackendImpl::Python => f(&PyBackend(this.into())),
        }
    }
}

#[pymethods]
impl Backend {
    #[new]
    fn new() -> Self {
        Self(BackendImpl::Python)
    }

    //     fn vcpu_count(&self) -> PyResult<u64> {
    //         Ok(self.0.vcpus_count() as u64)
    //     }

    //     fn instruction_pointer(&self, vcpu: usize) -> PyResult<VirtualAddress> {
    //         let ip = self
    //             .0
    //             .instruction_pointer(vmc::VcpuId(vcpu))
    //             .convert_err()?;
    //         Ok(ip.into())
    //     }

    //     fn mmu_addr(&self, vcpu: usize) -> PyResult<PhysicalAddress> {
    //         let ip = self.0.pgd(vmc::VcpuId(vcpu)).convert_err()?;
    //         Ok(ip.into())
    //     }

    fn arch<'py>(&self, py: Python<'py>) -> PyResult<&'py Bound<'py, PyString>> {
        let BackendImpl::Rust(b) = &self.0 else {
            return Err(VminerError::new_err("Missing \"arch\" implementation"));
        };

        Ok(match b.arch() {
            vmc::arch::RuntimeArchitecture::X86_64(_) => pyo3::intern!(py, "x86_64"),
            vmc::arch::RuntimeArchitecture::Aarch64(_) => pyo3::intern!(py, "aarch64"),
        })
    }

    fn virtual_to_physical(
        this: PyRef<'_, Self>,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> PyResult<u64> {
        Self::with_backend(this, |b| {
            let addr = b
                .virtual_to_physical(mmu_addr.into(), addr.into())
                .convert_err()?;
            Ok(addr.0)
        })
    }

    fn read_memory<'py>(
        this: PyRef<'py, Self>,
        py: Python<'py>,
        addr: PhysicalAddress,
        len: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        Self::with_backend(this, |b| {
            PyBytes::new_with(py, len, |buf| {
                b.read_physical(addr.into(), buf).convert_err()
            })
        })
    }

    fn read_virtual_memory<'py>(
        this: PyRef<'py, Self>,
        py: Python<'py>,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        len: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        Self::with_backend(this, |b| {
            PyBytes::new_with(py, len, |buf| {
                b.read_virtual_memory(mmu_addr.into(), addr.into(), buf)
                    .convert_err()
            })
        })
    }
}

struct PyBackend(Py<Backend>);

impl vmc::HasVcpus for PyBackend {
    type Arch = vmc::arch::RuntimeArchitecture;

    fn arch(&self) -> Self::Arch {
        pyo3::Python::with_gil(|py| {
            let res = self.0.call_method0(py, pyo3::intern!(py, "arch")).unwrap();
            let name = res.extract(py).unwrap();

            match name {
                "x86_64" => vmc::arch::RuntimeArchitecture::X86_64(vmc::arch::X86_64),
                "aarch64" => vmc::arch::RuntimeArchitecture::Aarch64(vmc::arch::Aarch64),
                _ => todo!(),
            }
        })
    }

    fn vcpus_count(&self) -> usize {
        pyo3::Python::with_gil(|py| {
            let res = self
                .0
                .call_method0(py, pyo3::intern!(py, "vcpus_count"))
                .unwrap();
            res.extract(py).unwrap()
        })
    }

    fn registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<<Self::Arch as vmc::Architecture>::Registers> {
        todo!()
    }

    fn special_registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<<Self::Arch as vmc::Architecture>::SpecialRegisters> {
        todo!()
    }

    fn other_registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<<Self::Arch as vmc::Architecture>::OtherRegisters> {
        todo!()
    }
}

impl vmc::Memory for PyBackend {
    fn memory_mappings(&self) -> &[vmc::mem::MemoryMap] {
        todo!()
    }

    fn read_physical(
        &self,
        addr: vmc::PhysicalAddress,
        buf: &mut [u8],
    ) -> vmc::MemoryAccessResult<()> {
        pyo3::Python::with_gil(|py| {
            let res = self
                .0
                .call_method1(
                    py,
                    pyo3::intern!(py, "read_physical_memory"),
                    (PhysicalAddress::from(addr), buf.len()),
                )
                .unwrap();

            let bytes = res.extract(py).unwrap();
            buf.copy_from_slice(bytes);

            Ok(())
        })
    }
}

impl vmc::Backend for PyBackend {}

#[pyclass(extends=Backend)]
struct Kvm;

#[pymethods]
impl Kvm {
    #[new]
    fn new(_pid: i32) -> PyResult<(Self, Backend)> {
        #[cfg(target_os = "linux")]
        {
            let kvm = vminer::backends::kvm::Kvm::connect(_pid).convert_err()?;
            Ok((
                Kvm,
                Backend(BackendImpl::Rust(Arc::new(vmc::RuntimeBackend(kvm)))),
            ))
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(VmError::from(
                "This backend is not available on your platform",
            ))
            .convert_err()
        }
    }
}

#[pyclass]
struct Vcpu {
    os: PyOwned<RawOs>,
    id: vmc::VcpuId,
}

impl Vcpu {
    fn new(py: Python, id: usize, os: &PyOwned<RawOs>) -> Self {
        Self {
            os: os.clone_ref(py),
            id: vmc::VcpuId(id),
        }
    }
}

#[pymethods]
impl Vcpu {
    #[getter]
    fn instruction_pointer(&self, py: Python) -> PyResult<VirtualAddress> {
        let os = self.os.borrow(py)?;
        let addr = os.0.instruction_pointer(self.id).convert_err()?;
        Ok(addr.into())
    }

    #[getter]
    fn stack_pointer(&self, py: Python) -> PyResult<VirtualAddress> {
        let os = self.os.borrow(py)?;
        let addr = os.0.stack_pointer(self.id).convert_err()?;
        Ok(addr.into())
    }

    fn __getattr__(&self, py: Python, name: &Bound<'_, PyString>) -> PyResult<u64> {
        let os = self.os.borrow(py)?;
        let name = name.to_str()?;

        os.0.register_by_name(self.id, name).convert_err()
    }
}

#[pyclass(extends = Backend)]
struct Dump;

#[pymethods]
impl Dump {
    #[new]
    fn new(path: &str) -> PyResult<(Self, Backend)> {
        let dump = vminer::backends::kvm_dump::DumbDump::read(path).convert_err()?;
        Ok((Dump, Backend(BackendImpl::Rust(Arc::new(dump)))))
    }
}

#[derive(Clone, Copy)]
enum RequestedOs {
    Linux,
    Windows,
}

#[pyclass]
struct RawOs(Box<dyn vmc::Os<Arch = vmc::arch::RuntimeArchitecture> + Send + Sync>);

impl RawOs {
    fn new(backend: Py<Backend>, path: Option<&str>, os: Option<RequestedOs>) -> VmResult<Self> {
        let backend = match &backend.get().0 {
            BackendImpl::Rust(b) => b.clone(),
            BackendImpl::Python => Arc::new(PyBackend(backend)),
        };

        let (mut builder, os) = Self::detect(&backend, os).context("failed to guess guest OS")?;

        if let Some(path) = path {
            let mut symbols = vmc::SymbolsIndexer::new();
            symbols.load_dir(path)?;
            builder = builder.with_symbols(symbols);
        }

        match os {
            RequestedOs::Linux => Ok(RawOs(Box::new(
                builder.build::<_, vminer::os::Linux<_>>(backend)?,
            ))),
            RequestedOs::Windows => Ok(RawOs(Box::new(
                builder.build::<_, vminer::os::Windows<_>>(backend)?,
            ))),
        }
    }

    fn detect(
        backend: &impl vmc::Backend,
        os: Option<RequestedOs>,
    ) -> Option<(vminer::os::OsBuilder, RequestedOs)> {
        use vminer::os::Buildable;

        if let Some(RequestedOs::Linux) | None = os {
            if let Some(builder) = vminer::os::Linux::quick_check(backend) {
                return Some((builder, RequestedOs::Linux));
            }
        }

        if let Some(RequestedOs::Windows) | None = os {
            if let Some(builder) = vminer::os::Windows::quick_check(backend) {
                return Some((builder, RequestedOs::Windows));
            }
        }

        None
    }
}

#[pyclass]
struct Os(PyOwned<RawOs>);

impl Os {
    fn make_proc(&self, py: Python, proc: vmc::Process) -> Process {
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
    #[pyo3(signature = (backend, path=None, kind=None))]
    fn new(
        py: Python,
        backend: Py<Backend>,
        path: Option<&str>,
        kind: Option<&str>,
    ) -> PyResult<Self> {
        let request = match kind {
            Some("linux") => Some(RequestedOs::Linux),
            Some("windows") => Some(RequestedOs::Windows),
            Some(_) => Err(VmError::new("Unknown OS")).convert_err()?,
            None => None,
        };
        let raw = RawOs::new(backend, path, request).convert_err()?;
        Ok(Os(PyOwned::new(py, raw)?))
    }

    fn vcpus(&self, py: Python) -> PyResult<VcpuIter> {
        let n = self.0.borrow(py)?.0.vcpus_count();
        Ok(VcpuIter {
            os: self.0.clone_ref(py),
            range: 0..n,
        })
    }

    fn init_process(&self, py: Python) -> PyResult<Process> {
        let init = self.0.borrow(py)?.0.init_process().convert_err()?;
        Ok(self.make_proc(py, init))
    }

    fn current_thread(&self, py: Python, vcpu: &Vcpu) -> PyResult<Thread> {
        let os = self.0.borrow(py)?;
        let thread = os.0.current_thread(vcpu.id).convert_err()?;
        Ok(Thread::new(py, thread, &self.0))
    }

    fn current_process(&self, py: Python, vcpu: &Vcpu) -> PyResult<Process> {
        let os = self.0.borrow(py)?;
        let proc = os.0.current_process(vcpu.id).convert_err()?;
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
    proc: vmc::Process,
    os: PyOwned<RawOs>,
}

impl Process {
    fn new(py: Python, proc: vmc::Process, os: &PyOwned<RawOs>) -> Self {
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
    thread: vmc::Thread,
    os: PyOwned<RawOs>,
}

impl Thread {
    fn new(py: Python, thread: vmc::Thread, os: &PyOwned<RawOs>) -> Self {
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
    fn new(py: Python, vma: vmc::Vma, os: &RawOs) -> VmResult<Self> {
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
    start: vmc::VirtualAddress,
    end: vmc::VirtualAddress,

    #[pyo3(get)]
    name: Py<PyString>,

    #[pyo3(get)]
    path: Py<PyString>,
}

impl Module {
    fn new(py: Python, module: vmc::Module, proc: vmc::Process, os: &RawOs) -> VmResult<Self> {
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
struct VcpuIter {
    os: PyOwned<RawOs>,
    range: std::ops::Range<usize>,
}

#[pymethods]
impl VcpuIter {
    fn __iter__(this: PyRef<Self>) -> PyRef<Self> {
        this
    }

    fn __next__(mut this: PyRefMut<Self>) -> PyResult<Option<Vcpu>> {
        let proc = this.range.next();
        Ok(proc.map(|id| Vcpu::new(this.py(), id, &this.os)))
    }
}

#[pyclass]
struct StackFrame {
    frame: vmc::StackFrame,

    os: PyOwned<RawOs>,
    proc: vmc::Process,
    module: GILOnceCell<Option<Py<Module>>>,
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

    #[pyo3(signature = (*, demangle=true))]
    fn symbol<'py>(&self, py: Python<'py>, demangle: bool) -> PyResult<Bound<'py, PyString>> {
        let os = &self.os.borrow(py)?;
        let mut s =
            os.0.format_stackframe_symbol(self.proc, &self.frame, demangle)
                .convert_err()?;

        if demangle {
            if let std::borrow::Cow::Owned(sym) = vmc::symbols::demangle(&s) {
                s = sym;
            }
        }

        Ok(PyString::new(py, &s))
    }
}

#[pyclass]
struct ProcessIter {
    procs: std::vec::IntoIter<vmc::Process>,
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
    threads: std::vec::IntoIter<vmc::Thread>,
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
    modules: std::vec::IntoIter<vmc::Module>,
    proc: vmc::Process,
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
    vmas: std::vec::IntoIter<vmc::Vma>,
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
    error: VmResult<()>,
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

/// Python module for vminer
#[pymodule]
#[pyo3(name = "vminer")]
fn vminer_module(py: Python, m: Bound<'_, PyModule>) -> PyResult<()> {
    let logger = pyo3_log::Logger::new(py, pyo3_log::Caching::Loggers)?;
    if let Err(err) = logger.install() {
        log::error!("{}", err);
    }
    // if let Err(err) = env_logger::try_init() {
    //     log::error!("{}", err);
    // }

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
