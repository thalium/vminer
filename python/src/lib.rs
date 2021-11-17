use std::sync::Arc;

use ibc::{GuestPhysAddr, GuestVirtAddr, IceError, IceResult, MemoryAccessResultExt};
use icebox::os::OsBuilder;
use pyo3::{exceptions, gc::PyGCProtocol, prelude::*};

use icebox_core::{self as ibc, Backend as _};

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
    fn read_u64(&self, addr: u64) -> PyResult<u64> {
        Ok(self.0.read_value(GuestPhysAddr(addr))?)
    }

    fn virtual_to_physical(&self, mmu_addr: GuestPhysAddr, addr: GuestVirtAddr) -> PyResult<u64> {
        let addr = self.0.virtual_to_physical(mmu_addr, addr).valid()?;
        Ok(addr.0)
    }
}

#[pyclass(extends=Backend)]
struct Kvm;

#[pymethods]
impl Kvm {
    #[new]
    fn new(pid: i32, mem_size: u64) -> PyResult<(Self, Backend)> {
        let kvm = icebox::backends::kvm::Kvm::connect(pid, mem_size)?;
        Ok((Kvm, Backend(Arc::new(kvm))))
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
    fn new(backend: Backend) -> IceResult<Self> {
        match icebox::os::Linux::quick_check(&backend.0) {
            Ok(true) => {
                let mut syms = ibc::SymbolsIndexer::new();
                let kallsyms = std::io::BufReader::new(std::fs::File::open("../kallsyms")?);
                icebox::os::linux::profile::parse_kallsyms(kallsyms, &mut syms)?;
                syms.read_object_file("../elf").unwrap();
                let profile = icebox::os::linux::Profile::new(syms)?;
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

#[pymethods]
impl Os {
    #[new]
    fn new(py: Python, backend: Backend) -> PyResult<Self> {
        let raw = RawOs::new(backend)?;
        Ok(Os(PyOwned::new(py, raw)?))
    }

    fn current_process(&self, py: Python, cpuid: usize) -> PyResult<Process> {
        let proc = self.0.borrow(py)?.0.current_process(cpuid)?;
        Ok(Process {
            proc,
            os: self.0.clone_ref(py),
        })
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

#[pymethods]
impl Process {
    #[getter]
    fn pid(&self, py: Python) -> PyResult<u32> {
        let os = self.os.borrow(py)?;
        let pid = os.0.process_pid(self.proc)?;
        Ok(pid)
    }

    #[getter]
    fn name(&self, py: Python) -> PyResult<String> {
        let os = self.os.borrow(py)?;
        let name = os.0.process_name(self.proc)?;
        Ok(name)
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

/// Python module for Icebox
#[pymodule]
fn icebox(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Backend>()?;
    m.add_class::<Dump>()?;
    m.add_class::<Kvm>()?;

    m.add_class::<Os>()?;
    m.add_class::<Process>()?;

    Ok(())
}
