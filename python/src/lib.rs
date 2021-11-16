use ibc::{GuestPhysAddr, GuestVirtAddr, MemoryAccessResultExt};
use pyo3::prelude::*;

use icebox_core::{self as ibc, Backend as _};

#[pyclass(subclass)]
struct Backend(Box<dyn ibc::RuntimeBackend + Send + Sync>);

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
        Ok((Kvm, Backend(Box::new(kvm))))
    }
}

#[pyclass(extends=Backend)]
struct Dump;

#[pymethods]
impl Dump {
    #[new]
    fn new(path: &str) -> PyResult<(Self, Backend)> {
        let dump = icebox::backends::kvm_dump::DumbDump::read(path)?;
        Ok((Dump, Backend(Box::new(dump))))
    }
}

/// Python module for Icebox
#[pymodule]
fn icebox(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<Backend>()?;
    m.add_class::<Dump>()?;
    m.add_class::<Kvm>()?;
    Ok(())
}
