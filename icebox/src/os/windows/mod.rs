use ibc::{Backend, IceResult, PhysicalAddress, VirtualAddress};

#[derive(Debug)]
pub struct Windows<B> {
    backend: B,
    kpgd: PhysicalAddress,
}

impl<B: Backend> Windows<B> {
    pub fn create(backend: B) -> IceResult<Self> {
        let kpgd = backend.find_kernel_pgd(false, &[VirtualAddress(0xfffff78000000000)])?;
        Ok(Self { backend, kpgd })
    }
}

impl<B: Backend> ibc::Os for Windows<B> {
    fn init_process(&self) -> IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn current_thread(&self, _cpuid: usize) -> IceResult<ibc::Thread> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_is_kernel(&self, _proc: ibc::Process) -> IceResult<bool> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_pid(&self, _proc: ibc::Process) -> IceResult<u32> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_name(&self, _proc: ibc::Process) -> IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_pgd(&self, _proc: ibc::Process) -> IceResult<ibc::PhysicalAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_exe(&self, _proc: ibc::Process) -> IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_parent(&self, _proc: ibc::Process) -> IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_child(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Process) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_thread(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Thread) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn for_each_process(&self, _f: &mut dyn FnMut(ibc::Process) -> IceResult<()>) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_vma(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Vma) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_callstack(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<()>,
    ) -> IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn thread_process(&self, _thread: ibc::Thread) -> IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn thread_id(&self, _thread: ibc::Thread) -> IceResult<u32> {
        Err(ibc::IceError::unimplemented())
    }

    fn thread_name(&self, _thread: ibc::Thread) -> IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn path_to_string(&self, _path: ibc::Path) -> IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_file(&self, _vma: ibc::Vma) -> IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_start(&self, _vma: ibc::Vma) -> IceResult<VirtualAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_end(&self, _vma: ibc::Vma) -> IceResult<VirtualAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_flags(&self, _vma: ibc::Vma) -> IceResult<ibc::VmaFlags> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_offset(&self, _vma: ibc::Vma) -> IceResult<u64> {
        Err(ibc::IceError::unimplemented())
    }

    fn resolve_symbol(&self, _addr: VirtualAddress, _vma: ibc::Vma) -> IceResult<Option<&str>> {
        Err(ibc::IceError::unimplemented())
    }
}
