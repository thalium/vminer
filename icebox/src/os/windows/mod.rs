use ibc::Backend;

pub struct Windows<B> {
    backend: B,
}

impl<B: Backend> Windows<B> {
    pub fn create(backend: B) -> Self {
        Self { backend }
    }
}

impl<B: Backend> ibc::Os for Windows<B> {
    fn init_process(&self) -> ibc::IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn current_thread(&self, _cpuid: usize) -> ibc::IceResult<ibc::Thread> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_is_kernel(&self, _proc: ibc::Process) -> ibc::IceResult<bool> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_pid(&self, _proc: ibc::Process) -> ibc::IceResult<u32> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_name(&self, _proc: ibc::Process) -> ibc::IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_pgd(&self, _proc: ibc::Process) -> ibc::IceResult<ibc::PhysicalAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_exe(&self, _proc: ibc::Process) -> ibc::IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_parent(&self, _proc: ibc::Process) -> ibc::IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_child(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Process) -> ibc::IceResult<()>,
    ) -> ibc::IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_thread(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Thread) -> ibc::IceResult<()>,
    ) -> ibc::IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn for_each_process(
        &self,
        _f: &mut dyn FnMut(ibc::Process) -> ibc::IceResult<()>,
    ) -> ibc::IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_for_each_vma(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(ibc::Vma) -> ibc::IceResult<()>,
    ) -> ibc::IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn process_callstack(
        &self,
        _proc: ibc::Process,
        _f: &mut dyn FnMut(&ibc::StackFrame) -> ibc::IceResult<()>,
    ) -> ibc::IceResult<()> {
        Err(ibc::IceError::unimplemented())
    }

    fn thread_process(&self, _thread: ibc::Thread) -> ibc::IceResult<ibc::Process> {
        Err(ibc::IceError::unimplemented())
    }

    fn thread_id(&self, _thread: ibc::Thread) -> ibc::IceResult<u32> {
        Err(ibc::IceError::unimplemented())
    }

    fn thread_name(&self, _thread: ibc::Thread) -> ibc::IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn path_to_string(&self, _path: ibc::Path) -> ibc::IceResult<String> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_file(&self, _vma: ibc::Vma) -> ibc::IceResult<Option<ibc::Path>> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_start(&self, _vma: ibc::Vma) -> ibc::IceResult<ibc::VirtualAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_end(&self, _vma: ibc::Vma) -> ibc::IceResult<ibc::VirtualAddress> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_flags(&self, _vma: ibc::Vma) -> ibc::IceResult<ibc::VmaFlags> {
        Err(ibc::IceError::unimplemented())
    }

    fn vma_offset(&self, _vma: ibc::Vma) -> ibc::IceResult<u64> {
        Err(ibc::IceError::unimplemented())
    }

    fn resolve_symbol(
        &self,
        _addr: ibc::VirtualAddress,
        _vma: ibc::Vma,
    ) -> ibc::IceResult<Option<&str>> {
        Err(ibc::IceError::unimplemented())
    }
}
