use crate::{
    arch, Architecture, GuestPhysAddr, GuestVirtAddr, IceResult, Memory, MemoryAccessResult,
    MemoryAccessResultExt,
};

pub trait Backend {
    type Arch: for<'a> Architecture<'a>;
    type Memory: Memory + ?Sized;

    #[inline]
    fn arch(&self) -> Self::Arch {
        use arch::Vcpus;

        self.vcpus().arch()
    }

    fn vcpus(&self) -> <Self::Arch as Architecture>::Vcpus;

    fn memory(&self) -> &Self::Memory;

    #[inline]
    fn read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.memory().read(addr, buf)
    }

    #[inline]
    fn read_value<T: bytemuck::Pod>(&self, addr: GuestPhysAddr) -> MemoryAccessResult<T> {
        let mut value = bytemuck::Zeroable::zeroed();
        self.read_memory(addr, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }

    #[inline]
    fn read_virtual_memory(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
        buf: &mut [u8],
    ) -> IceResult<()> {
        let addr = self.virtual_to_physical(mmu_addr, addr).valid()?;
        self.read_memory(addr, buf)?;
        Ok(())
    }

    #[inline]
    fn read_value_virtual<T: bytemuck::Pod>(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
    ) -> IceResult<T> {
        let mut value = bytemuck::Zeroable::zeroed();
        self.read_virtual_memory(mmu_addr, addr, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }

    #[inline]
    fn virtual_to_physical(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
    ) -> MemoryAccessResult<Option<GuestPhysAddr>> {
        self.arch()
            .virtual_to_physical(self.memory(), mmu_addr, addr)
    }

    #[inline]
    fn kernel_per_cpu(
        &self,
        cpuid: usize,
        check: impl Fn(GuestVirtAddr) -> bool,
    ) -> IceResult<GuestVirtAddr> {
        use arch::Vcpus;

        self.vcpus()
            .kernel_per_cpu(cpuid, check)
            .ok_or_else(|| "could not find per_cpu address".into())
    }

    #[inline]
    fn find_kernel_pgd(&self, test_addr: GuestVirtAddr) -> IceResult<GuestPhysAddr> {
        use arch::Vcpus;

        let test = |addr| matches!(self.virtual_to_physical(addr, test_addr), Ok(Some(_)));

        self.vcpus()
            .find_kernel_pgd(test)
            .ok_or_else(|| "could not find kernel page directory".into())
    }
}

trait RuntimeBackend {
    fn rt_arch(&self) -> arch::RuntimeArchitecture;

    fn rt_vcpus(&self) -> arch::runtime::Vcpus;

    fn rt_memory(&self) -> &(dyn Memory + 'static);

    fn rt_read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()>;

    fn rt_read_virtual_memory(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
        buf: &mut [u8],
    ) -> IceResult<()>;

    fn rt_virtual_to_physical(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
    ) -> MemoryAccessResult<Option<GuestPhysAddr>>;
}

impl<B> RuntimeBackend for B
where
    B: Backend,
    B::Memory: AsDynMemory,
{
    #[inline]
    fn rt_arch(&self) -> arch::RuntimeArchitecture {
        self.arch().into_runtime()
    }

    #[inline]
    fn rt_vcpus(&self) -> arch::runtime::Vcpus {
        use arch::Vcpus;

        self.vcpus().into_runtime()
    }

    #[inline]
    fn rt_memory(&self) -> &(dyn Memory + 'static) {
        self.memory().as_dyn()
    }

    #[inline]
    fn rt_read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.read_memory(addr, buf)
    }

    #[inline]
    fn rt_read_virtual_memory(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
        buf: &mut [u8],
    ) -> IceResult<()> {
        self.read_virtual_memory(mmu_addr, addr, buf)
    }

    #[inline]
    fn rt_virtual_to_physical(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
    ) -> MemoryAccessResult<Option<GuestPhysAddr>> {
        self.virtual_to_physical(mmu_addr, addr)
    }
}

impl Backend for dyn RuntimeBackend + '_ {
    type Arch = arch::runtime::Architecture;
    type Memory = dyn Memory;

    #[inline]
    fn arch(&self) -> Self::Arch {
        self.rt_arch()
    }

    #[inline]
    fn vcpus(&self) -> arch::runtime::Vcpus {
        self.rt_vcpus()
    }

    #[inline]
    fn memory(&self) -> &(dyn Memory + 'static) {
        self.rt_memory()
    }

    #[inline]
    fn read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.rt_read_memory(addr, buf)
    }

    #[inline]
    fn read_virtual_memory(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
        buf: &mut [u8],
    ) -> IceResult<()> {
        self.rt_read_virtual_memory(mmu_addr, addr, buf)
    }

    #[inline]
    fn virtual_to_physical(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
    ) -> MemoryAccessResult<Option<GuestPhysAddr>> {
        self.rt_virtual_to_physical(mmu_addr, addr)
    }
}

pub trait AsDynMemory {
    fn as_dyn(&self) -> &(dyn Memory + 'static);
}

impl<M: Memory + 'static> AsDynMemory for M {
    #[inline]
    fn as_dyn(&self) -> &(dyn Memory + 'static) {
        self
    }
}

impl AsDynMemory for dyn Memory + 'static {
    #[inline]
    fn as_dyn(&self) -> &(dyn Memory + 'static) {
        self
    }
}
