use crate::{arch, Architecture, GuestPhysAddr, GuestVirtAddr, Memory, MemoryAccessResult};

pub trait Backend {
    type Arch: for<'a> Architecture<'a>;
    type Memory: Memory + ?Sized;

    #[inline]
    fn arch(&self) -> Self::Arch {
        use arch::VcpusList;

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
        let mem = &self.memory();
        mem.read_value(addr)
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
}

trait RuntimeBackend {
    fn runtime_arch(&self) -> arch::RuntimeArchitecture;

    fn get_vcpus(&self) -> arch::runtime::Vcpus;

    fn runtime_memory(&self) -> &(dyn Memory + 'static);
}

impl<B> RuntimeBackend for B
where
    B: Backend,
    B::Memory: AsDynMemory,
{
    #[inline]
    fn runtime_arch(&self) -> arch::RuntimeArchitecture {
        self.arch().into_runtime()
    }

    #[inline]
    fn get_vcpus(&self) -> arch::runtime::Vcpus {
        use arch::VcpusList;

        self.vcpus().into_runtime()
    }

    #[inline]
    fn runtime_memory(&self) -> &(dyn Memory + 'static) {
        self.memory().as_dyn()
    }
}

impl Backend for dyn RuntimeBackend + '_ {
    type Arch = arch::runtime::Architecture;
    type Memory = dyn Memory;

    #[inline]
    fn vcpus(&self) -> arch::runtime::Vcpus {
        self.get_vcpus()
    }

    #[inline]
    fn memory(&self) -> &(dyn Memory + 'static) {
        self.runtime_memory()
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
