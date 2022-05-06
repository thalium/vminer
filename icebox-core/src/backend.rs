use crate::{
    arch, Architecture, IceResult, Memory, MemoryAccessResult, PhysicalAddress, TranslationResult,
    VirtualAddress,
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
    fn read_memory(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.memory().read(addr, buf)
    }

    #[inline]
    fn read_value<T: bytemuck::Pod>(&self, addr: PhysicalAddress) -> MemoryAccessResult<T> {
        let mut value = bytemuck::Zeroable::zeroed();
        self.read_memory(addr, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }

    #[inline]
    fn read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> TranslationResult<()> {
        let addr = self.virtual_to_physical(mmu_addr, addr)?;
        self.read_memory(addr, buf)?;
        Ok(())
    }

    #[inline]
    fn read_value_virtual<T: bytemuck::Pod>(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> TranslationResult<T> {
        let mut value = bytemuck::Zeroable::zeroed();
        self.read_virtual_memory(mmu_addr, addr, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }

    #[inline]
    fn virtual_to_physical(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> TranslationResult<PhysicalAddress> {
        self.arch()
            .virtual_to_physical(self.memory(), mmu_addr, addr)
    }

    #[inline]
    fn kernel_per_cpu(&self, cpuid: usize) -> IceResult<VirtualAddress> {
        use arch::Vcpus;

        self.vcpus()
            .kernel_per_cpu(cpuid)
            .ok_or_else(|| "could not find per_cpu address".into())
    }

    #[inline]
    fn find_kernel_pgd(
        &self,
        use_per_cpu: bool,
        additionnal: &[VirtualAddress],
    ) -> IceResult<PhysicalAddress> {
        use arch::Vcpus;

        self.vcpus()
            .find_kernel_pgd(self.memory(), use_per_cpu, additionnal)
            .ok_or_else(|| "could not find kernel page directory".into())
    }

    #[inline]
    fn find_in_kernel_memory(
        &self,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> MemoryAccessResult<Option<VirtualAddress>> {
        self.arch()
            .find_in_kernel_memory(self.memory(), mmu_addr, needle)
    }

    #[inline]
    fn iter_in_kernel_memory<'a, 'b>(
        &'a self,
        mmu_addr: PhysicalAddress,
        needle: &'b [u8],
    ) -> KernelSearchIterator<'a, 'b, Self> {
        KernelSearchIterator {
            backend: self,
            mmu_addr,
            finder: memchr::memmem::Finder::new(needle),
            base_search_addr: self.arch().kernel_base(),
            buffer: alloc::vec![0; (2 << 20) + needle.len()],
        }
    }
}

impl<B: Backend + ?Sized> Backend for alloc::sync::Arc<B> {
    type Arch = B::Arch;
    type Memory = B::Memory;

    fn arch(&self) -> Self::Arch {
        (**self).arch()
    }

    fn vcpus(&self) -> <Self::Arch as Architecture>::Vcpus {
        (**self).vcpus()
    }

    fn memory(&self) -> &Self::Memory {
        (**self).memory()
    }

    fn read_memory(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (**self).read_memory(addr, buf)
    }

    fn read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> TranslationResult<()> {
        (**self).read_virtual_memory(mmu_addr, addr, buf)
    }

    fn virtual_to_physical(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> TranslationResult<PhysicalAddress> {
        (**self).virtual_to_physical(mmu_addr, addr)
    }

    fn kernel_per_cpu(&self, cpuid: usize) -> IceResult<VirtualAddress> {
        (**self).kernel_per_cpu(cpuid)
    }

    fn find_kernel_pgd(
        &self,
        use_per_cpu: bool,
        additionnal: &[VirtualAddress],
    ) -> IceResult<PhysicalAddress> {
        (**self).find_kernel_pgd(use_per_cpu, additionnal)
    }
}

pub trait RuntimeBackend {
    fn rt_arch(&self) -> arch::RuntimeArchitecture;

    fn rt_vcpus(&self) -> arch::runtime::Vcpus;

    fn rt_memory(&self) -> &(dyn Memory + 'static);

    fn rt_read_memory(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()>;

    fn rt_read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> TranslationResult<()>;

    fn rt_virtual_to_physical(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> TranslationResult<PhysicalAddress>;
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
    fn rt_read_memory(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.read_memory(addr, buf)
    }

    #[inline]
    fn rt_read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> TranslationResult<()> {
        self.read_virtual_memory(mmu_addr, addr, buf)
    }

    #[inline]
    fn rt_virtual_to_physical(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> TranslationResult<PhysicalAddress> {
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
    fn read_memory(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.rt_read_memory(addr, buf)
    }

    #[inline]
    fn read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> TranslationResult<()> {
        self.rt_read_virtual_memory(mmu_addr, addr, buf)
    }

    #[inline]
    fn virtual_to_physical(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> TranslationResult<PhysicalAddress> {
        self.rt_virtual_to_physical(mmu_addr, addr)
    }
}

impl Backend for dyn RuntimeBackend + Send + Sync + '_ {
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
    fn read_memory(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.rt_read_memory(addr, buf)
    }

    #[inline]
    fn virtual_to_physical(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> TranslationResult<PhysicalAddress> {
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

#[derive(Debug)]
pub struct KernelSearchIterator<'a, 'b, B: ?Sized> {
    backend: &'a B,
    finder: memchr::memmem::Finder<'b>,
    buffer: alloc::vec::Vec<u8>,
    mmu_addr: PhysicalAddress,
    base_search_addr: VirtualAddress,
}

impl<B: Backend + ?Sized> Iterator for KernelSearchIterator<'_, '_, B> {
    type Item = IceResult<VirtualAddress>;

    fn next(&mut self) -> Option<IceResult<VirtualAddress>> {
        let result = self
            .backend
            .arch()
            .find_in_kernel_memory_raw(
                self.backend.memory(),
                self.mmu_addr,
                self.base_search_addr,
                &self.finder,
                &mut self.buffer,
            )
            .transpose()?;

        Some(match result {
            Ok(addr) => {
                self.base_search_addr = addr + 1u64;
                Ok(addr)
            }
            Err(err) => {
                self.base_search_addr += 1u64;
                Err(err.into())
            }
        })
    }
}
