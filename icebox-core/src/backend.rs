use crate::{
    arch, mem::MemoryMap, Architecture, IceResult, Memory, MemoryAccessResult, PhysicalAddress,
    TranslationResult, VirtualAddress,
};

pub trait RawBackend {
    type Arch: for<'a> Architecture<'a>;
    type Memory: Memory + ?Sized;

    #[inline]
    fn arch(&self) -> Self::Arch {
        use arch::Vcpus;

        self.vcpus().arch()
    }

    fn vcpus(&self) -> <Self::Arch as Architecture>::Vcpus;

    fn memory(&self) -> &Self::Memory;
}

pub trait Backend {
    type Arch: for<'a> Architecture<'a>;

    #[inline]
    fn arch(&self) -> Self::Arch {
        use arch::Vcpus;

        self.vcpus().arch()
    }

    fn vcpus(&self) -> <Self::Arch as Architecture>::Vcpus;

    fn memory_mappings(&self) -> &[MemoryMap];

    fn read_memory(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()>;

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
    ) -> TranslationResult<T>
    where
        Self: Sized,
    {
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
            .virtual_to_physical(&BackendMemory(self), mmu_addr, addr)
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
            .find_kernel_pgd(&BackendMemory(self), use_per_cpu, additionnal)
            .ok_or_else(|| "could not find kernel page directory".into())
    }

    #[inline]
    fn find_in_kernel_memory(
        &self,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> MemoryAccessResult<Option<VirtualAddress>> {
        self.arch()
            .find_in_kernel_memory(&BackendMemory(self), mmu_addr, needle)
    }

    #[inline]
    fn iter_in_kernel_memory<'a, 'b>(
        &'a self,
        mmu_addr: PhysicalAddress,
        needle: &'b [u8],
    ) -> KernelSearchIterator<'a, 'b, Self>
    where
        Self: Sized,
    {
        KernelSearchIterator {
            backend: self,
            mmu_addr,
            finder: memchr::memmem::Finder::new(needle),
            base_search_addr: self.arch().kernel_base(),
            buffer: alloc::vec![0; (2 << 20) + needle.len()],
        }
    }
}

impl<B: RawBackend> Backend for B {
    type Arch = B::Arch;

    #[inline]
    fn arch(&self) -> Self::Arch {
        self.arch()
    }

    #[inline]
    fn vcpus(&self) -> <Self::Arch as Architecture>::Vcpus {
        self.vcpus()
    }

    #[inline]
    fn memory_mappings(&self) -> &[MemoryMap] {
        self.memory().mappings()
    }

    #[inline]
    fn read_memory(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.memory().read(addr, buf)
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
}

impl<B: Backend + ?Sized> Backend for alloc::sync::Arc<B> {
    type Arch = B::Arch;

    #[inline]
    fn arch(&self) -> Self::Arch {
        (**self).arch()
    }

    #[inline]
    fn vcpus(&self) -> <Self::Arch as Architecture>::Vcpus {
        (**self).vcpus()
    }

    #[inline]
    fn memory_mappings(&self) -> &[MemoryMap] {
        (**self).memory_mappings()
    }

    #[inline]
    fn read_memory(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        (**self).read_memory(addr, buf)
    }

    #[inline]
    fn read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> TranslationResult<()> {
        (**self).read_virtual_memory(mmu_addr, addr, buf)
    }

    #[inline]
    fn virtual_to_physical(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> TranslationResult<PhysicalAddress> {
        (**self).virtual_to_physical(mmu_addr, addr)
    }

    #[inline]
    fn kernel_per_cpu(&self, cpuid: usize) -> IceResult<VirtualAddress> {
        (**self).kernel_per_cpu(cpuid)
    }

    #[inline]
    fn find_kernel_pgd(
        &self,
        use_per_cpu: bool,
        additionnal: &[VirtualAddress],
    ) -> IceResult<PhysicalAddress> {
        (**self).find_kernel_pgd(use_per_cpu, additionnal)
    }

    #[inline]
    fn find_in_kernel_memory(
        &self,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> MemoryAccessResult<Option<VirtualAddress>> {
        (**self).find_in_kernel_memory(mmu_addr, needle)
    }
}

#[derive(Debug)]
pub struct RuntimeBackend<B>(pub B);

impl<B: Backend> Backend for RuntimeBackend<B> {
    type Arch = arch::runtime::Architecture;

    #[inline]
    fn arch(&self) -> Self::Arch {
        self.0.arch().into_runtime()
    }

    #[inline]
    fn vcpus(&self) -> arch::runtime::Vcpus {
        use arch::Vcpus;

        self.0.vcpus().into_runtime()
    }

    #[inline]
    fn memory_mappings(&self) -> &[MemoryMap] {
        self.0.memory_mappings()
    }

    #[inline]
    fn read_memory(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.0.read_memory(addr, buf)
    }

    #[inline]
    fn read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> TranslationResult<()> {
        self.0.read_virtual_memory(mmu_addr, addr, buf)
    }

    #[inline]
    fn read_value_virtual<T: bytemuck::Pod>(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> TranslationResult<T> {
        self.0.read_value_virtual(mmu_addr, addr)
    }

    #[inline]
    fn virtual_to_physical(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> TranslationResult<PhysicalAddress> {
        self.0.virtual_to_physical(mmu_addr, addr)
    }

    #[inline]
    fn kernel_per_cpu(&self, cpuid: usize) -> IceResult<VirtualAddress> {
        self.0.kernel_per_cpu(cpuid)
    }

    #[inline]
    fn find_kernel_pgd(
        &self,
        use_per_cpu: bool,
        additionnal: &[VirtualAddress],
    ) -> IceResult<PhysicalAddress> {
        self.0.find_kernel_pgd(use_per_cpu, additionnal)
    }

    #[inline]
    fn find_in_kernel_memory(
        &self,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> MemoryAccessResult<Option<VirtualAddress>> {
        self.0.find_in_kernel_memory(mmu_addr, needle)
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
                &BackendMemory(self.backend),
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

struct BackendMemory<'a, B: Backend + ?Sized>(&'a B);

impl<B: Backend + ?Sized> Memory for BackendMemory<'_, B> {
    #[inline]
    fn mappings(&self) -> &[MemoryMap] {
        self.0.memory_mappings()
    }

    #[inline]
    fn read(&self, addr: PhysicalAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.0.read_memory(addr, buf)
    }
}
