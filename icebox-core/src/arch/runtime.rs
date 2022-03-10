use crate::{arch, Endianness, PhysicalAddress, RuntimeEndian, VirtualAddress};

#[derive(Debug, Clone, Copy)]
pub enum Architecture {
    X86_64(arch::X86_64),
    Aarch64(arch::Aarch64),
}

#[derive(Debug, Clone, Copy)]
pub enum Vcpu<'a> {
    X86_64(&'a arch::x86_64::Vcpu),
    Aarch64(&'a arch::aarch64::Vcpu),
}

impl<'a> arch::Vcpu<'a> for Vcpu<'a> {
    type Arch = Architecture;

    #[inline]
    fn arch(&self) -> Architecture {
        match self {
            Self::X86_64(vcpu) => Architecture::X86_64(vcpu.arch()),
            Self::Aarch64(vcpu) => Architecture::Aarch64(vcpu.arch()),
        }
    }

    #[inline]
    fn get_regs(&self) -> Registers {
        match self {
            Vcpu::X86_64(vcpu) => Registers::X86_64(vcpu.get_regs()),
            Vcpu::Aarch64(vcpu) => Registers::Aarch64(vcpu.get_regs()),
        }
    }

    #[inline]
    fn into_runtime(self) -> Vcpu<'a> {
        self
    }

    #[inline]
    fn instruction_pointer(&self) -> VirtualAddress {
        match self {
            Vcpu::X86_64(vcpu) => vcpu.instruction_pointer(),
            Vcpu::Aarch64(vcpu) => vcpu.instruction_pointer(),
        }
    }

    #[inline]
    fn stack_pointer(&self) -> VirtualAddress {
        match self {
            Vcpu::X86_64(vcpu) => vcpu.stack_pointer(),
            Vcpu::Aarch64(vcpu) => vcpu.stack_pointer(),
        }
    }

    #[inline]
    fn base_pointer(&self) -> Option<VirtualAddress> {
        match self {
            Vcpu::X86_64(vcpu) => vcpu.base_pointer(),
            Vcpu::Aarch64(vcpu) => vcpu.base_pointer(),
        }
    }

    fn pgd(&self) -> PhysicalAddress {
        match self {
            Vcpu::X86_64(vcpu) => vcpu.pgd(),
            Vcpu::Aarch64(vcpu) => vcpu.pgd(),
        }
    }

    #[inline]
    fn kernel_per_cpu(&self) -> Option<VirtualAddress> {
        match self {
            Self::X86_64(vcpu) => vcpu.kernel_per_cpu(),
            Self::Aarch64(vcpu) => vcpu.kernel_per_cpu(),
        }
    }
}

impl<'a> Vcpu<'a> {
    #[inline]
    pub const fn as_x86_64(&self) -> Option<&'a arch::x86_64::Vcpu> {
        match self {
            Self::X86_64(vcpu) => Some(vcpu),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_aarch64(&self) -> Option<&'a arch::aarch64::Vcpu> {
        match self {
            Self::Aarch64(vcpu) => Some(vcpu),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Vcpus<'a> {
    X86_64(&'a [arch::x86_64::Vcpu]),
    Aarch64(&'a [arch::aarch64::Vcpu]),
}

impl<'a> arch::Vcpus<'a> for Vcpus<'a> {
    type Arch = Architecture;

    #[inline]
    fn arch(&self) -> Architecture {
        match self {
            Self::X86_64(vcpus) => Architecture::X86_64(vcpus.arch()),
            Self::Aarch64(vcpus) => Architecture::Aarch64(vcpus.arch()),
        }
    }

    #[inline]
    fn count(&self) -> usize {
        match self {
            Self::X86_64(vcpus) => vcpus.len(),
            Self::Aarch64(vcpus) => vcpus.len(),
        }
    }

    #[inline]
    fn get(&self, id: usize) -> Vcpu<'a> {
        match self {
            Self::X86_64(vcpus) => Vcpu::X86_64(vcpus.get(id)),
            Self::Aarch64(vcpus) => Vcpu::Aarch64(vcpus.get(id)),
        }
    }

    #[inline]
    fn find_kernel_pgd<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        use_per_cpu: bool,
        additionnal: &[VirtualAddress],
    ) -> Option<PhysicalAddress> {
        match self {
            Self::X86_64(vcpus) => vcpus.find_kernel_pgd(memory, use_per_cpu, additionnal),
            Self::Aarch64(vcpus) => vcpus.find_kernel_pgd(memory, use_per_cpu, additionnal),
        }
    }

    #[inline]
    fn into_runtime(self) -> Vcpus<'a> {
        self
    }
}

impl<'a> Vcpus<'a> {
    #[inline]
    pub const fn as_x86_64(&self) -> Option<&'a [arch::x86_64::Vcpu]> {
        match self {
            Self::X86_64(vcpus) => Some(vcpus),
            _ => None,
        }
    }

    #[inline]
    pub const fn as_aarch64(&self) -> Option<&'a [arch::aarch64::Vcpu]> {
        match self {
            Self::Aarch64(vcpus) => Some(vcpus),
            _ => None,
        }
    }
}

#[derive(Debug)]
enum VcpuIterInner<'a> {
    X86_64(core::slice::Iter<'a, arch::x86_64::Vcpu>),
    Aarch64(core::slice::Iter<'a, arch::aarch64::Vcpu>),
}

#[derive(Debug)]
pub struct VcpuIter<'a>(VcpuIterInner<'a>);

impl<'a> Iterator for VcpuIter<'a> {
    type Item = Vcpu<'a>;

    fn next(&mut self) -> Option<Vcpu<'a>> {
        match &mut self.0 {
            VcpuIterInner::X86_64(iter) => iter.next().map(Vcpu::X86_64),
            VcpuIterInner::Aarch64(iter) => iter.next().map(Vcpu::Aarch64),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        match &self.0 {
            VcpuIterInner::X86_64(iter) => iter.size_hint(),
            VcpuIterInner::Aarch64(iter) => iter.size_hint(),
        }
    }

    fn fold<B, F>(self, init: B, mut f: F) -> B
    where
        Self: Sized,
        F: FnMut(B, Self::Item) -> B,
    {
        match self.0 {
            VcpuIterInner::X86_64(iter) => iter.fold(init, |acc, vcpu| f(acc, Vcpu::X86_64(vcpu))),
            VcpuIterInner::Aarch64(iter) => {
                iter.fold(init, |acc, vcpu| f(acc, Vcpu::Aarch64(vcpu)))
            }
        }
    }
}

impl<'a> ExactSizeIterator for VcpuIter<'a> {}

impl<'a> IntoIterator for Vcpus<'a> {
    type Item = Vcpu<'a>;
    type IntoIter = VcpuIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        let inner = match self {
            Self::X86_64(vcpus) => VcpuIterInner::X86_64(vcpus.iter()),
            Self::Aarch64(vcpus) => VcpuIterInner::Aarch64(vcpus.iter()),
        };

        VcpuIter(inner)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Registers {
    X86_64(arch::x86_64::Registers),
    Aarch64(arch::aarch64::Registers),
}

impl<'a> arch::Architecture<'a> for Architecture {
    type Registers = Registers;
    type Vcpu = Vcpu<'a>;
    type Vcpus = Vcpus<'a>;
    type Endian = RuntimeEndian;

    #[inline]
    fn into_runtime(self) -> Architecture {
        self
    }

    #[inline]
    fn endianness(&self) -> RuntimeEndian {
        match self {
            Architecture::X86_64(arch) => arch.endianness().as_runtime_endian(),
            Architecture::Aarch64(arch) => arch.endianness().as_runtime_endian(),
        }
    }

    #[inline]
    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> crate::MemoryAccessResult<Option<PhysicalAddress>> {
        match self {
            Self::X86_64(arch) => arch.virtual_to_physical(memory, mmu_addr, addr),
            Self::Aarch64(arch) => arch.virtual_to_physical(memory, mmu_addr, addr),
        }
    }

    fn find_in_kernel_memory<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> crate::MemoryAccessResult<Option<VirtualAddress>> {
        match self {
            Self::X86_64(arch) => arch.find_in_kernel_memory(memory, mmu_addr, needle),
            Self::Aarch64(arch) => arch.find_in_kernel_memory(memory, mmu_addr, needle),
        }
    }

    fn find_in_kernel_memory_raw<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        base_search_addr: VirtualAddress,
        finder: &memchr::memmem::Finder,
        buf: &mut [u8],
    ) -> crate::MemoryAccessResult<Option<VirtualAddress>> {
        match self {
            Self::X86_64(arch) => {
                arch.find_in_kernel_memory_raw(memory, mmu_addr, base_search_addr, finder, buf)
            }
            Self::Aarch64(arch) => {
                arch.find_in_kernel_memory_raw(memory, mmu_addr, base_search_addr, finder, buf)
            }
        }
    }

    fn kernel_base(&self) -> VirtualAddress {
        match self {
            Self::X86_64(arch) => arch.kernel_base(),
            Self::Aarch64(arch) => arch.kernel_base(),
        }
    }
}
