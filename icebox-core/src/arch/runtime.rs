use crate::arch;

#[derive(Debug, Clone, Copy)]
pub enum Architecture {
    X86_64(arch::X86_64),
    Aarch64(arch::Aarch64),
}

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
}

pub enum Vcpus<'a> {
    X86_64(&'a [arch::x86_64::Vcpu]),
    Aarch64(&'a [arch::aarch64::Vcpu]),
}

impl<'a> arch::VcpusList<'a> for Vcpus<'a> {
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
    fn into_runtime(self) -> Vcpus<'a> {
        self
    }
}

#[derive(Clone, Copy)]
pub enum Registers {
    X86_64(arch::x86_64::Registers),
    Aarch64(arch::aarch64::Registers),
}

impl<'a> arch::Architecture<'a> for Architecture {
    type Registers = Registers;
    type Vcpu = Vcpu<'a>;
    type Vcpus = Vcpus<'a>;

    #[inline]
    fn into_runtime(self) -> Architecture {
        self
    }

    #[inline]
    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: crate::GuestPhysAddr,
        addr: crate::GuestVirtAddr,
    ) -> crate::MemoryAccessResult<Option<crate::GuestPhysAddr>> {
        match self {
            Self::X86_64(arch) => arch.virtual_to_physical(memory, mmu_addr, addr),
            Self::Aarch64(arch) => arch.virtual_to_physical(memory, mmu_addr, addr),
        }
    }
}
