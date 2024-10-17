use crate::{arch, endian::RuntimeEndian, Endianness, HasVcpus, PhysicalAddress, VirtualAddress};

#[derive(Debug, Clone, Copy)]
pub enum Architecture {
    X86_64(arch::X86_64),
    Aarch64(arch::Aarch64),
}

#[derive(Debug, Clone, Copy)]
pub enum Registers {
    X86_64(arch::x86_64::Registers),
    Aarch64(arch::aarch64::Registers),
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Copy)]
pub enum SpecialRegisters {
    X86_64(arch::x86_64::SpecialRegisters),
    Aarch64(arch::aarch64::SpecialRegisters),
}

#[derive(Debug, Clone, Copy)]
pub enum OtherRegisters {
    X86_64(arch::x86_64::OtherRegisters),
    Aarch64(arch::aarch64::OtherRegisters),
}

macro_rules! dispatch {
    ($val:expr => |$arch:ident| $expr:expr) => {
        match $val {
            Architecture::X86_64($arch) => $expr,
            Architecture::Aarch64($arch) => $expr,
        }
    };
    ($val:expr, $vcpus:ident => |$arch:ident| $expr:expr) => {
        match $val {
            Architecture::X86_64($arch) => {
                let $vcpus = &super::AssumeX86_64($vcpus);
                $expr
            }
            Architecture::Aarch64($arch) => {
                let $vcpus = &super::AssumeAarch64($vcpus);
                $expr
            }
        }
    };
}

impl arch::Architecture for Architecture {
    type Endian = RuntimeEndian;

    type Registers = Registers;
    type SpecialRegisters = SpecialRegisters;
    type OtherRegisters = OtherRegisters;

    #[inline]
    fn into_runtime(self) -> Architecture {
        self
    }

    #[inline]
    fn endianness(&self) -> RuntimeEndian {
        dispatch!(self => |arch|arch.endianness().as_runtime_endian())
    }

    #[inline]
    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> crate::TranslationResult<PhysicalAddress> {
        dispatch!(self => |arch| arch.virtual_to_physical(memory, mmu_addr, addr))
    }

    #[inline]
    fn find_kernel_pgd<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        vcpus: &(impl HasVcpus<Arch = Self> + ?Sized),
        use_per_cpu: bool,
        additional: &[VirtualAddress],
    ) -> crate::VmResult<Option<PhysicalAddress>> {
        dispatch!(self, vcpus => |arch| arch.find_kernel_pgd(memory, vcpus, use_per_cpu, additional))
    }

    #[inline]
    fn find_in_kernel_memory_raw<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        base_search_addr: VirtualAddress,
        finder: &memchr::memmem::Finder,
        buf: &mut [u8],
    ) -> crate::MemoryAccessResult<Option<VirtualAddress>> {
        dispatch!(self => |arch| arch.find_in_kernel_memory_raw(memory, mmu_addr, base_search_addr, finder, buf))
    }

    #[inline]
    fn find_in_kernel_memory<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> crate::MemoryAccessResult<Option<VirtualAddress>> {
        dispatch!(self => |arch| arch.find_in_kernel_memory(memory, mmu_addr, needle))
    }

    #[inline]
    fn kernel_base(&self) -> VirtualAddress {
        dispatch!(self => |arch| arch.kernel_base())
    }

    #[inline]
    fn instruction_pointer<Vcpus: HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> crate::VcpuResult<VirtualAddress> {
        dispatch!(self, vcpus => |arch| arch.instruction_pointer(vcpus, vcpu))
    }

    #[inline]
    fn stack_pointer<Vcpus: HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> crate::VcpuResult<VirtualAddress> {
        dispatch!(self, vcpus => |arch| arch.stack_pointer(vcpus, vcpu))
    }

    #[inline]
    fn base_pointer<Vcpus: HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> crate::VcpuResult<Option<VirtualAddress>> {
        dispatch!(self, vcpus => |arch| arch.base_pointer(vcpus, vcpu))
    }

    #[inline]
    fn pgd<Vcpus: HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> crate::VcpuResult<PhysicalAddress> {
        dispatch!(self, vcpus => |arch| arch.pgd(vcpus, vcpu))
    }

    #[inline]
    fn kernel_per_cpu<Vcpus: HasVcpus<Arch = Self> + ?Sized>(
        &self,
        vcpus: &Vcpus,
        vcpu: crate::VcpuId,
    ) -> crate::VcpuResult<Option<VirtualAddress>> {
        dispatch!(self, vcpus => |arch| arch.kernel_per_cpu(vcpus, vcpu))
    }
}
