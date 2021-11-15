pub mod aarch64;
pub use aarch64::Aarch64;

pub mod runtime;
pub use runtime::Architecture as RuntimeArchitecture;

pub mod x86_64;
pub use x86_64::X86_64;

use crate::{GuestPhysAddr, GuestVirtAddr, MemoryAccessResult};

pub trait VcpusList<'a> {
    type Arch: Architecture<'a>;

    fn arch(&self) -> Self::Arch;

    fn count(&self) -> usize;

    fn get(&self, id: usize) -> <Self::Arch as Architecture<'a>>::Vcpu;

    fn into_runtime(self) -> runtime::Vcpus<'a>;
}

pub trait Vcpu<'a> {
    type Arch: Architecture<'a>;

    fn arch(&self) -> Self::Arch;

    fn get_regs(&self) -> <Self::Arch as Architecture<'a>>::Registers;

    fn into_runtime(self) -> runtime::Vcpu<'a>;
}

pub trait Architecture<'a> {
    type Vcpu: Vcpu<'a, Arch = Self>;
    type Vcpus: VcpusList<'a, Arch = Self>;
    type Registers;

    fn into_runtime(self) -> runtime::Architecture;

    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
    ) -> MemoryAccessResult<Option<GuestPhysAddr>>;
}
