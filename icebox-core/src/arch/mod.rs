pub mod aarch64;
pub use aarch64::Aarch64;

pub mod runtime;
pub use runtime::Architecture as RuntimeArchitecture;

pub mod x86_64;
pub use x86_64::X86_64;

use crate::{MemoryAccessResult, PhysicalAddress, VirtualAddress};

fn try_all_addresses(test: impl Fn(PhysicalAddress) -> bool) -> Option<PhysicalAddress> {
    for addr in (0..u32::MAX as u64).step_by(0x1000) {
        let addr = PhysicalAddress(addr);
        if test(addr) {
            return Some(addr);
        }
    }

    None
}

pub trait Vcpus<'a>: IntoIterator<Item = <Self::Arch as Architecture<'a>>::Vcpu> {
    type Arch: Architecture<'a>;

    fn arch(&self) -> Self::Arch;

    fn count(&self) -> usize;

    fn get(&self, id: usize) -> <Self::Arch as Architecture<'a>>::Vcpu;

    fn kernel_per_cpu(
        &self,
        cpuid: usize,
        check: impl Fn(VirtualAddress) -> bool,
    ) -> Option<VirtualAddress> {
        self.get(cpuid).kernel_per_cpu(check)
    }

    fn find_kernel_pgd(&self, test: impl Fn(PhysicalAddress) -> bool) -> Option<PhysicalAddress>;

    fn into_runtime(self) -> runtime::Vcpus<'a>;
}

pub trait Vcpu<'a> {
    type Arch: Architecture<'a>;

    fn arch(&self) -> Self::Arch;

    fn get_regs(&self) -> <Self::Arch as Architecture<'a>>::Registers;

    fn instruction_pointer(&self) -> VirtualAddress;

    fn kernel_per_cpu(&self, check: impl Fn(VirtualAddress) -> bool) -> Option<VirtualAddress>;

    fn into_runtime(self) -> runtime::Vcpu<'a>;
}

pub trait Architecture<'a> {
    type Vcpu: Vcpu<'a, Arch = Self>;
    type Vcpus: Vcpus<'a, Arch = Self>;
    type Registers;

    fn into_runtime(self) -> runtime::Architecture;

    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> MemoryAccessResult<Option<PhysicalAddress>>;
}
