use crate::{Architecture, GuestPhysAddr, GuestVirtAddr, Memory, MemoryAccessResult};

pub trait Backend {
    type Arch: Architecture;
    type Memory: Memory;

    fn arch(&self) -> &Self::Arch;

    fn vcpus(&self) -> &[<Self::Arch as Architecture>::Vcpu];

    fn memory(&self) -> &Self::Memory;

    fn read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.memory().read(addr, buf)
    }

    fn virtual_to_physical(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
    ) -> MemoryAccessResult<Option<GuestPhysAddr>> {
        self.arch()
            .virtual_to_physical(self.memory(), mmu_addr, addr)
    }
}
