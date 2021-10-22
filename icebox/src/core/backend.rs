use super::{mask, Architecture, GuestPhysAddr, GuestVirtAddr, Memory, MemoryAccessResult, MmPte};

pub trait Backend<Arch: Architecture> {
    type Memory: Memory;

    fn vcpus(&self) -> &[Arch::Vcpu];

    fn memory(&self) -> &Self::Memory;

    fn read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        self.memory().read(addr, buf)
    }

    fn virtual_to_physical(
        &self,
        mmu_addr: GuestPhysAddr,
        addr: GuestVirtAddr,
    ) -> MemoryAccessResult<Option<GuestPhysAddr>> {
        let mut mmu_entry = MmPte(0);

        let pml4e_addr = GuestPhysAddr(mmu_addr.0 & (mask(40) << 12)) + 8 * addr.pml4e();
        self.read_memory(pml4e_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
        if !mmu_entry.is_valid() {
            return Ok(None);
        }

        let pdpe_addr = mmu_entry.page_frame() + 8 * addr.pdpe();
        self.read_memory(pdpe_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
        if !mmu_entry.is_valid() {
            return Ok(None);
        }

        if mmu_entry.is_large() {
            let phys_addr = mmu_entry.huge_page_frame() + addr.huge_page_offset();
            return Ok(Some(phys_addr));
        }

        let pde_addr = mmu_entry.page_frame() + 8 * addr.pde();
        self.read_memory(pde_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
        if !mmu_entry.is_valid() {
            return Ok(None);
        }

        if mmu_entry.is_large() {
            let phys_addr = mmu_entry.large_page_frame() + addr.large_page_offset();
            return Ok(Some(phys_addr));
        }

        let pte_addr = mmu_entry.page_frame() + 8 * addr.pte();
        self.read_memory(pte_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
        if !mmu_entry.is_valid() {
            return Ok(None);
        }

        let phys_addr = mmu_entry.page_frame() + addr.page_offset();
        Ok(Some(phys_addr))
    }
}
