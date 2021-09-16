use core::fmt;

use crate::{mask, GuestPhysAddr, GuestVirtAddr, MmPte};

#[derive(Debug)]
#[non_exhaustive]
pub enum MemoryAccessError {
    OutOfBounds,
    Other(&'static str),
}

impl fmt::Display for MemoryAccessError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::OutOfBounds => f.write_str("out of bounds memory access"),
            Self::Other(s) => f.write_str(s),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MemoryAccessError {}

pub type MemoryAccessResult<T> = Result<T, MemoryAccessError>;

pub trait Backend {
    fn get_regs(&self) -> &kvm_common::kvm_regs;
    fn get_sregs(&self) -> &kvm_common::kvm_sregs;

    fn read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()>;
    fn write_memory(&mut self, addr: GuestPhysAddr, buf: &[u8]) -> MemoryAccessResult<()>;

    fn virtual_to_physical(
        &self,
        addr: GuestVirtAddr,
    ) -> MemoryAccessResult<Option<GuestPhysAddr>> {
        let mut mmu_entry = MmPte(0);

        let cr3 = self.get_sregs().cr3;

        let pml4e_addr = GuestPhysAddr(cr3 & (mask(40) << 12)) + 8 * addr.pml4e();
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

/*
pub fn dump_kvm(vm: &Kvm) -> io::Result<DumbDump> {
    let mut mem = vec![0; 2 << 30];
    vm.read_memory(GuestPhysAddr(0), &mut mem).unwrap();

    let dump = dumb_dump::DumbDump {
        regs: *vm.get_regs(),
        sregs: *vm.get_sregs(),
        mem: dumb_dump::Mem::Bytes(mem),
    };
    Ok(dump)
}
*/
