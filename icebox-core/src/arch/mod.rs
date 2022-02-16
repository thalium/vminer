pub mod aarch64;
pub use aarch64::Aarch64;

pub mod runtime;
pub use runtime::Architecture as RuntimeArchitecture;

pub mod x86_64;
pub use x86_64::X86_64;

use crate::{addr::MmuEntry, mask, MemoryAccessResult, PhysicalAddress, VirtualAddress};

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

    fn kernel_per_cpu(&self, cpuid: usize) -> Option<VirtualAddress> {
        self.get(cpuid).kernel_per_cpu()
    }

    fn find_kernel_pgd<M: crate::Memory + ?Sized>(&self, memory: &M) -> Option<PhysicalAddress>;

    fn into_runtime(self) -> runtime::Vcpus<'a>;
}

pub trait Vcpu<'a> {
    type Arch: Architecture<'a>;

    fn arch(&self) -> Self::Arch;

    fn get_regs(&self) -> <Self::Arch as Architecture<'a>>::Registers;

    fn instruction_pointer(&self) -> VirtualAddress;

    fn stack_pointer(&self) -> VirtualAddress;

    fn base_pointer(&self) -> Option<VirtualAddress>;

    fn pgd(&self) -> PhysicalAddress;

    fn kernel_per_cpu(&self) -> Option<VirtualAddress>;

    fn into_runtime(self) -> runtime::Vcpu<'a>;
}

pub trait Architecture<'a> {
    type Vcpu: Vcpu<'a, Arch = Self>;
    type Vcpus: Vcpus<'a, Arch = Self>;
    type Registers;
    type Endian: crate::Endianness;

    fn into_runtime(self) -> runtime::Architecture;

    fn endianness(&self) -> Self::Endian;

    fn virtual_to_physical<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
    ) -> MemoryAccessResult<Option<PhysicalAddress>>;

    fn find_in_kernel_memory<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> MemoryAccessResult<Option<VirtualAddress>>;
}

trait MmuDesc {
    const MEM_OFFSET: u64 = 0;

    const ADDR_BITS: u32 = 48;
    const LEVELS: &'static [(u32, bool)] = &[(39, false), (30, true), (21, true), (12, false)];

    fn is_valid(mmu_entry: MmuEntry) -> bool;

    fn is_large(mmu_entry: MmuEntry) -> bool;
}

fn virtual_to_physical<Mmu: MmuDesc, M: crate::Memory + ?Sized>(
    memory: &M,
    mmu_addr: PhysicalAddress,
    addr: VirtualAddress,
) -> crate::MemoryAccessResult<Option<PhysicalAddress>> {
    let mut mmu_entry = MmuEntry(mmu_addr.0);

    for &(shift, has_huge) in Mmu::LEVELS {
        let table_addr = mmu_entry.take_bits(12, Mmu::ADDR_BITS);
        let index = (addr.0 >> shift) & mask(9);

        memory.read(
            table_addr + 8 * index,
            bytemuck::bytes_of_mut(&mut mmu_entry),
        )?;
        if !Mmu::is_valid(mmu_entry) {
            return Ok(None);
        }
        mmu_entry -= Mmu::MEM_OFFSET;

        if has_huge && Mmu::is_large(mmu_entry) {
            let base = mmu_entry.take_bits(shift, Mmu::ADDR_BITS);
            let phys_addr = base + (addr.0 & mask(shift));
            return Ok(Some(phys_addr));
        }
    }

    let phys_addr = mmu_entry.take_bits(12, Mmu::ADDR_BITS) + (addr.0 & mask(12));
    Ok(Some(phys_addr))
}

fn find_in_kernel_memory_inner<Mmu: MmuDesc, M: crate::Memory + ?Sized>(
    memory: &M,
    table_addr: PhysicalAddress,
    base_addr: VirtualAddress,
    finder: &memchr::memmem::Finder,
    buf: &mut [u8],
    levels: &[(u32, bool)],
) -> MemoryAccessResult<Option<VirtualAddress>> {
    let (shift, has_large, rest) = match levels {
        [] => return Ok(None),
        [(shift, has_large), rest @ ..] => (*shift, *has_large, rest),
    };

    let mut table = [MmuEntry(0u64); 512];
    memory.read(table_addr, bytemuck::bytes_of_mut(&mut table))?;
    let page_size = 1 << shift;

    let skip = if levels.len() == Mmu::LEVELS.len() {
        0x140
    } else {
        0
    };

    for (index, entry) in table
        .into_iter()
        .enumerate()
        .skip(skip)
        .filter(|(_, mmu_entry)| Mmu::is_valid(*mmu_entry))
    {
        let base_addr = base_addr + index as u64 * page_size;
        let entry = entry - Mmu::MEM_OFFSET;

        if rest.is_empty() || (has_large && Mmu::is_large(entry)) {
            let addr = entry.take_bits(shift, Mmu::ADDR_BITS);
            match memory.search(addr, page_size, finder, buf) {
                Ok(Some(i)) => return Ok(Some(base_addr + i as u64)),
                Ok(None) | Err(crate::MemoryAccessError::OutOfBounds) => (),
                Err(err) => return Err(err),
            }
        } else {
            let table_addr = entry.take_bits(12, Mmu::ADDR_BITS);
            let result = find_in_kernel_memory_inner::<Mmu, M>(
                memory, table_addr, base_addr, finder, buf, rest,
            )?;
            if let Some(addr) = result {
                return Ok(Some(addr));
            }
        }
    }

    Ok(None)
}

fn find_in_kernel_memory<Mmu: MmuDesc, M: crate::Memory + ?Sized>(
    memory: &M,
    mmu_addr: PhysicalAddress,
    needle: &[u8],
) -> MemoryAccessResult<Option<VirtualAddress>> {
    let mut buf = alloc::vec![0; (1 << 21) + needle.len()];
    let base_addr = VirtualAddress(crate::mask_range(Mmu::ADDR_BITS, 64));
    let finder = memchr::memmem::Finder::new(needle);
    let table_addr = MmuEntry(mmu_addr.0).take_bits(12, Mmu::ADDR_BITS);

    find_in_kernel_memory_inner::<Mmu, M>(
        memory,
        table_addr,
        base_addr,
        &finder,
        &mut buf,
        Mmu::LEVELS,
    )
}
