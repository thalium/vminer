pub mod aarch64;
pub use aarch64::Aarch64;

pub mod runtime;
pub use runtime::Architecture as RuntimeArchitecture;

pub mod x86_64;
pub use x86_64::X86_64;

use crate::{
    addr::MmuEntry, mask, MemoryAccessResult, PhysicalAddress, TranslationResult, VirtualAddress,
};

fn try_all_addresses(test: impl Fn(PhysicalAddress) -> bool) -> Option<PhysicalAddress> {
    log::debug!("Trying all addresses to guess kernel PGD");

    for addr in (0..u32::MAX as u64).step_by(0x1000) {
        let addr = PhysicalAddress(addr);
        if test(addr) {
            return Some(addr);
        }
    }

    None
}

fn make_address_test<'a>(
    vcpus: &'a (impl Vcpus<'a> + Copy),
    memory: &'a (impl crate::Memory + ?Sized),
    use_per_cpu: bool,
    additionnal: &'a [&[VirtualAddress]],
) -> impl Fn(PhysicalAddress) -> bool + 'a {
    move |addr| {
        let test_one = |test_addr| match vcpus.arch().virtual_to_physical(memory, addr, test_addr) {
            Ok(addr) => memory.is_valid(addr, 1),
            _ => false,
        };

        let valid = additionnal.iter().copied().flatten().copied().all(test_one);

        if use_per_cpu {
            valid
                && vcpus
                    .into_iter()
                    .filter_map(|vcpu| vcpu.kernel_per_cpu())
                    .all(test_one)
        } else {
            valid
        }
    }
}

/// Architecture-independant operations for vCPUs lists
pub trait Vcpus<'a>: IntoIterator<Item = <Self::Arch as Architecture<'a>>::Vcpu> {
    type Arch: Architecture<'a>;

    fn arch(&self) -> Self::Arch;

    fn count(&self) -> usize;

    fn get(&self, id: usize) -> <Self::Arch as Architecture<'a>>::Vcpu;

    fn kernel_per_cpu(&self, cpuid: usize) -> Option<VirtualAddress> {
        self.get(cpuid).kernel_per_cpu()
    }

    fn find_kernel_pgd<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        use_per_cpu: bool,
        additionnal: &[VirtualAddress],
    ) -> Option<PhysicalAddress>;

    fn into_runtime(self) -> runtime::Vcpus<'a>;
}

/// Architecture-independant operations for vCPUs
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

/// A hardware architecture
///
/// This trait has a lifetime, which will be removed when GAT are stable
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
    ) -> TranslationResult<PhysicalAddress>;

    fn find_in_kernel_memory_raw<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        base_search_addr: VirtualAddress,
        finder: &memchr::memmem::Finder,
        buf: &mut [u8],
    ) -> MemoryAccessResult<Option<VirtualAddress>>;

    fn find_in_kernel_memory<M: crate::Memory + ?Sized>(
        &self,
        memory: &M,
        mmu_addr: PhysicalAddress,
        needle: &[u8],
    ) -> MemoryAccessResult<Option<VirtualAddress>>;

    fn kernel_base(&self) -> VirtualAddress;
}

/// The description of how a MMU works
///
/// All architechtures have similar MMU with multiple tables, so this trait
/// tries to abstract that, giving configurations capabities to adapt to each
/// architecture.
///
/// Using a trait here enable many compile-time optimisations.
trait MmuDesc {
    /// The number of significant bits in an address.
    const ADDR_BITS: u32 = 48;

    /// The bits at which each an index can be found for each table entry.
    ///
    /// The boolean should be `true` if a large page can be encountered at this
    /// level.
    const LEVELS: &'static [(u32, bool)] = &[(39, false), (30, true), (21, true), (12, false)];

    /// Returns true if an entry is valid
    fn is_valid(mmu_entry: MmuEntry) -> bool;

    /// Returns true if an entry is a "large" one.
    ///
    /// This is required to support 2M pages for example. If a large page is
    /// encountered, address translation stops here.
    fn is_large(mmu_entry: MmuEntry) -> bool;
}

fn virtual_to_physical<Mmu: MmuDesc, M: crate::Memory + ?Sized>(
    memory: &M,
    mmu_addr: PhysicalAddress,
    addr: VirtualAddress,
) -> TranslationResult<PhysicalAddress> {
    let mut mmu_entry = MmuEntry(mmu_addr.0);

    // This loop is generally unrolled and values are calculated at compile time
    for &(shift, has_huge) in Mmu::LEVELS {
        // First, retreive the index in the table
        let table_addr = mmu_entry.take_bits(12, Mmu::ADDR_BITS);
        let index = (addr.0 >> shift) & mask(9);

        // Each entry is 64 bits (8 bytes) large. This should probably be
        // changed to support 32 bits.
        memory.read(
            table_addr + 8 * index,
            bytemuck::bytes_of_mut(&mut mmu_entry),
        )?;
        if !Mmu::is_valid(mmu_entry) {
            return Err(crate::TranslationError::Invalid(mmu_entry.0));
        }

        // If we encounter a huge page, we are done
        if has_huge && Mmu::is_large(mmu_entry) {
            let base = mmu_entry.take_bits(shift, Mmu::ADDR_BITS);
            let phys_addr = base + (addr.0 & mask(shift));
            return Ok(phys_addr);
        }
    }

    let phys_addr = mmu_entry.take_bits(12, Mmu::ADDR_BITS) + (addr.0 & mask(12));
    Ok(phys_addr)
}

/// This is a recursive function to walk the translation table.
///
/// The buffer is used to avoid allocating a new one for each entry.
fn find_in_kernel_memory_inner<Mmu: MmuDesc, M: crate::Memory + ?Sized>(
    memory: &M,
    table_addr: PhysicalAddress,
    base_search_addr: VirtualAddress,
    finder: &memchr::memmem::Finder,
    buf: &mut [u8],
    levels: &[(u32, bool)],
) -> MemoryAccessResult<Option<VirtualAddress>> {
    let (shift, has_large, rest) = match levels {
        [] => return Ok(None),
        [(shift, has_large), rest @ ..] => (*shift, *has_large, rest),
    };

    let mut table = [MmuEntry(0u64); 512];
    match memory.read(table_addr, bytemuck::bytes_of_mut(&mut table)) {
        Err(crate::MemoryAccessError::OutOfBounds) => return Ok(None),
        Err(err) => return Err(err),
        _ => (),
    }
    let page_size = 1 << shift;

    // The search address can be split in three parts:
    // - A prefix that will used to get final address
    // - An index for the current level to start searching
    // - The rest of the adress that will be given to the next level
    let prefix = VirtualAddress(base_search_addr.0 & !mask(shift + 9));
    let base_index = ((base_search_addr.0 >> shift) & mask(9)) as usize;
    let search_rest = base_search_addr.0 & mask(shift);

    // Iterate over the valid entries
    for (index, entry) in table
        .into_iter()
        .enumerate()
        .skip(base_index)
        .filter(|(_, mmu_entry)| Mmu::is_valid(*mmu_entry))
    {
        let base_addr = prefix + index as u64 * page_size;
        let offset = if index == base_index { search_rest } else { 0 };

        if rest.is_empty() || (has_large && Mmu::is_large(entry)) {
            // If this is the last level or if we encountered a large page, look
            // for the pattern in memory
            let addr = entry.take_bits(shift, Mmu::ADDR_BITS);
            match memory.search(addr + offset, page_size - offset, finder, buf) {
                Ok(Some(i)) => return Ok(Some(base_addr + offset + i as u64)),
                Ok(None) | Err(crate::MemoryAccessError::OutOfBounds) => (),
                Err(err) => return Err(err),
            }
        } else {
            // Else call ourselves recursively
            let table_addr = entry.take_bits(12, Mmu::ADDR_BITS);
            let base_search_addr = base_addr + offset;
            let result = find_in_kernel_memory_inner::<Mmu, M>(
                memory,
                table_addr,
                base_search_addr,
                finder,
                buf,
                rest,
            )?;
            if let Some(addr) = result {
                return Ok(Some(addr));
            }
        }
    }

    Ok(None)
}

/// Find a pattern in kernel memory by walking the translation table starting
/// from the given address.
///
/// This will probably fail if the pattern overlaps multiple pages.
fn find_in_kernel_memory_raw<Mmu: MmuDesc, M: crate::Memory + ?Sized>(
    memory: &M,
    mmu_addr: PhysicalAddress,
    base_search_addr: VirtualAddress,
    finder: &memchr::memmem::Finder,
    buf: &mut [u8],
) -> MemoryAccessResult<Option<VirtualAddress>> {
    let table_addr = MmuEntry(mmu_addr.0).take_bits(12, Mmu::ADDR_BITS);

    find_in_kernel_memory_inner::<Mmu, M>(
        memory,
        table_addr,
        base_search_addr,
        finder,
        buf,
        Mmu::LEVELS,
    )
}

/// Find a pattern in kernel memory by walking the translation table starting
/// from the given address.
///
/// This will probably fail if the pattern overlaps multiple pages.
fn find_in_kernel_memory<Mmu: MmuDesc, M: crate::Memory + ?Sized>(
    memory: &M,
    mmu_addr: PhysicalAddress,
    needle: &[u8],
    base_search_addr: VirtualAddress,
) -> MemoryAccessResult<Option<VirtualAddress>> {
    let mut buf = alloc::vec![0; (1 << 21) + needle.len()];
    let finder = memchr::memmem::Finder::new(needle);

    find_in_kernel_memory_raw::<Mmu, M>(memory, mmu_addr, base_search_addr, &finder, &mut buf)
}
