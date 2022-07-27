use super::{pointer, profile, Pointer};
use ibc::{Os, PhysicalAddress, VirtualAddress};

const VAD_MASK: u64 = 0xffffffff00000000;

const MMPTE_VALID_BIT: u64 = 1 << 0;
const MMPTE_SWIZZLE_BIT: u64 = 1 << 4;
const MMPTE_SOFTWARE_BIT: u64 = 1 << 10;
const MMPTE_TRANSITION_BIT: u64 = 1 << 11;

#[derive(Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(transparent)]
pub(crate) struct MmPte(u64);

enum MmPteKind {
    Software,
    Transition,
    Vad,
    Zero,
    Unknown,
}

impl MmPte {
    #[inline]
    fn is_valid(self) -> bool {
        self.0 & MMPTE_VALID_BIT != 0
    }

    #[inline]
    fn transition_page(self) -> PhysicalAddress {
        PhysicalAddress(self.0 & ibc::mask_range(12, 40))
    }

    #[inline]
    fn classify(self) -> MmPteKind {
        let pte = self.0;

        if pte & MMPTE_SOFTWARE_BIT != 0 {
            if pte & VAD_MASK == VAD_MASK {
                MmPteKind::Vad
            } else {
                MmPteKind::Software
            }
        } else if pte == 0 {
            MmPteKind::Vad
        } else if pte & MMPTE_TRANSITION_BIT != 0 {
            MmPteKind::Transition
        } else if pte >> 32 == 0 {
            MmPteKind::Zero
        } else {
            MmPteKind::Unknown
        }
    }
}

impl<B: ibc::Backend> super::Windows<B> {
    #[inline]
    fn unswizzle(&self, pte: MmPte) -> MmPte {
        if pte.0 & MMPTE_SWIZZLE_BIT == 0 {
            MmPte(pte.0 & self.unswizzle_mask)
        } else {
            pte
        }
    }

    fn read_vad_pte(
        &self,
        addr: VirtualAddress,
        buf: &mut [u8],
        proc: ibc::Process,
    ) -> ibc::TranslationResult<()> {
        if addr.is_kernel() {
            return Err(ibc::TranslationError::Invalid(0));
        }

        let result = (|| {
            let vma = self
                .process_find_vma_by_address(proc, addr)?
                .ok_or("encoutered unmapped page")?;

            let vma_start = self.vma_start(vma)?;

            let pte: Pointer<profile::Mmvad, _> = Pointer::new(vma.0, self, pointer::KernelSpace);
            let mut pte = pte.read_pointer_field(|mmvad| mmvad.FirstPrototypePte)?;

            pte.addr += ((addr - vma_start) as u64 / 0x1000) * 8;
            pte.read()
        })();

        match result {
            Ok(pte) => self.read_prototype_pte(addr, buf, pte),
            Err(err) => {
                log::warn!("Failed to read VAD PTE for address {addr:#x}: {err}");
                Err(ibc::TranslationError::Invalid(0))
            }
        }
    }

    fn read_prototype_pte(
        &self,
        addr: VirtualAddress,
        buf: &mut [u8],
        pte: MmPte,
    ) -> ibc::TranslationResult<()> {
        let offset = addr.0 & ibc::mask(12);

        if pte.is_valid() {
            let addr_base = PhysicalAddress(pte.0 & ibc::mask_range(12, 48));
            self.backend.read_physical(addr_base + offset, buf)?;
            return Ok(());
        }

        let pte = self.unswizzle(pte);

        match pte.classify() {
            MmPteKind::Transition => {
                self.backend
                    .read_physical(pte.transition_page() + offset, buf)?;
                Ok(())
            }
            MmPteKind::Zero => {
                buf.fill(0);
                Ok(())
            }
            _ => Err(ibc::TranslationError::Invalid(pte.0)),
        }
    }

    pub(super) fn read_virtual_memory_raw(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
        proc: Option<ibc::Process>,
    ) -> ibc::TranslationResult<()> {
        let entry = match self.backend.read_virtual_memory(mmu_addr, addr, buf) {
            Ok(()) => return Ok(()),
            Err(ibc::TranslationError::Invalid(entry)) => MmPte(entry),
            Err(ibc::TranslationError::Memory(err)) => return Err(err.into()),
        };

        let offset = addr.0 & ibc::mask(12);
        let pte = self.unswizzle(entry);

        match pte.classify() {
            MmPteKind::Software => {
                let pte_addr = VirtualAddress(pte.0 >> 16);
                let pte = self.backend.read_value_virtual(self.kpgd, pte_addr)?;
                self.read_prototype_pte(addr, buf, pte)
            }
            MmPteKind::Transition => {
                self.backend
                    .read_physical(pte.transition_page() + offset, buf)?;
                Ok(())
            }
            MmPteKind::Vad => match proc {
                Some(proc) => self.read_vad_pte(addr, buf, proc),
                None => Err(ibc::TranslationError::Invalid(pte.0)),
            },
            MmPteKind::Zero => {
                buf.fill(0);
                Ok(())
            }
            MmPteKind::Unknown => Err(ibc::TranslationError::Invalid(pte.0)),
        }
    }
}
