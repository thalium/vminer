use ibc::{Backend, GuestVirtAddr, Os};

pub struct Linux;

impl Linux {
    pub const fn is_kernel_addr(addr: GuestVirtAddr) -> bool {
        (addr.0 as i64) < 0
    }
}

impl Os for Linux {
    fn quick_check<B: Backend>(backend: &B) -> ibc::backend::MemoryAccessResult<bool> {
        const OFFSET: usize = 0x1000;
        const TARGET: &[u8] = b"Linux version";

        const KERNEL_START: u64 = 0xffffffff80000000;
        const KERNEL_END: u64 = 0xfffffffffff00000;

        let mut buf = [0; OFFSET + TARGET.len()];
        let finder = memchr::memmem::Finder::new(TARGET);

        for addr in (KERNEL_START..KERNEL_END).step_by(OFFSET) {
            let addr = GuestVirtAddr(addr);
            if let Ok(Some(paddr)) = backend.virtual_to_physical(addr) {
                backend.read_memory(paddr, &mut buf)?;

                if finder.find(&buf).is_some() {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebox_backend_dumb_dump::DumbDump;

    #[test]
    fn quick_check() {
        let vm = DumbDump::read("../linux.dump").unwrap();
        assert!(Linux::quick_check(&vm).unwrap());

        let vm = DumbDump::read("../grub.dump").unwrap();
        assert!(!Linux::quick_check(&vm).unwrap());
    }
}
