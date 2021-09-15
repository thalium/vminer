use std::io;

use crate::addr::GuestVirtAddr;

use super::Os;

pub struct Linux;

impl Os for Linux {
    fn quick_check<B: crate::Backend>(backend: &B) -> io::Result<bool> {
        const OFFSET: usize = 0x1000;
        const TARGET: &[u8] = b"Linux version";

        const KERNEL_START: u64 = 0xffffffff80000000;
        const KERNEL_END: u64 = 0xfffffffffff00000;

        let mut buf = [0; OFFSET + TARGET.len()];
        let finder = memchr::memmem::Finder::new(TARGET);

        for addr in (KERNEL_START..KERNEL_END).step_by(OFFSET) {
            let addr = GuestVirtAddr(addr);
            if let Ok(paddr) = crate::virtual_to_physical(backend, addr) {
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

    #[test]
    fn quick_check() {
        let vm = crate::DumbDump::read("../linux.dump").unwrap();
        assert!(Linux::quick_check(&vm).unwrap());

        let vm = crate::DumbDump::read("../grub.dump").unwrap();
        assert!(!Linux::quick_check(&vm).unwrap());
    }
}
