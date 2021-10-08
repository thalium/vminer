extern crate alloc;

mod profile;
pub use profile::Profile;

use ibc::{Backend, GuestVirtAddr, Os};

pub struct Linux {
    profile: Profile,
}

fn per_cpu<B: Backend>(backend: &B) -> ibc::GuestVirtAddr {
    let sregs = backend.get_sregs();

    let per_cpu = ibc::GuestVirtAddr(sregs.gs.base);
    assert!(per_cpu.0 > 0x7fffffffffffffff);

    per_cpu
}

impl Linux {
    pub const fn is_kernel_addr(addr: GuestVirtAddr) -> bool {
        (addr.0 as i64) < 0
    }

    pub fn create(profile: Profile) -> Self {
        Linux { profile }
    }

    pub fn read_current_task<B: Backend>(
        &self,
        backend: &B,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let current_task = per_cpu(backend)
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);
        let current_task = backend.virtual_to_physical(current_task)?.unwrap();

        let mut addr = GuestVirtAddr(0);
        backend.read_memory(current_task, bytemuck::bytes_of_mut(&mut addr))?;

        println!("0x{:016x}", addr);
        let addr = backend.virtual_to_physical(addr)?.unwrap();
        let task_struct = self.profile.syms.get_struct("task_struct").unwrap();

        for win in task_struct.fields[..100].windows(2) {
            match win {
                [current, next] => {
                    let size = (next.offset - current.offset) as usize;
                    let mut buf = [0; 1024];
                    let buf = &mut buf[..size];
                    backend.read_memory(addr + current.offset, buf)?;

                    match size {
                        4 => {
                            let x: &u32 = bytemuck::from_bytes(buf);
                            println!("{} ({}): {}", current.name, size, x);
                        }
                        8 => {
                            let x: &u64 = bytemuck::from_bytes(buf);
                            println!("{} ({}): {}", current.name, size, x);
                        }
                        _ => println!("{} ({}): {:02x?}", current.name, size, buf),
                    }
                }
                _ => unreachable!(),
            }
        }

        Ok(())
    }
}

impl Os for Linux {
    fn quick_check<B: Backend>(backend: &B) -> ibc::MemoryAccessResult<bool> {
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
