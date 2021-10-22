extern crate alloc;

pub mod profile;
pub use profile::Profile;

use crate::core::{self as ice, GuestPhysAddr, GuestVirtAddr};

pub struct Linux {
    profile: Profile,
}

fn per_cpu<B: ice::Backend<ice::arch::X86_64>>(backend: &B) -> GuestVirtAddr {
    let sregs = &backend.vcpus()[0].special_registers;

    let per_cpu = GuestVirtAddr(sregs.gs.base);
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

    #[cfg(feature = "std")]
    pub fn read_current_task<B: ice::Backend<ice::arch::X86_64>>(
        &self,
        backend: &B,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sregs = &backend.vcpus()[0].special_registers;
        let mmu_addr = GuestPhysAddr(sregs.cr3);

        let current_task = per_cpu(backend)
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);
        let current_task = backend
            .virtual_to_physical(mmu_addr, current_task)?
            .unwrap();

        let mut addr = GuestVirtAddr(0);
        backend.read_memory(current_task, bytemuck::bytes_of_mut(&mut addr))?;

        let addr = backend.virtual_to_physical(mmu_addr, addr)?.unwrap();
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

impl ice::Os for Linux {
    fn quick_check<Arch: ice::Architecture, B: ice::Backend<Arch>>(
        backend: &B,
    ) -> ice::MemoryAccessResult<bool> {
        const OFFSET: usize = 0x1000;
        const TARGET: &[u8] = b"Linux version";

        const KERNEL_START: u64 = 0xffffffff80000000;
        const KERNEL_END: u64 = 0xfffffffffff00000;

        let sregs = (&backend.vcpus()[0] as &dyn core::any::Any)
            .downcast_ref::<ice::arch::x86_64::Vcpu>()
            .expect("TODO")
            .special_registers;
        let mmu_addr = GuestPhysAddr(sregs.cr3);

        let mut buf = [0; OFFSET + TARGET.len()];
        let finder = memchr::memmem::Finder::new(TARGET);

        for addr in (KERNEL_START..KERNEL_END).step_by(OFFSET) {
            let addr = GuestVirtAddr(addr);
            if let Ok(Some(paddr)) = backend.virtual_to_physical(mmu_addr, addr) {
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
    use crate::backends;
    use crate::core::Os;
    use crate::os::linux::Linux;

    #[test]
    fn quick_check() {
        let vm = backends::kvm_dump::DumbDump::read("../linux.dump").unwrap();
        assert!(Linux::quick_check(&vm).unwrap());

        let vm = backends::kvm_dump::DumbDump::read("../grub.dump").unwrap();
        assert!(!Linux::quick_check(&vm).unwrap());
    }
}
