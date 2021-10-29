extern crate alloc;

pub mod profile;
pub use profile::Profile;

use crate::core::{self as ice, GuestPhysAddr, GuestVirtAddr};

pub struct Linux {
    profile: Profile,
}

fn per_cpu<B: ice::Backend<Arch = ice::arch::X86_64>>(backend: &B, cpuid: usize) -> GuestVirtAddr {
    let sregs = &backend.vcpus()[cpuid].special_registers;

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

    pub fn get_aslr<B: ice::Backend<Arch = ice::arch::X86_64>>(
        &self,
        backend: &B,
    ) -> ice::MemoryAccessResult<i64> {
        let mmu_addr = GuestPhysAddr(backend.vcpus()[0].special_registers.cr3);
        let base_banner_addr = self.profile.syms.get_addr("linux_banner").unwrap();
        let (banner_addr, _) = get_banner_addr(backend, mmu_addr)?.unwrap();

        Ok(banner_addr.0.overflowing_sub(base_banner_addr.0).0 as i64)
    }

    #[cfg(feature = "std")]
    pub fn read_all_tasks<B: ice::Backend<Arch = ice::arch::X86_64>>(
        &self,
        backend: &B,
        kaslr: i64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mmu_addr = GuestPhysAddr(backend.vcpus()[0].special_registers.cr3);

        let task_struct = self.profile.syms.get_struct("task_struct").unwrap();
        let list_head = self.profile.syms.get_struct("list_head").unwrap();
        let init_task = self.profile.syms.get_addr("init_task").unwrap() + kaslr;

        let next_offset = list_head.find_offset("prev").unwrap();
        let tasks_offset = task_struct.find_offset("tasks").unwrap();
        let comm_offset = task_struct.find_offset("comm").unwrap();
        let pid_offset = task_struct.find_offset("pid").unwrap();

        // let mut init_task = per_cpu(backend, 0)
        //    + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);

        // let addr = backend.virtual_to_physical(mmu_addr, init_task)?.unwrap();
        // backend.read_memory(addr, bytemuck::bytes_of_mut(&mut init_task))?;

        let mut current_task = init_task;

        let mut name = [0u8; 16];
        let mut pid = 0u32;
        loop {
            let current_task_addr = backend
                .virtual_to_physical(mmu_addr, current_task)?
                .unwrap();

            backend.read_memory(
                current_task_addr + comm_offset,
                bytemuck::bytes_of_mut(&mut name),
            )?;
            backend.read_memory(
                current_task_addr + pid_offset,
                bytemuck::bytes_of_mut(&mut pid),
            )?;

            let name = String::from_utf8_lossy(&name);
            println!("{}: {}", pid, name);

            backend.read_memory(
                current_task_addr + tasks_offset + next_offset,
                bytemuck::bytes_of_mut(&mut current_task),
            )?;
            current_task -= tasks_offset;

            if current_task == init_task || current_task == GuestVirtAddr(0) {
                break;
            }
        }

        Ok(())
    }

    #[cfg(feature = "std")]
    pub fn read_current_task<B: ice::Backend<Arch = ice::arch::X86_64>>(
        &self,
        backend: &B,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let sregs = &backend.vcpus()[0].special_registers;
        let mmu_addr = GuestPhysAddr(sregs.cr3);

        let current_task = per_cpu(backend, 0)
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

fn get_banner_addr<B: ice::Backend>(
    backend: &B,
    mmu_addr: GuestPhysAddr,
) -> ice::MemoryAccessResult<Option<(GuestVirtAddr, GuestPhysAddr)>> {
    const OFFSET: usize = 0x1000;
    const TARGET: &[u8] = b"Linux version";

    const KERNEL_START: u64 = 0xffffffff80000000;
    const KERNEL_END: u64 = 0xfffffffffff00000;

    let mut buf = [0; OFFSET + TARGET.len()];
    let finder = memchr::memmem::Finder::new(TARGET);

    for addr in (KERNEL_START..KERNEL_END).step_by(OFFSET) {
        let addr = GuestVirtAddr(addr);
        if let Ok(Some(paddr)) = backend.virtual_to_physical(mmu_addr, addr) {
            backend.read_memory(paddr, &mut buf)?;

            if let Some(offset) = finder.find(&buf) {
                let offset = offset as u64;
                return Ok(Some((addr + offset, paddr + offset)));
            }
        }
    }

    Ok(None)
}

impl ice::Os for Linux {
    fn quick_check<B: ice::Backend>(backend: &B) -> ice::MemoryAccessResult<bool> {
        let sregs = (&backend.vcpus()[0] as &dyn core::any::Any)
            .downcast_ref::<ice::arch::x86_64::Vcpu>()
            .expect("TODO")
            .special_registers;
        let mmu_addr = GuestPhysAddr(sregs.cr3);

        Ok(get_banner_addr(backend, mmu_addr)?.is_some())
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
