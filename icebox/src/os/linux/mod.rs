pub mod process;
pub mod profile;

use crate::core::{
    self as ice, arch, GuestPhysAddr, GuestVirtAddr, IceResult, MemoryAccessResultExt,
};
use core::fmt;

pub use process::Process;
pub use profile::Profile;

pub struct Linux {
    profile: Profile,
}

fn per_cpu<B: ice::Backend<Arch = ice::arch::X86_64>>(backend: &B, cpuid: usize) -> GuestVirtAddr {
    let cpu = &backend.vcpus()[cpuid];

    let mut per_cpu = GuestVirtAddr(cpu.special_registers.gs.base);
    if !Linux::is_kernel_addr(per_cpu) {
        per_cpu = GuestVirtAddr(cpu.gs_kernel_base);
        assert!(Linux::is_kernel_addr(per_cpu));
    }

    per_cpu
}

pub fn kernel_page_dir<B: ice::Backend<Arch = ice::arch::X86_64>>(
    backend: &B,
    profile: &Profile,
) -> IceResult<GuestPhysAddr> {
    let addr =
        per_cpu(backend, 0) + (profile.fast_syms.current_task - profile.fast_syms.per_cpu_start);

    for vcpu in backend.vcpus() {
        let cr3 = GuestPhysAddr(vcpu.special_registers.cr3);

        if backend.virtual_to_physical(cr3, addr)?.is_some() {
            return Ok(cr3);
        }
    }

    Err("failed to find a valid cr3".into())
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
    ) -> IceResult<i64> {
        let mmu_addr = kernel_page_dir(backend, &self.profile)?;
        let base_banner_addr = self.profile.syms.get_addr("linux_banner")?;
        let (banner_addr, _) =
            get_banner_addr(backend, mmu_addr)?.ok_or("could not find banner address")?;

        Ok(banner_addr.0.overflowing_sub(base_banner_addr.0).0 as i64)
    }

    #[cfg(feature = "std")]
    pub fn read_all_tasks<B: ice::Backend<Arch = ice::arch::X86_64>>(
        &self,
        backend: &B,
        kaslr: i64,
    ) -> IceResult<()> {
        let mmu_addr = kernel_page_dir(backend, &self.profile)?;

        let task_struct = self.profile.syms.get_struct("task_struct")?;
        let list_head = self.profile.syms.get_struct("list_head")?;
        let init_task = self.profile.syms.get_addr("init_task")? + kaslr;

        let next_offset = list_head.find_offset("next")?;
        let tasks_offset = task_struct.find_offset("tasks")?;

        // let mut init_task = per_cpu(backend, 0)
        //    + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);

        // let addr = backend.virtual_to_physical(mmu_addr, init_task).valid()?;
        // backend.read_memory(addr, bytemuck::bytes_of_mut(&mut init_task))?;

        let mut current_task = init_task;

        let mut name = [0u8; 16];
        loop {
            let current_task_addr = backend
                .virtual_to_physical(mmu_addr, current_task)
                .valid()?;

            let proc = Process::new(current_task_addr, self);

            proc.read_comm(backend, &mut name)?;
            let pid = proc.pid(backend)?;

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
        cpuid: usize,
    ) -> IceResult<()> {
        let mmu_addr = kernel_page_dir(backend, &self.profile)?;

        let current_task = per_cpu(backend, cpuid)
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);
        let current_task = backend
            .virtual_to_physical(mmu_addr, current_task)
            .valid()?;

        let addr = backend.read_value(current_task)?;

        let addr = backend.virtual_to_physical(mmu_addr, addr).valid()?;
        let task_struct = self.profile.syms.get_struct("task_struct")?;

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

    pub fn current_process<B: ice::Backend<Arch = ice::arch::X86_64>>(
        &self,
        backend: &B,
        cpuid: usize,
    ) -> IceResult<Process> {
        let mmu_addr = kernel_page_dir(backend, &self.profile)?;

        let current_task = per_cpu(backend, cpuid)
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);
        let current_task = backend
            .virtual_to_physical(mmu_addr, current_task)
            .valid()?;

        let addr = backend.read_value(current_task)?;
        let addr = backend.virtual_to_physical(mmu_addr, addr).valid()?;

        Ok(Process::new(addr, self))
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
        if let Some(paddr) = backend.virtual_to_physical(mmu_addr, addr)? {
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
        use arch::VcpusList;
        let sregs = match backend.vcpus().into_runtime().as_x86_64() {
            Some(vcpus) => vcpus[0].special_registers,
            None => return Ok(false),
        };

        let mmu_addr = GuestPhysAddr(sregs.cr3);

        Ok(get_banner_addr(backend, mmu_addr)?.is_some())
    }
}

impl fmt::Debug for Linux {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Linux").finish_non_exhaustive()
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
