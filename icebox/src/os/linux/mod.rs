pub mod process;
pub mod profile;

use crate::core::{
    self as ice, arch::Vcpus, GuestPhysAddr, GuestVirtAddr, IceResult, MemoryAccessResultExt,
};
use core::fmt;

pub use process::Process;
pub use profile::Profile;

pub struct Linux {
    profile: Profile,
    kpgd: GuestPhysAddr,
}

fn per_cpu<B: ice::Backend>(backend: &B, cpuid: usize) -> IceResult<GuestVirtAddr> {
    backend.kernel_per_cpu(cpuid, Linux::is_kernel_addr)
}

fn kernel_page_dir<B: ice::Backend>(backend: &B, profile: &Profile) -> IceResult<GuestPhysAddr> {
    let vcpus = backend
        .vcpus()
        .into_runtime()
        .as_x86_64()
        .ok_or_else(ice::IceError::unsupported_architecture)?;

    let addr =
        per_cpu(backend, 0)? + (profile.fast_syms.current_task - profile.fast_syms.per_cpu_start);

    for vcpu in vcpus {
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

    pub fn create<B: ice::Backend>(backend: &B, profile: Profile) -> IceResult<Self> {
        let kpgd = kernel_page_dir(backend, &profile)?;
        Ok(Linux { profile, kpgd })
    }

    pub fn get_aslr<B: ice::Backend>(&self, backend: &B) -> IceResult<i64> {
        let base_banner_addr = self.profile.syms.get_addr("linux_banner")?;
        let (banner_addr, _) =
            get_banner_addr(backend, self.kpgd)?.ok_or("could not find banner address")?;

        Ok(banner_addr.0.overflowing_sub(base_banner_addr.0).0 as i64)
    }

    pub fn read_tasks<'b, B: ice::Backend>(
        &self,
        backend: &'b B,
        kaslr: i64,
    ) -> IceResult<process::Iter<'_, 'b, B>> {
        let init_task = self.profile.fast_syms.init_task + kaslr;
        let current_task = backend.virtual_to_physical(self.kpgd, init_task).valid()?;

        Ok(process::Iter::new(self, backend, current_task))
    }

    #[cfg(feature = "std")]
    pub fn read_current_task<B: ice::Backend>(&self, backend: &B, cpuid: usize) -> IceResult<()> {
        let current_task = per_cpu(backend, cpuid)?
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);
        let current_task = backend
            .virtual_to_physical(self.kpgd, current_task)
            .valid()?;

        let addr = backend.read_value(current_task)?;

        let addr = backend.virtual_to_physical(self.kpgd, addr).valid()?;
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

    pub fn current_thread<B: ice::Backend>(&self, backend: &B, cpuid: usize) -> IceResult<Process> {
        let mmu_addr = kernel_page_dir(backend, &self.profile)?;

        let current_task = per_cpu(backend, cpuid)?
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);
        let current_task = backend
            .virtual_to_physical(mmu_addr, current_task)
            .valid()?;

        let addr = backend.read_value(current_task)?;
        let addr = backend.virtual_to_physical(mmu_addr, addr).valid()?;

        Ok(Process::new(addr, self))
    }

    pub fn current_process<B: ice::Backend>(
        &self,
        backend: &B,
        cpuid: usize,
    ) -> IceResult<Process> {
        self.current_thread(backend, cpuid)?.group_leader(backend)
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
