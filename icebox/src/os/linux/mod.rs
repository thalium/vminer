pub mod process;
pub mod profile;

use crate::core::{
    self as ice, arch::Vcpus, GuestPhysAddr, GuestVirtAddr, IceResult, MemoryAccessResultExt,
};
use core::fmt;

use ice::Backend;
pub use process::Process;
pub use profile::Profile;

pub struct Linux<B> {
    backend: B,
    profile: Profile,
    kpgd: GuestPhysAddr,
}

fn per_cpu<B: ice::Backend>(backend: &B, cpuid: usize) -> IceResult<GuestVirtAddr> {
    backend.kernel_per_cpu(cpuid, is_kernel_addr)
}

pub const fn is_kernel_addr(addr: GuestVirtAddr) -> bool {
    (addr.0 as i64) < 0
}

impl<B: Backend> Linux<B> {
    pub fn create(backend: B, profile: Profile) -> IceResult<Self> {
        let valid_addr = per_cpu(&backend, 0)?;
        let kpgd = backend.find_kernel_pgd(valid_addr)?;
        Ok(Linux {
            backend,
            profile,
            kpgd,
        })
    }

    fn kernel_to_physical(&self, addr: GuestVirtAddr) -> IceResult<GuestPhysAddr> {
        self.backend.virtual_to_physical(self.kpgd, addr).valid()
    }

    fn read_kernel_value<T: bytemuck::Pod>(&self, addr: GuestVirtAddr) -> IceResult<T> {
        self.backend.read_value_virtual(self.kpgd, addr)
    }

    pub fn get_aslr(&self) -> IceResult<i64> {
        let base_banner_addr = self.profile.syms.get_addr("linux_banner")?;
        let (banner_addr, _) =
            get_banner_addr(&self.backend, self.kpgd)?.ok_or("could not find banner address")?;

        Ok(banner_addr.0.overflowing_sub(base_banner_addr.0).0 as i64)
    }

    pub fn read_tasks(&self, kaslr: i64) -> IceResult<process::Iter<'_, B>> {
        let init_task = self.profile.fast_syms.init_task + kaslr;
        let current_task = self.kernel_to_physical(init_task)?;

        Ok(process::Iter::new(self, current_task))
    }

    #[cfg(feature = "std")]
    pub fn read_current_task(&self, cpuid: usize) -> IceResult<()> {
        let current_task = per_cpu(&self.backend, cpuid)?
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);

        let addr = self.read_kernel_value(current_task)?;

        let addr = self.kernel_to_physical(addr)?;
        let task_struct = self.profile.syms.get_struct("task_struct")?;

        for win in task_struct.fields[..100].windows(2) {
            match win {
                [current, next] => {
                    let size = (next.offset - current.offset) as usize;
                    let mut buf = [0; 1024];
                    let buf = &mut buf[..size];
                    self.backend.read_memory(addr + current.offset, buf)?;

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

    pub fn current_thread(&self, cpuid: usize) -> IceResult<Process<B>> {
        let current_task = per_cpu(&self.backend, cpuid)?
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);

        let addr = self.read_kernel_value(current_task)?;
        let addr = self.kernel_to_physical(addr)?;

        Ok(Process::new(addr, self))
    }

    pub fn current_process(&self, cpuid: usize) -> IceResult<Process<B>> {
        self.current_thread(cpuid)?.group_leader()
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

impl<B: Backend> ice::Os for Linux<B> {
    fn quick_check<Back: ice::Backend>(backend: &Back) -> ice::MemoryAccessResult<bool> {
        let sregs = match backend.vcpus().into_runtime().as_x86_64() {
            Some(vcpus) => vcpus[0].special_registers,
            None => return Ok(false),
        };

        let mmu_addr = GuestPhysAddr(sregs.cr3);

        Ok(get_banner_addr(backend, mmu_addr)?.is_some())
    }
}

impl<B> fmt::Debug for Linux<B> {
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
        assert!(Linux::<backends::kvm_dump::DumbDump<ibc::File>>::quick_check(&vm).unwrap());

        let vm = backends::kvm_dump::DumbDump::read("../grub.dump").unwrap();
        assert!(!Linux::<backends::kvm_dump::DumbDump<ibc::File>>::quick_check(&vm).unwrap());
    }
}
