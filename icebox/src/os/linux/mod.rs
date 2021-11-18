pub mod process;
pub mod profile;

use crate::core::{self as ice, GuestPhysAddr, GuestVirtAddr, IceResult, MemoryAccessResultExt};
use alloc::string::String;
use core::fmt;

use process::Process;
pub use profile::Profile;

pub struct Linux<B> {
    backend: B,
    profile: Profile,
    kpgd: GuestPhysAddr,
    kaslr: i64,
}

fn per_cpu<B: ice::Backend>(backend: &B, cpuid: usize) -> IceResult<GuestVirtAddr> {
    backend.kernel_per_cpu(cpuid, is_kernel_addr)
}

fn find_kpgd<B: ice::Backend>(backend: &B) -> IceResult<GuestPhysAddr> {
    let valid_addr = per_cpu(backend, 0)?;
    backend.find_kernel_pgd(valid_addr)
}

pub fn get_aslr<B: ice::Backend>(
    backend: &B,
    profile: &Profile,
    kpgd: GuestPhysAddr,
) -> IceResult<i64> {
    let base_banner_addr = profile.syms.get_addr("linux_banner")?;
    let (banner_addr, _) =
        get_banner_addr(backend, kpgd)?.ok_or("could not find banner address")?;

    Ok(banner_addr.0.overflowing_sub(base_banner_addr.0).0 as i64)
}

pub const fn is_kernel_addr(addr: GuestVirtAddr) -> bool {
    (addr.0 as i64) < 0
}

impl<B: ice::Backend> Linux<B> {
    pub fn create(backend: B, profile: Profile) -> IceResult<Self> {
        let kpgd = find_kpgd(&backend)?;
        let kaslr = get_aslr(&backend, &profile, kpgd)?;

        Ok(Linux {
            backend,
            profile,
            kpgd,
            kaslr,
        })
    }

    fn kernel_to_physical(&self, addr: GuestVirtAddr) -> IceResult<GuestPhysAddr> {
        self.backend.virtual_to_physical(self.kpgd, addr).valid()
    }

    fn read_kernel_value<T: bytemuck::Pod>(&self, addr: GuestVirtAddr) -> IceResult<T> {
        self.backend.read_value_virtual(self.kpgd, addr)
    }

    pub fn read_tasks(&self) -> IceResult<process::Iter<'_, B>> {
        let init_task = self.profile.fast_syms.init_task + self.kaslr;
        let current_task = self.kernel_to_physical(init_task)?;

        Ok(process::Iter::new(self, ibc::Process(current_task)))
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

    pub fn current_thread(&self, cpuid: usize) -> IceResult<ibc::Thread> {
        let current_task = per_cpu(&self.backend, cpuid)?
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);

        let addr = self.read_kernel_value(current_task)?;
        let addr = self.kernel_to_physical(addr)?;

        Ok(ibc::Thread(addr))
    }

    pub fn iterate_list(
        &self,
        head: GuestPhysAddr,
        mut f: impl FnMut(GuestPhysAddr) -> IceResult<()>,
    ) -> IceResult<()> {
        let mut pos = head;
        let next_offset = self.profile.fast_offsets.list_head_next;

        loop {
            let next = self.backend.read_value(pos + next_offset)?;
            pos = self.kernel_to_physical(next)?;

            if pos == head {
                break;
            }

            f(pos)?;
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

impl<B: ice::Backend> super::OsBuilder<B> for Linux<B> {
    fn quick_check(backend: &B) -> IceResult<bool> {
        let mmu_addr = find_kpgd(backend)?;
        Ok(get_banner_addr(backend, mmu_addr)?.is_some())
    }
}

impl<B: ice::Backend> ice::Os for Linux<B> {
    fn init_process(&self) -> IceResult<ibc::Process> {
        let init_task = self.profile.fast_syms.init_task + self.kaslr;
        Ok(ibc::Process(self.kernel_to_physical(init_task)?))
    }

    fn current_thread(&self, cpuid: usize) -> IceResult<ibc::Thread> {
        self.current_thread(cpuid)
    }

    fn thread_process(&self, thread: ibc::Thread) -> IceResult<ibc::Process> {
        Process::new(ibc::Process(thread.0), self).group_leader()
    }

    fn process_is_kernel(&self, proc: ibc::Process) -> IceResult<bool> {
        Process::new(proc, self).is_kernel()
    }

    fn process_pid(&self, proc: ibc::Process) -> IceResult<u32> {
        Process::new(proc, self).pid()
    }

    fn process_name(&self, proc: ice::Process) -> IceResult<String> {
        Process::new(proc, self).comm()
    }

    fn process_parent(&self, proc: ice::Process) -> IceResult<ice::Process> {
        Process::new(proc, self).parent()
    }

    fn process_for_each_child(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(ibc::Process) -> IceResult<()>,
    ) -> IceResult<()> {
        let offsets = &self.profile.fast_offsets;

        self.iterate_list(proc.0 + offsets.task_struct_children, |addr| {
            f(ibc::Process(addr - offsets.task_struct_sibling))
        })
    }

    fn for_each_process(&self, f: &mut dyn FnMut(ibc::Process) -> IceResult<()>) -> IceResult<()> {
        let mut current = self.init_process()?;

        loop {
            f(current)?;

            current = Process::new(current, self).next()?;
            if self.process_pid(current)? == 0 {
                break;
            }
        }

        Ok(())
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
    use crate::os::{Linux, OsBuilder};

    #[test]
    fn quick_check() {
        let vm = backends::kvm_dump::DumbDump::read("../linux.dump").unwrap();
        assert!(Linux::quick_check(&vm).unwrap());

        let vm = backends::kvm_dump::DumbDump::read("../grub.dump").unwrap();
        assert!(!Linux::quick_check(&vm).unwrap());
    }
}
