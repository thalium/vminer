pub mod profile;
pub use profile::Profile;

use crate::core::{self as ice, GuestPhysAddr, GuestVirtAddr, MemoryAccessResult};
use alloc::string::String;
use core::str;

#[derive(Debug, Clone, Copy)]
pub struct Process(GuestPhysAddr);

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
) -> MemoryAccessResult<Option<GuestPhysAddr>> {
    let addr =
        per_cpu(backend, 0) + (profile.fast_syms.current_task - profile.fast_syms.per_cpu_start);

    for vcpu in backend.vcpus() {
        let cr3 = GuestPhysAddr(vcpu.special_registers.cr3);

        if backend.virtual_to_physical(cr3, addr)?.is_some() {
            return Ok(Some(cr3));
        }
    }

    Ok(None)
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
        let mmu_addr = kernel_page_dir(backend, &self.profile)?.unwrap();
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
        let mmu_addr = kernel_page_dir(backend, &self.profile)?.unwrap();

        let task_struct = self.profile.syms.get_struct("task_struct").unwrap();
        let list_head = self.profile.syms.get_struct("list_head").unwrap();
        let init_task = self.profile.syms.get_addr("init_task").unwrap() + kaslr;

        let next_offset = list_head.find_offset("next").unwrap();
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
        cpuid: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mmu_addr = kernel_page_dir(backend, &self.profile)?.unwrap();

        let current_task = per_cpu(backend, cpuid)
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

    pub fn current_process<B: ice::Backend<Arch = ice::arch::X86_64>>(
        &self,
        backend: &B,
        cpuid: usize,
    ) -> ice::MemoryAccessResult<Process> {
        let mmu_addr = kernel_page_dir(backend, &self.profile)?.unwrap();

        let current_task = per_cpu(backend, cpuid)
            + (self.profile.fast_syms.current_task - self.profile.fast_syms.per_cpu_start);
        let current_task = backend
            .virtual_to_physical(mmu_addr, current_task)?
            .unwrap();

        let mut addr = GuestVirtAddr(0);
        backend.read_memory(current_task, bytemuck::bytes_of_mut(&mut addr))?;

        Ok(Process(
            backend.virtual_to_physical(mmu_addr, addr)?.unwrap(),
        ))
    }

    pub fn read_process_id<B: ice::Backend>(
        &self,
        backend: &B,
        proc: Process,
    ) -> ice::MemoryAccessResult<u32> {
        let mut pid = 0u32;
        backend.read_memory(
            proc.0 + self.profile.fast_offsets.task_struct_pid,
            bytemuck::bytes_of_mut(&mut pid),
        )?;
        Ok(pid)
    }

    pub fn read_process_pgd<B: ice::Backend<Arch = ice::arch::X86_64>>(
        &self,
        backend: &B,
        proc: Process,
    ) -> ice::MemoryAccessResult<GuestPhysAddr> {
        let mmu_addr = kernel_page_dir(backend, &self.profile)?.unwrap();
        let fast_offsets = &self.profile.fast_offsets;
        let mut mm = GuestVirtAddr(0);
        backend.read_memory(
            proc.0 + fast_offsets.task_struct_mm,
            bytemuck::bytes_of_mut(&mut mm),
        )?;
        if mm.is_null() {
            backend.read_memory(
                proc.0 + fast_offsets.task_struct_active_mm,
                bytemuck::bytes_of_mut(&mut mm),
            )?;
        }

        let mm = backend.virtual_to_physical(mmu_addr, mm)?.unwrap();
        let mut pgd_ptr = GuestVirtAddr(0);
        backend.read_memory(
            mm + fast_offsets.mm_struct_pgd,
            bytemuck::bytes_of_mut(&mut pgd_ptr),
        )?;
        let pgd = backend.virtual_to_physical(mmu_addr, pgd_ptr)?.unwrap();
        Ok(pgd)
    }

    pub fn read_process_comm<B: ice::Backend>(
        &self,
        backend: &B,
        proc: Process,
        buf: &mut [u8],
    ) -> ice::MemoryAccessResult<()> {
        let buf = if buf.len() >= 16 { &mut buf[..16] } else { buf };
        backend.read_memory(proc.0 + self.profile.fast_offsets.task_struct_comm, buf)?;
        Ok(())
    }

    pub fn read_process_comm_to_string<B: ice::Backend>(
        &self,
        backend: &B,
        proc: Process,
    ) -> ice::MemoryAccessResult<String> {
        let mut buf = [0; 16];
        self.read_process_comm(backend, proc, &mut buf)?;

        let buf = match buf.into_iter().enumerate().find(|(_, b)| *b == 0) {
            Some((i, _)) => &buf[..i],
            None => &buf,
        };

        Ok(String::from_utf8_lossy(buf).into_owned())
    }

    pub fn read_process_field<B: ice::Backend>(
        &self,
        backend: &B,
        proc: Process,
        field_name: &str,
        buf: &mut [u8],
    ) -> ice::MemoryAccessResult<()> {
        let task_struct = self.profile.syms.get_struct("task_struct").unwrap();
        let (offset, size) = task_struct.find_offset_and_size(field_name).unwrap();
        let size = size as usize;
        let buf = if buf.len() >= size {
            &mut buf[..size]
        } else {
            buf
        };
        backend.read_memory(proc.0 + offset, buf)?;
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
