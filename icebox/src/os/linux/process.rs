use alloc::string::String;

use ibc::{GuestPhysAddr, GuestVirtAddr, IceResult, MemoryAccessResultExt};

#[derive(Debug, Clone, Copy)]
pub struct Process<'a> {
    pub addr: GuestPhysAddr,
    linux: &'a super::Linux,
}

impl<'a> Process<'a> {
    pub fn new(addr: GuestPhysAddr, linux: &'a super::Linux) -> Self {
        Self { addr, linux }
    }

    pub fn pid<B: ibc::Backend>(&self, backend: &B) -> IceResult<u32> {
        Ok(backend.read_value(self.addr + self.linux.profile.fast_offsets.task_struct_pid)?)
    }

    pub fn pgd<B: ibc::Backend<Arch = ibc::arch::X86_64>>(
        &self,
        backend: &B,
    ) -> IceResult<GuestPhysAddr> {
        let mmu_addr = super::kernel_page_dir(backend, &self.linux.profile)?;
        let fast_offsets = &self.linux.profile.fast_offsets;
        let mut mm: GuestVirtAddr = backend.read_value(self.addr + fast_offsets.task_struct_mm)?;
        if mm.is_null() {
            mm = backend.read_value(self.addr + fast_offsets.task_struct_active_mm)?;
        }

        let mm = backend.virtual_to_physical(mmu_addr, mm).valid()?;
        let pgd_ptr = backend.read_value(mm + fast_offsets.mm_struct_pgd)?;
        let pgd = backend.virtual_to_physical(mmu_addr, pgd_ptr).valid()?;
        Ok(pgd)
    }

    pub fn read_comm<B: ibc::Backend>(&self, backend: &B, buf: &mut [u8]) -> IceResult<()> {
        let buf = if buf.len() >= 16 { &mut buf[..16] } else { buf };
        backend.read_memory(
            self.addr + self.linux.profile.fast_offsets.task_struct_comm,
            buf,
        )?;
        Ok(())
    }

    pub fn comm<B: ibc::Backend>(&self, backend: &B) -> IceResult<String> {
        let mut buf = [0; 16];
        self.read_comm(backend, &mut buf)?;

        let buf = match buf.into_iter().enumerate().find(|(_, b)| *b == 0) {
            Some((i, _)) => &buf[..i],
            None => &buf,
        };

        Ok(String::from_utf8_lossy(buf).into_owned())
    }

    pub fn read_field<B: ibc::Backend>(
        &self,
        backend: &B,
        field_name: &str,
        buf: &mut [u8],
    ) -> IceResult<()> {
        let task_struct = self.linux.profile.syms.get_struct("task_struct")?;
        let (offset, size) = task_struct.find_offset_and_size(field_name)?;
        let size = size as usize;
        let buf = if buf.len() >= size {
            &mut buf[..size]
        } else {
            buf
        };
        backend.read_memory(self.addr + offset, buf)?;
        Ok(())
    }
}
