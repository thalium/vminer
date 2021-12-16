use alloc::string::String;

use ibc::{IceResult, PhysicalAddress, VirtualAddress};

#[derive(Debug)]
pub(super) struct Process<'a, B> {
    raw: ibc::Process,
    linux: &'a super::Linux<B>,
}

impl<B> Clone for Process<'_, B> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<B> Copy for Process<'_, B> {}

impl<'a, B: ibc::Backend> Process<'a, B> {
    pub fn new(raw: ibc::Process, linux: &'a super::Linux<B>) -> Self {
        Self { raw, linux }
    }

    fn read_value<T: bytemuck::Pod>(&self, offset: u64) -> IceResult<T> {
        Ok(self.linux.backend.read_value(self.raw.0 + offset)?)
    }

    pub fn tid(&self) -> IceResult<u32> {
        self.read_value(self.linux.profile.fast_offsets.task_struct_pid)
    }

    pub fn pid(&self) -> IceResult<u32> {
        self.read_value(self.linux.profile.fast_offsets.task_struct_tgid)
    }

    pub fn mm(&self) -> IceResult<PhysicalAddress> {
        let fast_offsets = &self.linux.profile.fast_offsets;
        let mut mm: VirtualAddress = self.read_value(fast_offsets.task_struct_mm)?;
        if mm.is_null() {
            mm = self.read_value(fast_offsets.task_struct_active_mm)?;
        }

        self.linux.kernel_to_physical(mm)
    }

    pub fn pgd(&self) -> IceResult<PhysicalAddress> {
        let mm = self.mm()?;
        let pgd_ptr = self
            .linux
            .backend
            .read_value(mm + self.linux.profile.fast_offsets.mm_struct_pgd)?;
        let pgd = self.linux.kernel_to_physical(pgd_ptr)?;
        Ok(pgd)
    }

    pub fn group_leader(&self) -> IceResult<ibc::Process> {
        let addr = self.read_value(self.linux.profile.fast_offsets.task_struct_group_leader)?;
        let addr = self.linux.kernel_to_physical(addr)?;
        Ok(ibc::Process(addr))
    }

    pub fn read_comm(&self, buf: &mut [u8]) -> IceResult<()> {
        let buf = if buf.len() >= 16 { &mut buf[..16] } else { buf };
        self.linux.backend.read_memory(
            self.raw.0 + self.linux.profile.fast_offsets.task_struct_comm,
            buf,
        )?;
        Ok(())
    }

    pub fn comm(&self) -> IceResult<String> {
        let mut buf = [0; 16];
        self.read_comm(&mut buf)?;

        let buf = match buf.into_iter().enumerate().find(|(_, b)| *b == 0) {
            Some((i, _)) => &buf[..i],
            None => &buf,
        };

        Ok(String::from_utf8_lossy(buf).into_owned())
    }

    pub fn parent(&self) -> IceResult<ibc::Process> {
        let addr = self.read_value(self.linux.profile.fast_offsets.task_struct_real_parent)?;
        let addr = self.linux.kernel_to_physical(addr)?;
        Ok(ibc::Process(addr))
    }

    pub fn read_field(&self, field_name: &str, buf: &mut [u8]) -> IceResult<()> {
        let task_struct = self.linux.profile.syms.get_struct("task_struct")?;
        let (offset, size) = task_struct.find_offset_and_size(field_name)?;
        let size = size as usize;
        let buf = if buf.len() >= size {
            &mut buf[..size]
        } else {
            buf
        };
        self.linux.backend.read_memory(self.raw.0 + offset, buf)?;
        Ok(())
    }

    fn flags(&self) -> IceResult<u32> {
        let mut flags = 0;
        self.read_field("flags", bytemuck::bytes_of_mut(&mut flags))?;
        Ok(flags)
    }

    pub fn is_kernel(&self) -> IceResult<bool> {
        let flags = self.flags()?;
        Ok(flags & 0x200000 != 0)
    }
}
