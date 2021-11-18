use alloc::string::String;

use ibc::{GuestPhysAddr, GuestVirtAddr, IceResult};

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

#[allow(dead_code)]
impl<'a, B: ibc::Backend> Process<'a, B> {
    pub fn new(raw: ibc::Process, linux: &'a super::Linux<B>) -> Self {
        Self { raw, linux }
    }

    fn read_value<T: bytemuck::Pod>(&self, offset: u64) -> IceResult<T> {
        Ok(self.linux.backend.read_value(self.raw.0 + offset)?)
    }

    pub fn pid(&self) -> IceResult<u32> {
        self.read_value(self.linux.profile.fast_offsets.task_struct_pid)
    }

    pub fn tgid(&self) -> IceResult<u32> {
        self.read_value(self.linux.profile.fast_offsets.task_struct_tgid)
    }

    pub fn pgd(&self) -> IceResult<GuestPhysAddr> {
        let fast_offsets = &self.linux.profile.fast_offsets;
        let mut mm: GuestVirtAddr =
            self.read_value(self.linux.profile.fast_offsets.task_struct_mm)?;
        if mm.is_null() {
            mm = self.read_value(self.linux.profile.fast_offsets.task_struct_active_mm)?;
        }

        let pgd_ptr = self
            .linux
            .read_kernel_value(mm + fast_offsets.mm_struct_pgd)?;
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

    pub fn next(&self) -> IceResult<ibc::Process> {
        let offsets = &self.linux.profile.fast_offsets;

        let next_offset = offsets.task_struct_tasks + offsets.list_head_next;
        let mut addr = self.read_value(next_offset)?;
        addr -= offsets.task_struct_tasks;
        let addr = self.linux.kernel_to_physical(addr)?;

        Ok(ibc::Process(addr))
    }

    pub fn prev(&self) -> IceResult<ibc::Process> {
        let offsets = &self.linux.profile.fast_offsets;

        let prev_offset = offsets.task_struct_tasks + offsets.list_head_prev;
        let mut addr = self.read_value(prev_offset)?;
        addr -= offsets.task_struct_tasks;
        let addr = self.linux.kernel_to_physical(addr)?;

        Ok(ibc::Process(addr))
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

#[derive(Debug, Clone, Copy)]
enum State {
    First,
    Running,
    Error,
}

pub struct Iter<'a, B: ibc::Backend> {
    linux: &'a super::Linux<B>,
    first: ibc::Process,
    next: ibc::Process,
    state: State,
}

impl<'a, B: ibc::Backend> Iterator for Iter<'a, B> {
    type Item = IceResult<ibc::Process>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = match self.state {
            State::First => {
                self.state = State::Running;
                self.next
            }
            State::Running => {
                if self.next == self.first {
                    return None;
                }
                self.next
            }
            State::Error => return None,
        };

        self.next = match Process::new(current, self.linux).next() {
            Ok(next) => next,
            Err(e) => {
                self.state = State::Error;
                return Some(Err(e));
            }
        };
        Some(Ok(current))
    }
}

impl<'a, B: ibc::Backend> Iter<'a, B> {
    pub(super) fn new(linux: &'a super::Linux<B>, first: ibc::Process) -> Self {
        Self {
            linux,
            first,
            next: first,
            state: State::First,
        }
    }
}
