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

    pub fn tgid<B: ibc::Backend>(&self, backend: &B) -> IceResult<u32> {
        Ok(backend.read_value(self.addr + self.linux.profile.fast_offsets.task_struct_tgid)?)
    }

    pub fn pgd<B: ibc::Backend>(&self, backend: &B) -> IceResult<GuestPhysAddr> {
        let fast_offsets = &self.linux.profile.fast_offsets;
        let mut mm: GuestVirtAddr = backend.read_value(self.addr + fast_offsets.task_struct_mm)?;
        if mm.is_null() {
            mm = backend.read_value(self.addr + fast_offsets.task_struct_active_mm)?;
        }

        let pgd_ptr =
            backend.read_value_virtual(self.linux.kpgd, mm + fast_offsets.mm_struct_pgd)?;
        let pgd = backend
            .virtual_to_physical(self.linux.kpgd, pgd_ptr)
            .valid()?;
        Ok(pgd)
    }

    pub fn group_leader<B: ibc::Backend>(&self, backend: &B) -> IceResult<Process<'a>> {
        let addr = backend
            .read_value(self.addr + self.linux.profile.fast_offsets.task_struct_group_leader)?;
        let addr = backend.virtual_to_physical(self.linux.kpgd, addr).valid()?;
        Ok(Process::new(addr, self.linux))
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

    pub fn next<B: ibc::Backend>(&self, backend: &B) -> IceResult<Process<'a>> {
        let offsets = &self.linux.profile.fast_offsets;

        let next_offset = offsets.task_struct_tasks + offsets.list_head_next;
        let mut addr = backend.read_value(self.addr + next_offset)?;
        addr -= offsets.task_struct_tasks;
        let addr = backend.virtual_to_physical(self.linux.kpgd, addr).valid()?;

        Ok(Self::new(addr, self.linux))
    }

    pub fn prev<B: ibc::Backend>(&self, backend: &B) -> IceResult<Process<'a>> {
        let offsets = &self.linux.profile.fast_offsets;

        let next_offset = offsets.task_struct_tasks + offsets.list_head_prev;
        let mut addr = backend.read_value(self.addr + next_offset)?;
        addr -= offsets.task_struct_tasks;
        let addr = backend.virtual_to_physical(self.linux.kpgd, addr).valid()?;

        Ok(Self::new(addr, self.linux))
    }
}

#[derive(Debug, Clone, Copy)]
enum State {
    First,
    Running,
    Error,
}

pub struct Iter<'a, 'b, B: ibc::Backend> {
    first_addr: GuestPhysAddr,
    next: Process<'a>,
    state: State,
    backend: &'b B,
}

impl<'a, 'b, B: ibc::Backend> Iterator for Iter<'a, 'b, B> {
    type Item = IceResult<Process<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let current = match self.state {
            State::First => {
                self.state = State::Running;
                self.next
            }
            State::Running => {
                if self.next.addr == self.first_addr {
                    return None;
                }
                self.next
            }
            State::Error => return None,
        };

        self.next = match current.next(self.backend) {
            Ok(next) => next,
            Err(e) => {
                self.state = State::Error;
                return Some(Err(e));
            }
        };
        Some(Ok(current))
    }
}

impl<'a, 'b, B: ibc::Backend> Iter<'a, 'b, B> {
    pub(super) fn new(linux: &'a super::Linux, backend: &'b B, first_addr: GuestPhysAddr) -> Self {
        Self {
            first_addr,
            next: Process::new(first_addr, linux),
            state: State::First,
            backend,
        }
    }
}
