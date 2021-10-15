use std::{
    fs,
    io::{self, Read, Seek, Write},
    mem,
    os::unix::prelude::*,
    path::Path,
};

use crate::core::{
    self as ice,
    arch::{self, x86_64},
    Backend, GuestPhysAddr, MemoryAccessError, MemoryAccessResult,
};

pub enum Mem {
    Bytes(Vec<u8>),
    File(fs::File),
}

pub struct DumbDump {
    vcpus: Vec<arch::x86_64::Vcpu>,
    pub mem: Mem,
}

const MEM_OFFSET: u64 =
    (mem::size_of::<x86_64::Registers>() + mem::size_of::<x86_64::SpecialRegisters>()) as _;

impl DumbDump {
    pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut f = fs::File::open(path)?;

        let mut buf = [0; mem::size_of::<x86_64::Registers>()];
        f.read_exact(&mut buf)?;
        let registers = *bytemuck::from_bytes(&buf);

        let mut buf = [0; mem::size_of::<x86_64::SpecialRegisters>()];
        f.read_exact(&mut buf)?;
        let special_registers = *bytemuck::from_bytes(&buf);

        let mem = Mem::File(f);
        Ok(DumbDump {
            vcpus: vec![x86_64::Vcpu {
                registers,
                special_registers,
            }],
            mem,
        })
    }

    pub fn write<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut out = fs::File::create(path)?;

        match &self.mem {
            Mem::Bytes(b) => {
                out.write_all(bytemuck::bytes_of(&self.vcpus[0].registers))?;
                out.write_all(bytemuck::bytes_of(&self.vcpus[0].special_registers))?;
                out.write_all(b)?;
            }
            Mem::File(f) => {
                let mut f = f;
                f.rewind()?;
                io::copy(&mut f, &mut out)?;
            }
        }

        Ok(())
    }

    pub fn dump_vm<B: Backend<arch::X86_64>>(backend: &B) -> io::Result<DumbDump> {
        let mut mem = vec![0; 2 << 30];
        backend.read_memory(GuestPhysAddr(0), &mut mem).unwrap();

        let vcpu = &backend.vcpus()[0];

        let dump = DumbDump {
            vcpus: vec![x86_64::Vcpu {
                registers: vcpu.registers,
                special_registers: vcpu.special_registers,
            }],
            mem: Mem::Bytes(mem),
        };
        Ok(dump)
    }
}

impl Backend<ice::arch::X86_64> for DumbDump {
    fn vcpus(&self) -> &[x86_64::Vcpu] {
        &self.vcpus
    }

    fn read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> MemoryAccessResult<()> {
        match &self.mem {
            Mem::Bytes(mem) => {
                let start = addr.0 as usize;
                match mem.get(start..start + buf.len()) {
                    Some(mem) => {
                        buf.copy_from_slice(mem);
                        Ok(())
                    }
                    None => Err(MemoryAccessError::OutOfBounds),
                }
            }
            Mem::File(f) => f
                .read_exact_at(buf, addr.0 + MEM_OFFSET)
                .map_err(|e| MemoryAccessError::Io(e.into())),
        }
    }

    fn write_memory(&mut self, addr: GuestPhysAddr, buf: &[u8]) -> MemoryAccessResult<()> {
        match &mut self.mem {
            Mem::Bytes(mem) => {
                let start = addr.0 as usize;
                match mem.get_mut(start..start + buf.len()) {
                    Some(mem) => {
                        mem.copy_from_slice(buf);
                        Ok(())
                    }
                    None => Err(MemoryAccessError::OutOfBounds),
                }
            }
            Mem::File(f) => f
                .write_all_at(buf, addr.0 + MEM_OFFSET)
                .map_err(|e| MemoryAccessError::Io(e.into())),
        }
    }
}
