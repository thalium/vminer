use std::{
    fs,
    io::{self, Read, Seek, Write},
    mem,
    os::unix::prelude::*,
    path::Path,
};

use crate::core::{Backend, GuestPhysAddr, MemoryAccessError, MemoryAccessResult};

pub enum Mem {
    Bytes(Vec<u8>),
    File(fs::File),
}

pub struct DumbDump {
    pub regs: kvm::kvm_regs,
    pub sregs: kvm::kvm_sregs,
    pub mem: Mem,
}

const MEM_OFFSET: u64 = (mem::size_of::<kvm::kvm_regs>() + mem::size_of::<kvm::kvm_sregs>()) as _;

impl DumbDump {
    pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut f = fs::File::open(path)?;

        let mut buf = [0; mem::size_of::<kvm::kvm_regs>()];
        f.read_exact(&mut buf)?;
        let regs = *bytemuck::from_bytes(&buf);

        let mut buf = [0; mem::size_of::<kvm::kvm_sregs>()];
        f.read_exact(&mut buf)?;
        let sregs = *bytemuck::from_bytes(&buf);

        let mem = Mem::File(f);
        Ok(DumbDump { regs, sregs, mem })
    }

    pub fn write<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut out = fs::File::create(path)?;

        match &self.mem {
            Mem::Bytes(b) => {
                out.write_all(bytemuck::bytes_of(&self.regs))?;
                out.write_all(bytemuck::bytes_of(&self.sregs))?;
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

    pub fn dump_vm<B: Backend>(backend: &B) -> io::Result<DumbDump> {
        let mut mem = vec![0; 2 << 30];
        backend.read_memory(GuestPhysAddr(0), &mut mem).unwrap();

        let dump = DumbDump {
            regs: *backend.get_regs(),
            sregs: *backend.get_sregs(),
            mem: Mem::Bytes(mem),
        };
        Ok(dump)
    }
}

impl Backend for DumbDump {
    fn get_regs(&self) -> &kvm::kvm_regs {
        &self.regs
    }

    fn get_sregs(&self) -> &kvm::kvm_sregs {
        &self.sregs
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
