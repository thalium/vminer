use std::{
    fs,
    io::{self, Read, Seek, Write},
    mem,
    os::unix::prelude::*,
    path::Path,
};

use crate::{Backend, GuestPhysAddr};

pub enum Mem {
    Bytes(Vec<u8>),
    File(fs::File),
}

pub struct DumbDump {
    pub regs: kvm_common::kvm_regs,
    pub sregs: kvm_common::kvm_sregs,
    pub mem: Mem,
}

const MEM_OFFSET: u64 =
    (mem::size_of::<kvm_common::kvm_regs>() + mem::size_of::<kvm_common::kvm_sregs>()) as _;

impl DumbDump {
    pub fn read<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut f = fs::File::open(path)?;

        let mut buf = [0; mem::size_of::<kvm_common::kvm_regs>()];
        f.read_exact(&mut buf)?;
        let regs = *bytemuck::from_bytes(&buf);

        let mut buf = [0; mem::size_of::<kvm_common::kvm_sregs>()];
        f.read_exact(&mut buf)?;
        let sregs = *bytemuck::from_bytes(&buf);

        let mem = Mem::File(f);
        Ok(DumbDump { regs, sregs, mem })
    }

    pub fn write<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
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
}

impl Backend for DumbDump {
    fn get_regs(&self) -> &kvm_common::kvm_regs {
        &self.regs
    }

    fn get_sregs(&self) -> &kvm_common::kvm_sregs {
        &self.sregs
    }

    fn read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> io::Result<()> {
        match &self.mem {
            Mem::Bytes(mem) => {
                let start = addr.0 as usize;
                buf.copy_from_slice(&mem[start..start + buf.len()]);
                Ok(())
            }
            Mem::File(f) => f.read_exact_at(buf, addr.0 + MEM_OFFSET),
        }
    }

    fn write_memory(&mut self, addr: GuestPhysAddr, buf: &[u8]) -> io::Result<()> {
        match &mut self.mem {
            Mem::Bytes(mem) => {
                let start = addr.0 as usize;
                mem[start..start + buf.len()].copy_from_slice(buf);
                Ok(())
            }
            Mem::File(f) => f.write_all_at(buf, addr.0 + MEM_OFFSET),
        }
    }
}
