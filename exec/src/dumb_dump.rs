use std::{fs, io, path::Path};

use crate::{Backend, GuestPhysAddr};

#[derive(serde::Serialize, serde::Deserialize)]
pub struct DumbDump {
    pub regs: kvm_common::kvm_regs,
    pub sregs: kvm_common::kvm_sregs,
    pub mem: Vec<u8>,
}

impl DumbDump {
    pub fn read<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let f = io::BufReader::new(fs::File::open(path)?);
        let res = bincode::deserialize_from(f)?;
        Ok(res)
    }

    pub fn write<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let f = io::BufWriter::new(fs::File::create(path)?);
        bincode::serialize_into(f, self)?;
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
        let start = addr.0 as usize;
        let mem = &self.mem[start..start + buf.len()];
        buf.copy_from_slice(mem);
        Ok(())
    }

    fn write_memory(&mut self, addr: GuestPhysAddr, buf: &[u8]) -> io::Result<()> {
        let start = addr.0 as usize;
        let mem = &mut self.mem[start..start + buf.len()];
        mem.copy_from_slice(buf);
        Ok(())
    }
}