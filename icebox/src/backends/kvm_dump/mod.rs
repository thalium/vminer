use crate::core::{
    self as ice,
    arch::{self, x86_64},
    Backend, GuestPhysAddr, Memory,
};
use std::{
    fs,
    io::{self, Read, Seek, Write},
    mem,
    path::Path,
};

pub struct DumbDump<Mem> {
    vcpus: Vec<arch::x86_64::Vcpu>,
    mem: Mem,
}

const MEM_OFFSET: u64 =
    (mem::size_of::<x86_64::Registers>() + mem::size_of::<x86_64::SpecialRegisters>()) as _;

impl DumbDump<ice::File> {
    pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut f = fs::File::open(path)?;

        let mut buf = [0; mem::size_of::<x86_64::Registers>()];
        f.read_exact(&mut buf)?;
        let registers = *bytemuck::from_bytes(&buf);

        let mut buf = [0; mem::size_of::<x86_64::SpecialRegisters>()];
        f.read_exact(&mut buf)?;
        let special_registers = *bytemuck::from_bytes(&buf);

        let end = f.seek(io::SeekFrom::End(0))?;

        Ok(DumbDump {
            vcpus: vec![x86_64::Vcpu {
                registers,
                special_registers,
            }],
            mem: ice::File::new(f, MEM_OFFSET, end),
        })
    }
}

impl<Mem: ice::Memory> DumbDump<Mem> {
    pub fn write<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut out = fs::File::create(path)?;

        out.write_all(bytemuck::bytes_of(&self.vcpus[0].registers))?;
        out.write_all(bytemuck::bytes_of(&self.vcpus[0].special_registers))?;

        let size = self.mem.size();
        let mut buf = [0; 4096];

        for addr in (0..size).step_by(buf.len() as _) {
            self.mem.read(GuestPhysAddr(addr), &mut buf)?;
            out.write_all(&buf)?;
        }

        Ok(())
    }
}

impl DumbDump<Vec<u8>> {
    pub fn dump_vm<B: Backend<Arch = arch::X86_64>>(backend: &B) -> io::Result<Self> {
        let memory = backend.memory();
        let mut mem = vec![0; memory.size() as usize];
        memory.read(GuestPhysAddr(0), &mut mem).unwrap();

        let dump = DumbDump {
            vcpus: backend.vcpus().to_vec(),
            mem,
        };
        Ok(dump)
    }
}

impl<Mem: ice::Memory> Backend for DumbDump<Mem> {
    type Arch = ice::arch::X86_64;
    type Memory = Mem;

    fn vcpus(&self) -> &[x86_64::Vcpu] {
        &self.vcpus
    }

    fn memory(&self) -> &Self::Memory {
        &self.mem
    }
}
