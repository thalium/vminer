use bytemuck::Zeroable;

use crate::core::{
    self as ice,
    arch::{self, x86_64},
    Backend, GuestPhysAddr, Memory,
};
use std::{
    fs,
    io::{self, Read, Seek, Write},
    path::Path,
};

pub struct DumbDump<Mem> {
    vcpus: Vec<arch::x86_64::Vcpu>,
    mem: Mem,
}

impl DumbDump<ice::File> {
    pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = io::BufReader::new(fs::File::open(path)?);

        let mut n_vcpus = 0;
        file.read_exact(bytemuck::bytes_of_mut(&mut n_vcpus))?;

        let mut vcpus = Vec::with_capacity(n_vcpus);

        for _ in 0..n_vcpus {
            let mut vcpu = x86_64::Vcpu {
                registers: Zeroable::zeroed(),
                special_registers: Zeroable::zeroed(),
                gs_kernel_base: 0,
            };

            file.read_exact(bytemuck::bytes_of_mut(&mut vcpu.registers))?;
            file.read_exact(bytemuck::bytes_of_mut(&mut vcpu.special_registers))?;
            file.read_exact(bytemuck::bytes_of_mut(&mut vcpu.gs_kernel_base))?;

            vcpus.push(vcpu);
        }

        let start = file.stream_position()?;
        let mut file = file.into_inner();
        let end = file.seek(io::SeekFrom::End(0))?;

        Ok(DumbDump {
            vcpus,
            mem: ice::File::new(file, start, end),
        })
    }
}

impl<Mem: ice::Memory> DumbDump<Mem> {
    pub fn write<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut out = io::BufWriter::new(fs::File::create(path)?);

        let vcpus = &*self.vcpus;
        out.write_all(bytemuck::bytes_of(&vcpus.len()))?;

        for vcpu in vcpus {
            out.write_all(bytemuck::bytes_of(&vcpu.registers))?;
            out.write_all(bytemuck::bytes_of(&vcpu.special_registers))?;
            out.write_all(bytemuck::bytes_of(&vcpu.gs_kernel_base))?;
        }

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

    fn arch(&self) -> &Self::Arch {
        &ice::arch::X86_64
    }

    fn vcpus(&self) -> &[x86_64::Vcpu] {
        &self.vcpus
    }

    fn memory(&self) -> &Self::Memory {
        &self.mem
    }
}
