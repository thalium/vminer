use bytemuck::Zeroable;
use ibc::{
    arch::{self, aarch64, x86_64, Vcpus as _},
    PhysicalAddress,
};
use std::{
    fs,
    io::{self, Read, Seek, Write},
    path::Path,
};

#[derive(Debug)]
enum Vcpus {
    X86_64(Vec<arch::x86_64::Vcpu>),
    Aarch64(Vec<arch::aarch64::Vcpu>),
}

impl Vcpus {
    fn read_x86_64<R: Read>(mut reader: R, n_vcpus: usize) -> io::Result<Self> {
        let mut vcpus = Vec::with_capacity(n_vcpus as usize);

        for _ in 0..n_vcpus {
            let mut vcpu = x86_64::Vcpu {
                registers: Zeroable::zeroed(),
                special_registers: Zeroable::zeroed(),
                lstar: 0,
                gs_kernel_base: 0,
            };

            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.registers))?;
            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.special_registers))?;
            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.lstar))?;
            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.gs_kernel_base))?;

            vcpus.push(vcpu);
        }

        Ok(Self::X86_64(vcpus))
    }

    fn read_aarch64<R: Read>(mut reader: R, n_vcpus: usize) -> io::Result<Self> {
        let mut vcpus = Vec::with_capacity(n_vcpus as usize);

        for _ in 0..n_vcpus {
            let mut vcpu = aarch64::Vcpu {
                registers: Zeroable::zeroed(),
                special_registers: Zeroable::zeroed(),
            };

            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.registers))?;
            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.special_registers))?;

            vcpus.push(vcpu);
        }

        Ok(Self::Aarch64(vcpus))
    }
}

#[derive(Debug)]
pub struct DumbDump<Mem> {
    vcpus: Vcpus,
    mem: Mem,
}

impl DumbDump<ibc::File> {
    pub fn read<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = io::BufReader::new(fs::File::open(path)?);

        let mut arch = 0u32;
        file.read_exact(bytemuck::bytes_of_mut(&mut arch))?;

        let mut n_vcpus = 0u32;
        file.read_exact(bytemuck::bytes_of_mut(&mut n_vcpus))?;

        let vcpus = match arch {
            0 => Vcpus::read_x86_64(&mut file, n_vcpus as _)?,
            1 => Vcpus::read_aarch64(&mut file, n_vcpus as _)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported architecture",
                ))
            }
        };

        let start = file.stream_position()?;
        let mut file = file.into_inner();
        let end = file.seek(io::SeekFrom::End(0))?;

        Ok(DumbDump {
            vcpus,
            mem: ibc::File::new(file, start, end),
        })
    }
}

impl<Mem: ibc::Memory> DumbDump<Mem> {
    pub fn write<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut out = io::BufWriter::new(fs::File::create(path)?);

        match &self.vcpus {
            Vcpus::X86_64(vcpus) => {
                out.write_all(bytemuck::bytes_of(&0u32))?;
                out.write_all(bytemuck::bytes_of(&(vcpus.len() as u32)))?;

                for vcpu in vcpus {
                    out.write_all(bytemuck::bytes_of(&vcpu.registers))?;
                    out.write_all(bytemuck::bytes_of(&vcpu.special_registers))?;
                    out.write_all(bytemuck::bytes_of(&vcpu.lstar))?;
                    out.write_all(bytemuck::bytes_of(&vcpu.gs_kernel_base))?;
                }
            }
            Vcpus::Aarch64(vcpus) => {
                out.write_all(bytemuck::bytes_of(&1u32))?;
                out.write_all(bytemuck::bytes_of(&(vcpus.len() as u32)))?;

                for vcpu in vcpus {
                    out.write_all(bytemuck::bytes_of(&vcpu.registers))?;
                    out.write_all(bytemuck::bytes_of(&vcpu.special_registers))?;
                }
            }
        }

        self.mem.dump(&mut out)?;

        Ok(())
    }
}

impl DumbDump<Vec<u8>> {
    pub fn dump_vm<B: ibc::Backend>(backend: &B) -> io::Result<Self> {
        let mut mem = vec![0; backend.memory_size() as usize];
        backend.read_memory(PhysicalAddress(0), &mut mem).unwrap();

        let vcpus = match backend.vcpus().into_runtime() {
            arch::runtime::Vcpus::X86_64(vcpus) => Vcpus::X86_64(vcpus.to_vec()),
            arch::runtime::Vcpus::Aarch64(vcpus) => Vcpus::Aarch64(vcpus.to_vec()),
        };

        let dump = DumbDump { vcpus, mem };
        Ok(dump)
    }
}

impl<Mem: ibc::Memory> ibc::RawBackend for DumbDump<Mem> {
    type Arch = arch::RuntimeArchitecture;
    type Memory = Mem;

    #[inline]
    fn vcpus(&self) -> arch::runtime::Vcpus {
        match &self.vcpus {
            Vcpus::X86_64(vcpus) => arch::runtime::Vcpus::X86_64(vcpus),
            Vcpus::Aarch64(vcpus) => arch::runtime::Vcpus::Aarch64(vcpus),
        }
    }

    #[inline]
    fn memory(&self) -> &Self::Memory {
        &self.mem
    }
}
