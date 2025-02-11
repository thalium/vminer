use bytemuck::Zeroable;
use std::{
    fs,
    io::{self, Read, Seek, Write},
    path::Path,
};
use vmc::{
    arch::{self, aarch64, x86_64, HasVcpus},
    Architecture, Memory, PhysicalAddress, VmResult,
};

#[derive(Debug, Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct Header {
    magic: u32,
    arch: u32,
    n_mappings: u32,
    n_vcpus: u32,
}

const MAGIC: u32 = u32::from_le_bytes(*b"\xaabox");

#[derive(Debug)]
enum Vcpus {
    X86_64(Vec<arch::x86_64::Vcpu>),
    Aarch64(Vec<arch::aarch64::Vcpu>),
    Riscv64(Vec<arch::riscv64::Vcpu>),
}

impl Vcpus {
    fn read_x86_64<R: Read>(mut reader: R, n_vcpus: usize) -> io::Result<Self> {
        let mut vcpus = Vec::with_capacity(n_vcpus);

        for _ in 0..n_vcpus {
            let mut vcpu = x86_64::Vcpu::zeroed();

            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.registers))?;
            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.special_registers))?;
            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.other_registers))?;

            vcpus.push(vcpu);
        }

        Ok(Self::X86_64(vcpus))
    }

    fn read_aarch64<R: Read>(mut reader: R, n_vcpus: usize) -> io::Result<Self> {
        let mut vcpus = Vec::with_capacity(n_vcpus);

        for _ in 0..n_vcpus {
            let mut vcpu = aarch64::Vcpu::zeroed();

            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.registers))?;
            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.special_registers))?;
            reader.read_exact(bytemuck::bytes_of_mut(&mut vcpu.other_registers))?;

            vcpus.push(vcpu);
        }

        Ok(Self::Aarch64(vcpus))
    }
}

#[derive(Debug)]
pub struct DumbDump<Mem> {
    vcpus: Vcpus,
    mem: vmc::mem::MemRemap<Mem>,
}

impl DumbDump<vmc::mem::File> {
    pub fn read<P: AsRef<Path>>(path: P) -> VmResult<Self> {
        let mut file = io::BufReader::new(fs::File::open(path)?);

        let mut header = Header::zeroed();
        file.read_exact(bytemuck::bytes_of_mut(&mut header))?;

        if header.magic != MAGIC {
            return Err(vmc::VmError::new("invalid file magic"));
        }

        let mut mappings = vec![vmc::mem::MemoryMap::zeroed(); header.n_mappings as _];
        file.read_exact(bytemuck::cast_slice_mut(&mut mappings))?;

        let mut remap_addr = PhysicalAddress(0);
        let remap_at = mappings
            .iter()
            .map(|mapping| {
                let offset = remap_addr;
                remap_addr += mapping.end - mapping.start;
                offset
            })
            .collect();

        let vcpus = match header.arch {
            0 => Vcpus::read_x86_64(&mut file, header.n_vcpus as _)?,
            1 => Vcpus::read_aarch64(&mut file, header.n_vcpus as _)?,
            _ => return Err(vmc::VmError::new("unsupported architecture")),
        };

        let start = file.stream_position()?;
        let mut file = file.into_inner();
        let end = file.seek(io::SeekFrom::End(0))?;

        let mem_size: i64 = mappings.iter().map(|map| map.end - map.start).sum();
        if end - start != mem_size as u64 {
            println!(
                "memsize 0x{mem_size:x} ; 0x{end:x} - 0x{start:x} = 0x{:x}",
                end - start
            );
            return Err(vmc::VmError::new("invalid file size"));
        }

        let mem =
            vmc::mem::MemRemap::new(vmc::mem::File::new(file, start, end), mappings, remap_at);

        Ok(DumbDump { vcpus, mem })
    }
}

impl<Mem: vmc::Memory> DumbDump<Mem> {
    pub fn write<P: AsRef<Path>>(&self, path: P) -> io::Result<()> {
        let mut out = io::BufWriter::new(fs::File::create(path)?);

        let mappings = self.mem.memory_mappings();

        let mut header = Header {
            magic: MAGIC,
            n_mappings: mappings.len() as u32,
            arch: 0,
            n_vcpus: 0,
        };

        match &self.vcpus {
            Vcpus::X86_64(vcpus) => {
                header.arch = 0;
                header.n_vcpus = vcpus.len() as u32;
            }
            Vcpus::Aarch64(vcpus) => {
                header.arch = 1;
                header.n_vcpus = vcpus.len() as u32;
            }
            Vcpus::Riscv64(vcpus) => {
                header.arch = 2;
                header.n_vcpus = vcpus.len() as u32;
            }
        }

        out.write_all(bytemuck::bytes_of(&header))?;
        out.write_all(bytemuck::cast_slice(mappings))?;

        match &self.vcpus {
            Vcpus::X86_64(vcpus) => {
                for vcpu in vcpus {
                    out.write_all(bytemuck::bytes_of(&vcpu.registers))?;
                    out.write_all(bytemuck::bytes_of(&vcpu.special_registers))?;
                    out.write_all(bytemuck::bytes_of(&vcpu.other_registers))?;
                }
            }
            Vcpus::Aarch64(vcpus) => {
                for vcpu in vcpus {
                    out.write_all(bytemuck::bytes_of(&vcpu.registers))?;
                    out.write_all(bytemuck::bytes_of(&vcpu.special_registers))?;
                    out.write_all(bytemuck::bytes_of(&vcpu.other_registers))?;
                }
            }
            Vcpus::Riscv64(vcpus) => {
                for vcpu in vcpus {
                    out.write_all(bytemuck::bytes_of(&vcpu.registers))?;
                    out.write_all(bytemuck::bytes_of(&vcpu.special_registers))?;
                    out.write_all(bytemuck::bytes_of(&vcpu.other_registers))?;
                }
            }
        }

        self.mem.dump(&mut out)?;

        Ok(())
    }
}

impl DumbDump<vmc::mem::RawMemory<Vec<u8>>> {
    pub fn dump_vm<B: vmc::Backend>(backend: &B) -> VmResult<Self> {
        let mappings = backend.memory_mappings().to_owned();

        let mut remap_addr = PhysicalAddress(0);
        let remap_at = mappings
            .iter()
            .map(|mapping| {
                let offset = remap_addr;
                remap_addr += mapping.end - mapping.start;
                offset
            })
            .collect();

        let mut mem = vec![0; remap_addr.0 as usize];
        let mut offset = 0;
        for mapping in &mappings {
            let next_offset = offset + (mapping.end - mapping.start) as usize;
            backend.read_physical(mapping.start, &mut mem[offset..next_offset])?;
            offset = next_offset;
        }

        let vcpus = match backend.arch().into_runtime() {
            arch::RuntimeArchitecture::X86_64(_) => {
                let backend = vmc::arch::AssumeX86_64(backend);
                let mut vcpus = Vec::with_capacity(backend.vcpus_count());
                for vcpu in backend.iter_vcpus() {
                    vcpus.push(vmc::arch::x86_64::Vcpu {
                        registers: backend.registers(vcpu)?,
                        special_registers: backend.special_registers(vcpu)?,
                        other_registers: backend.other_registers(vcpu)?,
                    })
                }
                Vcpus::X86_64(vcpus)
            }
            arch::RuntimeArchitecture::Aarch64(_) => {
                let backend = vmc::arch::AssumeAarch64(backend);
                let mut vcpus = Vec::with_capacity(backend.vcpus_count());
                for vcpu in backend.iter_vcpus() {
                    vcpus.push(vmc::arch::aarch64::Vcpu {
                        registers: backend.registers(vcpu)?,
                        special_registers: backend.special_registers(vcpu)?,
                        other_registers: backend.other_registers(vcpu)?,
                    })
                }
                Vcpus::Aarch64(vcpus)
            }
            arch::RuntimeArchitecture::Riscv64(_) => {
                let backend = vmc::arch::AssumeRiscv64(backend);
                let mut vcpus = Vec::with_capacity(backend.vcpus_count());
                for vcpu in backend.iter_vcpus() {
                    vcpus.push(vmc::arch::riscv64::Vcpu {
                        registers: backend.registers(vcpu)?,
                        special_registers: backend.special_registers(vcpu)?,
                        other_registers: backend.other_registers(vcpu)?,
                    })
                }
                Vcpus::Riscv64(vcpus)
            }
        };

        let mem = vmc::mem::RawMemory::new(mem);
        let mem = vmc::mem::MemRemap::new(mem, mappings, remap_at);

        let dump = DumbDump { vcpus, mem };
        Ok(dump)
    }
}

impl<Mem: vmc::Memory> vmc::Memory for DumbDump<Mem> {
    #[inline]
    fn memory_mappings(&self) -> &[vmc::mem::MemoryMap] {
        self.mem.memory_mappings()
    }

    #[inline]
    fn is_valid(&self, addr: PhysicalAddress, size: usize) -> bool {
        self.mem.is_valid(addr, size)
    }

    #[inline]
    fn read_physical(&self, addr: PhysicalAddress, buf: &mut [u8]) -> vmc::MemoryAccessResult<()> {
        self.mem.read_physical(addr, buf)
    }

    #[inline]
    fn search(
        &self,
        addr: PhysicalAddress,
        page_size: u64,
        finder: &memchr::memmem::Finder,
        buf: &mut [u8],
    ) -> vmc::MemoryAccessResult<Option<u64>> {
        self.mem.search(addr, page_size, finder, buf)
    }
}

impl<Mem> vmc::HasVcpus for DumbDump<Mem> {
    type Arch = vmc::arch::RuntimeArchitecture;

    fn arch(&self) -> Self::Arch {
        match &self.vcpus {
            Vcpus::X86_64(_) => vmc::arch::RuntimeArchitecture::X86_64(vmc::arch::X86_64),
            Vcpus::Aarch64(_) => vmc::arch::RuntimeArchitecture::Aarch64(vmc::arch::Aarch64),
            Vcpus::Riscv64(_) => vmc::arch::RuntimeArchitecture::Riscv64(vmc::arch::Riscv64),
        }
    }

    fn vcpus_count(&self) -> usize {
        match &self.vcpus {
            Vcpus::X86_64(vcpus) => vcpus.len(),
            Vcpus::Aarch64(vcpus) => vcpus.len(),
            Vcpus::Riscv64(vcpus) => vcpus.len(),
        }
    }

    fn registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<<Self::Arch as vmc::Architecture>::Registers> {
        Ok(match &self.vcpus {
            Vcpus::X86_64(vcpus) => vmc::arch::runtime::Registers::X86_64(
                vcpus
                    .get(vcpu.0)
                    .ok_or(vmc::VcpuError::InvalidId)?
                    .registers,
            ),
            Vcpus::Aarch64(vcpus) => vmc::arch::runtime::Registers::Aarch64(
                vcpus
                    .get(vcpu.0)
                    .ok_or(vmc::VcpuError::InvalidId)?
                    .registers,
            ),
            Vcpus::Riscv64(vcpus) => vmc::arch::runtime::Registers::Riscv64(
                vcpus
                    .get(vcpu.0)
                    .ok_or(vmc::VcpuError::InvalidId)?
                    .registers,
            ),
        })
    }

    fn special_registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<<Self::Arch as vmc::Architecture>::SpecialRegisters> {
        Ok(match &self.vcpus {
            Vcpus::X86_64(vcpus) => vmc::arch::runtime::SpecialRegisters::X86_64(
                vcpus
                    .get(vcpu.0)
                    .ok_or(vmc::VcpuError::InvalidId)?
                    .special_registers,
            ),
            Vcpus::Aarch64(vcpus) => vmc::arch::runtime::SpecialRegisters::Aarch64(
                vcpus
                    .get(vcpu.0)
                    .ok_or(vmc::VcpuError::InvalidId)?
                    .special_registers,
            ),
            Vcpus::Riscv64(vcpus) => vmc::arch::runtime::SpecialRegisters::Riscv64(
                vcpus
                    .get(vcpu.0)
                    .ok_or(vmc::VcpuError::InvalidId)?
                    .special_registers,
            ),
        })
    }

    fn other_registers(
        &self,
        vcpu: vmc::VcpuId,
    ) -> vmc::VcpuResult<<Self::Arch as vmc::Architecture>::OtherRegisters> {
        Ok(match &self.vcpus {
            Vcpus::X86_64(vcpus) => vmc::arch::runtime::OtherRegisters::X86_64(
                vcpus
                    .get(vcpu.0)
                    .ok_or(vmc::VcpuError::InvalidId)?
                    .other_registers,
            ),
            Vcpus::Aarch64(vcpus) => vmc::arch::runtime::OtherRegisters::Aarch64(
                vcpus
                    .get(vcpu.0)
                    .ok_or(vmc::VcpuError::InvalidId)?
                    .other_registers,
            ),
            Vcpus::Riscv64(vcpus) => vmc::arch::runtime::OtherRegisters::Riscv64(
                vcpus
                    .get(vcpu.0)
                    .ok_or(vmc::VcpuError::InvalidId)?
                    .other_registers,
            ),
        })
    }
}

impl<Mem: vmc::Memory> vmc::Backend for DumbDump<Mem> {}
