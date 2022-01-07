use alloc::{format, vec::Vec};

use gimli::UnwindSection;
use hashbrown::HashMap;
use ibc::{
    Architecture, Endianness, IceError, IceResult, MemoryAccessResult, MemoryAccessResultExt, Os,
    PhysicalAddress, VirtualAddress,
};
use once_cell::unsync::OnceCell;

use super::Linux;

struct Vma {
    start: VirtualAddress,
    end: VirtualAddress,
    perms: ibc::VmaFlags,
    file: ibc::Path,
}

impl Vma {
    fn contains(&self, addr: VirtualAddress) -> bool {
        self.start <= addr && addr < self.end
    }
}

struct UnwindData {
    bases: gimli::BaseAddresses,
    endian: gimli::RunTimeEndian,
    segment: Vec<u8>,
    eh_frame: usize,
}

impl UnwindData {
    fn eh_frame(&self) -> gimli::EhFrame<impl gimli::Reader + '_> {
        gimli::EhFrame::new(&self.segment[self.eh_frame..], self.endian)
    }
}

struct Context<'a, B: ibc::Backend> {
    linux: &'a super::Linux<B>,
    eh_frames: HashMap<ibc::Path, OnceCell<UnwindData>>,
    pgd: PhysicalAddress,
    vmas: Vec<Vma>,
}

impl<'a, B: ibc::Backend> Context<'a, B> {
    fn new(linux: &'a super::Linux<B>, proc: ibc::Process) -> IceResult<Self> {
        let pgd = linux.process_pgd(proc)?;
        let mut vmas = Vec::new();

        linux.process_for_each_vma(proc, &mut |vma| {
            if let Some(file) = linux.vma_file(vma)? {
                vmas.push(Vma {
                    start: linux.vma_start(vma)?,
                    end: linux.vma_end(vma)?,
                    perms: ibc::VmaFlags(linux.vma_flags(vma)?.0 & 7),
                    file,
                });
            }
            Ok(())
        })?;

        let eh_frames = vmas.iter().map(|vma| (vma.file, OnceCell::new())).collect();

        Ok(Self {
            linux,
            eh_frames,
            pgd,
            vmas,
        })
    }

    fn virtual_to_physical(
        &self,
        addr: VirtualAddress,
    ) -> MemoryAccessResult<Option<PhysicalAddress>> {
        self.linux.backend.virtual_to_physical(self.pgd, addr)
    }

    #[allow(dead_code)]
    fn is_valid(&self, addr: VirtualAddress) -> IceResult<bool> {
        Ok(self.virtual_to_physical(addr)?.is_some())
    }

    fn read_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> MemoryAccessResult<Option<()>> {
        let mut offset = 0;

        while offset < buf.len() {
            let max = core::cmp::min(offset + 0x1000, buf.len());
            let chunk = &mut buf[offset..max];

            match self.virtual_to_physical(addr + offset as u64)? {
                Some(p_addr) => {
                    self.linux.backend.read_memory(p_addr, chunk)?;
                }
                None => {
                    chunk.fill(0);
                    log::debug!("Encountered unmapped page: 0x{:x}", addr + offset as u64);
                }
            }

            offset += 0x1000;
        }

        Ok(Some(()))
    }

    fn read_value<T: bytemuck::Pod>(&self, addr: VirtualAddress) -> MemoryAccessResult<Option<T>> {
        Ok(match self.virtual_to_physical(addr)? {
            Some(addr) => Some(self.linux.backend.read_value(addr)?),
            None => None,
        })
    }

    fn read_range(
        &self,
        start: VirtualAddress,
        end: VirtualAddress,
        buf: &mut Vec<u8>,
    ) -> MemoryAccessResult<Option<()>> {
        assert!(start <= end);
        let vma_size = (end - start) as usize;
        buf.resize(vma_size, 0);
        self.read_memory(start, buf)
    }

    fn find_vma_by_address(&self, addr: VirtualAddress) -> Option<&Vma> {
        match self.vmas.binary_search_by_key(&addr, |vma| vma.start) {
            Ok(i) => Some(&self.vmas[i]),
            Err(i) => {
                let vma = &self.vmas[i.checked_sub(1)?];
                vma.contains(addr).then(|| vma)
            }
        }
    }

    fn get_unwind_data(&self, exe_path: ibc::Path, ip: VirtualAddress) -> IceResult<&UnwindData> {
        let cell = self
            .eh_frames
            .get(&exe_path)
            .ok_or_else(|| IceError::new("unknown file"))?;
        cell.get_or_try_init(|| self.discover_sections(exe_path, ip))
    }

    fn discover_sections(&self, exe_path: ibc::Path, ip: VirtualAddress) -> IceResult<UnwindData> {
        if log::log_enabled!(log::Level::Debug) {
            let path = self.linux.path_to_string(exe_path)?;
            log::debug!("Looking for .eh_frame for {}", path);
        }

        let endian = match self.linux.backend.arch().endianness().as_runtime_endian() {
            ibc::RuntimeEndian::Little => gimli::RunTimeEndian::Little,
            ibc::RuntimeEndian::Big => gimli::RunTimeEndian::Big,
        };
        let mut vma_data = Vec::with_capacity(0x1000);

        for vma in &self.vmas {
            if vma.perms.0 != ibc::VmaFlags::READ.0 || vma.file != exe_path {
                continue;
            }

            if self
                .read_range(vma.start, vma.end, &mut vma_data)?
                .is_none()
            {
                log::debug!("Encountered unmapped page: 0x{:x}", vma.start);
                continue;
            }

            log::trace!("Trying VMA starting at {:x}", vma.start);

            for i in memchr::memmem::find_iter(&vma_data, b"\x01") {
                let header = gimli::EhFrameHdr::new(&vma_data[i..], endian);
                let eh_frame_hdr = vma.start + i as u64;
                let mut bases = gimli::BaseAddresses::default().set_eh_frame_hdr(eh_frame_hdr.0);

                let eh_frame_addr = match header.parse(&bases, 8) {
                    Ok(hdr) => match hdr.eh_frame_ptr() {
                        gimli::Pointer::Direct(addr) => VirtualAddress(addr),
                        gimli::Pointer::Indirect(addr) => {
                            match self.read_value(VirtualAddress(addr))? {
                                Some(addr) => addr,
                                None => {
                                    log::trace!("Unvalid indirect pointer");
                                    continue;
                                }
                            }
                        }
                    },
                    Err(err) => {
                        log::trace!("Rejected .eh_frame_hdr: {:?}", err);
                        continue;
                    }
                };

                if !vma.contains(eh_frame_addr) {
                    log::trace!("Unvalid pointer");
                    continue;
                }

                let eh_frame_offset = (eh_frame_addr - vma.start) as usize;
                bases = bases.set_eh_frame(eh_frame_addr.0);

                let eh_frame = gimli::EhFrame::new(&vma_data[eh_frame_offset..], endian);
                let fde = eh_frame.fde_for_address(&bases, ip.0, |this, bases, offset| {
                    this.cie_from_offset(bases, offset)
                });

                if fde.is_err() {
                    log::trace!("Incomplete .eh_frame");
                    continue;
                }

                return Ok(UnwindData {
                    bases,
                    endian,
                    segment: vma_data,
                    eh_frame: eh_frame_offset,
                });
            }
        }

        Err(ibc::IceError::new("Unable to find .eh_frame section"))
    }
}

pub fn iter<B: ibc::Backend>(
    linux: &Linux<B>,
    proc: ibc::Process,
    f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<()>,
) -> IceResult<()> {
    use ibc::arch::{Vcpu, Vcpus};

    let ctx = Context::new(linux, proc)?;
    let mut cie_cache = HashMap::new();
    let mut unwind_ctx = gimli::UnwindContext::new();

    let vcpus = linux.backend.vcpus();
    let (rip, rsp, rbp) = 'res: loop {
        for i in 0..vcpus.count() {
            if linux.current_process(i)? == proc {
                let vcpu = vcpus.get(i);
                break 'res (
                    vcpu.instruction_pointer(),
                    vcpu.stack_pointer(),
                    vcpu.into_runtime().as_x86_64().unwrap().registers.rbp,
                );
            }
        }

        return Err(IceError::new("Not a running process"));
    };

    let mut frame = ibc::StackFrame {
        instruction_pointer: rip,
        stack_pointer: rsp,
        ..Default::default()
    };
    let mut rbp = VirtualAddress(rbp);

    loop {
        let path = match ctx.find_vma_by_address(frame.instruction_pointer) {
            Some(vma) => vma.file,
            None => return Err(IceError::new("anonymous page")),
        };

        let cie_cache = cie_cache.entry(path).or_insert_with(HashMap::new);

        frame.file = linux.path_to_string(path)?;

        let data = ctx.get_unwind_data(path, frame.instruction_pointer)?;
        let eh_frame = data.eh_frame();

        let fde = eh_frame
            .fde_for_address(
                &data.bases,
                frame.instruction_pointer.0,
                |this, bases, offset| {
                    cie_cache
                        .entry(offset)
                        .or_insert_with(|| this.cie_from_offset(bases, offset))
                        .clone()
                },
            )
            .unwrap();

        frame.start = VirtualAddress(fde.initial_address());
        frame.size = fde.len();

        f(&frame)?;

        let row = fde
            .unwind_info_for_address(
                &eh_frame,
                &data.bases,
                &mut unwind_ctx,
                frame.instruction_pointer.0,
            )
            .unwrap();

        let cfa = match row.cfa() {
            gimli::CfaRule::RegisterAndOffset { register, offset } => match register {
                gimli::Register(6) => rbp + *offset,
                gimli::Register(7) => frame.stack_pointer + *offset,
                gimli::Register(n) => {
                    return Err(IceError::new(format!("unsupported register in CFA: {}", n)))
                }
            },
            gimli::CfaRule::Expression(_) => {
                return Err(IceError::new("unsupported DWARF expression"))
            }
        };

        let old_bp = rbp;
        let old_sp = frame.stack_pointer;
        let old_ip = frame.instruction_pointer;

        rbp = match row.register(gimli::Register(6)) {
            gimli::RegisterRule::SameValue => rbp,
            gimli::RegisterRule::Offset(offset) => ctx.read_value(cfa + offset).valid()?,
            gimli::RegisterRule::ValOffset(offset) => cfa + offset,
            gimli::RegisterRule::Register(register) => match register {
                gimli::Register(6) => old_bp,
                gimli::Register(7) => old_sp,
                gimli::Register(16) => old_ip,
                _ => return Err(IceError::new("unsupported register in CFA")),
            },
            _ => {
                log::debug!("cannot retreive rbp");
                rbp
            }
        };

        frame.instruction_pointer = match row.register(gimli::Register(16)) {
            gimli::RegisterRule::Undefined => break,
            gimli::RegisterRule::SameValue => frame.instruction_pointer,
            gimli::RegisterRule::Offset(offset) => ctx.read_value(cfa + offset).valid()?,
            gimli::RegisterRule::ValOffset(offset) => cfa + offset,
            gimli::RegisterRule::Register(register) => match register {
                gimli::Register(6) => old_bp,
                gimli::Register(7) => old_sp,
                gimli::Register(16) => old_ip,
                _ => return Err(IceError::new("unsupported register in CFA")),
            },
            _ => return Err(IceError::new("cannot retreive instruction pointer")),
        };

        frame.stack_pointer = cfa;
    }

    Ok(())
}
