use core::ops::ControlFlow;

use alloc::{format, vec::Vec};
use gimli::UnwindSection;
use hashbrown::HashMap;
use ibc::{
    Architecture, Endianness, IceError, IceResult, Os, PhysicalAddress, ResultExt, VirtualAddress,
};
use once_cell::unsync::OnceCell;

use super::Linux;

struct Module {
    start: VirtualAddress,
    end: VirtualAddress,
    module: ibc::Module,
}

impl Module {
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
    proc: ibc::Process,
    pgd: PhysicalAddress,

    /// Finding `.eh_frame` sections is generally costly, so we definitly want
    /// to cache this information
    eh_frames: HashMap<ibc::Module, OnceCell<UnwindData>>,

    /// This is sorted by growing address so we can do binary searches
    modules: Vec<Module>,
}

impl<'a, B: ibc::Backend> Context<'a, B> {
    fn new(linux: &'a super::Linux<B>, proc: ibc::Process) -> IceResult<Self> {
        let pgd = linux.process_pgd(proc)?;
        let mut modules = Vec::new();

        linux.process_for_each_module(proc, &mut |module| {
            let (start, end) = linux.module_span(module, proc)?;
            modules.push(Module { start, end, module });
            Ok(ControlFlow::Continue(()))
        })?;

        let eh_frames = modules
            .iter()
            .map(|m| (m.module, OnceCell::new()))
            .collect();

        Ok(Self {
            linux,
            proc,
            pgd,

            eh_frames,
            modules,
        })
    }

    fn read_value<T: bytemuck::Pod>(&self, addr: VirtualAddress) -> IceResult<T> {
        let mut value = bytemuck::Zeroable::zeroed();
        self.linux
            .read_virtual_memory(self.pgd, addr, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }

    fn find_module_by_address(&self, addr: VirtualAddress) -> Option<&Module> {
        match self.modules.binary_search_by_key(&addr, |m| m.start) {
            Ok(i) => Some(&self.modules[i]),
            Err(i) => {
                let module = &self.modules[i.checked_sub(1)?];
                module.contains(addr).then_some(module)
            }
        }
    }

    fn get_unwind_data(&self, module: &Module, ip: VirtualAddress) -> IceResult<&UnwindData> {
        let cell = self
            .eh_frames
            .get(&module.module)
            .ok_or_else(|| IceError::new("unknown file"))?;
        cell.get_or_try_init(|| self.discover_sections(module, ip))
    }

    /// This is where things get difficult
    ///
    /// Unwind data is stored in the `.eh_frame` section. However, when an ELF
    /// gets mapped in memory, its section table is ignored. We can only find
    /// segments, which is not enough by itself.
    ///
    /// To circumvent this, we search the `.eh_frame_hdr` section, which is
    /// useful to us for two reasons:
    /// - It contains a pointer to `.eh_frame`
    /// - It always starts with a `\x01` byte. This is few, but better than
    ///   nothing.
    ///
    /// So to get `eh_frame`, we iterate over all the mappings of the file, look
    /// for `\x01` bytes and try to parse `.eh_frame_hdr` from there.
    fn discover_sections(&self, module: &Module, ip: VirtualAddress) -> IceResult<UnwindData> {
        if log::log_enabled!(log::Level::Debug) {
            let path = self.linux.module_path(module.module, self.proc)?;
            log::debug!("Looking for .eh_frame for {}", path);
        }

        let endian = match self.linux.backend.arch().endianness().as_runtime_endian() {
            ibc::endian::RuntimeEndian::Little => gimli::RunTimeEndian::Little,
            ibc::endian::RuntimeEndian::Big => gimli::RunTimeEndian::Big,
        };

        let mut vma_data = alloc::vec![0; (module.end - module.start) as usize];
        self.linux
            .try_read_virtual_memory(self.pgd, module.start, &mut vma_data)?;

        for i in memchr::memmem::find_iter(&vma_data, b"\x01") {
            let header = gimli::EhFrameHdr::new(&vma_data[i..], endian);
            let eh_frame_hdr = module.start + i as u64;
            let mut bases = gimli::BaseAddresses::default().set_eh_frame_hdr(eh_frame_hdr.0);

            // We found a `\x01` ! If parsing from there gives an error, it was not the good one

            let eh_frame_addr = match header.parse(&bases, 8) {
                Ok(hdr) => match hdr.eh_frame_ptr() {
                    gimli::Pointer::Direct(addr) => VirtualAddress(addr),
                    gimli::Pointer::Indirect(addr) => match self.read_value(VirtualAddress(addr)) {
                        Ok(addr) => addr,
                        Err(_) => continue,
                    },
                },
                Err(_) => continue,
            };

            if !module.contains(eh_frame_addr) {
                continue;
            }

            let eh_frame_offset = (eh_frame_addr - module.start) as usize;
            bases = bases.set_eh_frame(eh_frame_addr.0);

            // Ok we managed to get a pointer for `.eh_frame`. Make sure
            // that it actually means something and was not not pure luck.

            let eh_frame = gimli::EhFrame::new(&vma_data[eh_frame_offset..], endian);
            let fde = eh_frame.fde_for_address(&bases, ip.0, gimli::UnwindSection::cie_from_offset);
            if fde.is_err() {
                continue;
            }

            // At this point we can be pretty confident this was the good one

            log::debug!("Found .eh_frame section at 0x{eh_frame_addr:x}");

            return Ok(UnwindData {
                bases,
                endian,
                segment: vma_data,
                eh_frame: eh_frame_offset,
            });
        }

        Err(ibc::IceError::new("Unable to find .eh_frame section"))
    }
}

impl<B: ibc::Backend> Linux<B> {
    #[cold]
    fn handle_invalid_address(
        &self,
        proc: ibc::Process,
        frame: &mut ibc::StackFrame,
        f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        // We don't support kernel unwinding yet, so give the incomplete frame
        // that we have and error out.
        if frame.instruction_pointer.is_kernel() {
            return match f(frame)? {
                ControlFlow::Continue(()) => Err("kernel unwinding is not supported".into()),
                ControlFlow::Break(()) => Ok(()),
            };
        }

        // Current IP is not in a module. If both IP and SP are
        // valid addresses, we can suppose that we went through
        // JIT code.

        let sp_is_valid = self
            .process_find_vma_by_address(proc, frame.stack_pointer)
            .unwrap_or_else(|err| {
                log::warn!("Failed to get VMA for {:#x}: {err}", frame.stack_pointer);
                None
            })
            .is_some();
        let ip_is_valid = (|| {
            Ok(
                match self.process_find_vma_by_address(proc, frame.instruction_pointer)? {
                    Some(vma) => self.vma_flags(vma)?.is_exec(),
                    None => false,
                },
            )
        })()
        .unwrap_or_else(|err: ibc::IceError| {
            log::warn!("Failed to check VMA for {:#x}: {err}", frame.stack_pointer);
            false
        });

        if sp_is_valid && ip_is_valid {
            frame.start = None;
            frame.size = None;
            frame.module = None;
            match f(frame)? {
                ControlFlow::Continue(()) => Err("unwinding through JIT is unsupported".into()),
                ControlFlow::Break(()) => Ok(()),
            }
        } else {
            Err("this is probably a bug").context(format!(
                "invalid instruction pointer: {:#x}",
                frame.instruction_pointer
            ))
        }
    }
}

pub fn iter<B: ibc::Backend>(
    linux: &Linux<B>,
    proc: ibc::Process,
    instruction_pointer: VirtualAddress,
    stack_pointer: VirtualAddress,
    mut base_pointer: Option<VirtualAddress>,
    f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<ControlFlow<()>>,
) -> IceResult<()> {
    let ctx = Context::new(linux, proc)?;
    let mut cie_cache = HashMap::new();
    let mut unwind_ctx = gimli::UnwindContext::new();

    let registers = dwarf_registers(linux.backend.arch());

    let get_base_pointer = |bp: Option<VirtualAddress>| {
        bp.ok_or_else(|| IceError::new("missing required register rpb"))
    };

    let unsupported_register = |gimli::Register(n), missing: &str| {
        IceError::new(format!(
            "getting {missing} requires unsupported register {n}"
        ))
    };

    // Start building the frame with the data we have
    let mut frame = ibc::StackFrame {
        instruction_pointer,
        stack_pointer,
        start: None,
        size: None,
        module: None,
    };

    loop {
        // Where are we ?
        let module = match ctx.find_module_by_address(frame.instruction_pointer) {
            Some(m) => m,
            None => return linux.handle_invalid_address(proc, &mut frame, f),
        };
        frame.module = Some(module.module);

        let cie_cache = cie_cache.entry(module.module).or_insert_with(HashMap::new);

        // Find unwind data of the binary we're in
        let data = ctx.get_unwind_data(module, frame.instruction_pointer)?;
        let eh_frame = data.eh_frame();

        // At this point the only missing data is the function start and its size.
        let fde = eh_frame.fde_for_address(
            &data.bases,
            frame.instruction_pointer.0,
            |this, bases, offset| {
                cie_cache
                    .entry(offset)
                    .or_insert_with(|| this.cie_from_offset(bases, offset))
                    .clone()
            },
        );

        let fde = match fde {
            Ok(fde) => fde,
            Err(err) => {
                // Even without the FDE, we can still send the incomplete frame
                // we got with the previous one
                log::debug!("Cannot get FDE: {err:?}");
                frame.start = None;
                frame.size = None;
                f(&frame)?;
                return Ok(());
            }
        };

        // Warning: `gimli::UnwindTableRow` gives similar infos but slightly
        // different
        frame.start = Some(VirtualAddress(fde.initial_address()));
        frame.size = Some(fde.len());

        // Now the frame is complete, we can "send" it before starting again
        if f(&frame)?.is_break() {
            return Ok(());
        }

        let row = fde
            .unwind_info_for_address(
                &eh_frame,
                &data.bases,
                &mut unwind_ctx,
                frame.instruction_pointer.0,
            )
            .unwrap();

        // Other registers are generally defined with an offset to the Canonical
        // Frame Address so we get that first.
        let cfa = match row.cfa() {
            &gimli::CfaRule::RegisterAndOffset { register, offset } => match register {
                reg if reg == registers.sp => frame.stack_pointer + offset,
                reg if Some(reg) == registers.bp => get_base_pointer(base_pointer)? + offset,
                reg => return Err(unsupported_register(reg, "CFA")),
            },
            gimli::CfaRule::Expression(_) => {
                return Err(IceError::new("unsupported DWARF expression"))
            }
        };

        // Now let's get registers values for the next frame

        let old_bp = base_pointer;
        let old_sp = frame.stack_pointer;
        let old_ip = frame.instruction_pointer;

        base_pointer = match registers.bp {
            None => None,
            Some(bp_reg) => (|| {
                Ok(Some(match row.register(bp_reg) {
                    gimli::RegisterRule::SameValue => get_base_pointer(base_pointer)?,
                    gimli::RegisterRule::Offset(offset) => ctx.read_value(cfa + offset)?,
                    gimli::RegisterRule::ValOffset(offset) => cfa + offset,
                    gimli::RegisterRule::Register(register) => match register {
                        reg if reg == registers.sp => old_sp,
                        reg if reg == registers.ip => old_ip,
                        reg if Some(reg) == registers.bp => get_base_pointer(old_bp)?,
                        reg => return Err(unsupported_register(reg, "base pointer")),
                    },
                    _ => return Ok(None),
                }))
            })()?,
        };

        frame.instruction_pointer = match row.register(registers.ip) {
            gimli::RegisterRule::Undefined => break,
            gimli::RegisterRule::SameValue => frame.instruction_pointer,
            gimli::RegisterRule::Offset(offset) => ctx.read_value(cfa + offset)?,
            gimli::RegisterRule::ValOffset(offset) => cfa + offset,
            gimli::RegisterRule::Register(register) => match register {
                reg if reg == registers.sp => old_sp,
                reg if reg == registers.ip => old_ip,
                reg if Some(reg) == registers.bp => get_base_pointer(old_bp)?,
                reg => return Err(unsupported_register(reg, "instruction pointer")),
            },
            _ => return Err(IceError::new("cannot retrieve instruction pointer")),
        };

        frame.stack_pointer = cfa;
    }

    Ok(())
}

struct DwarfRegisters {
    ip: gimli::Register,
    sp: gimli::Register,
    bp: Option<gimli::Register>,
}

fn dwarf_registers<A: ibc::Architecture>(arch: A) -> DwarfRegisters {
    match arch.into_runtime() {
        ibc::arch::RuntimeArchitecture::X86_64(_) => DwarfRegisters {
            ip: gimli::X86_64::RA,
            sp: gimli::X86_64::RSP,
            bp: Some(gimli::X86_64::RBP),
        },
        ibc::arch::RuntimeArchitecture::Aarch64(_) => DwarfRegisters {
            ip: gimli::AArch64::X30,
            sp: gimli::AArch64::SP,
            bp: None,
        },
    }
}
