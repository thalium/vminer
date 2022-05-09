use ibc::{
    Backend, IceError, IceResult, MemoryAccessResult, Os, PhysicalAddress, ResultExt,
    TranslationResult, TranslationResultExt, VirtualAddress,
};
use once_cell::unsync::OnceCell;

use super::Windows;

struct Vma {
    start: VirtualAddress,
    end: VirtualAddress,
    vma: ibc::Vma,
    unwind_data: OnceCell<UnwindData>,
}

impl Vma {
    fn contains(&self, addr: VirtualAddress) -> bool {
        self.start <= addr && addr < self.end
    }
}

#[derive(Debug, Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct RuntimeFunction {
    start: u32,
    end: u32,
    ptr: u32,
}

#[derive(Debug)]
struct FunctionEntry {
    start: u32,
    end: u32,
    stack_frame_size: u32,
    frame_register: u32,
    #[allow(dead_code)]
    frame_register_offset: u32,
    mother: Option<RuntimeFunction>,
}

impl FunctionEntry {
    fn contains(&self, addr: u32) -> bool {
        self.start <= addr && addr < self.end
    }
}

/// Cached unwind data by module
struct UnwindData {
    offset: VirtualAddress,
    functions: Vec<FunctionEntry>,
}

impl UnwindData {
    fn find_by_address(&self, addr: VirtualAddress) -> Option<&FunctionEntry> {
        self.find_by_offset((addr - self.offset) as u32)
    }

    fn find_by_offset(&self, offset: u32) -> Option<&FunctionEntry> {
        match self.functions.binary_search_by_key(&offset, |e| e.start) {
            Ok(index) => Some(&self.functions[index]),
            Err(index) => {
                let function = &self.functions[index.checked_sub(1)?];
                function.contains(offset).then(|| function)
            }
        }
    }
}

// TODO: these should probably live elsewhere

fn read_u8(codes: &mut &[u8]) -> Option<u8> {
    let (first, rest) = codes.split_first()?;
    *codes = rest;
    Some(*first)
}

fn read_u16(codes: &mut &[u8]) -> Option<u16> {
    match codes {
        [a, b, rest @ ..] => {
            *codes = rest;
            Some(u16::from_le_bytes([*a, *b]))
        }
        _ => None,
    }
}

fn read_u32(codes: &mut &[u8]) -> Option<u32> {
    match codes {
        [a, b, c, d, rest @ ..] => {
            *codes = rest;
            Some(u32::from_le_bytes([*a, *b, *c, *d]))
        }
        _ => None,
    }
}

fn read_slice<'a>(codes: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    (len <= codes.len()).then(|| {
        let (first, rest) = codes.split_at(len);
        *codes = rest;
        first
    })
}

// Windows unwind operations
const UWOP_PUSH_NONVOL: u8 = 0;
const UWOP_ALLOC_LARGE: u8 = 1;
const UWOP_ALLOC_SMALL: u8 = 2;
const UWOP_SET_FPREG: u8 = 3;
const UWOP_SAVE_NONVOL: u8 = 4;
const UWOP_SAVE_NONVOL_FAR: u8 = 5;
const UWOP_EPILOG: u8 = 6;
const UWOP_SAVE_XMM128: u8 = 8;
const UWOP_SAVE_XMM128_FAR: u8 = 9;
const UWOP_PUSH_MACHFRAME: u8 = 10;

struct Context<'a, B: ibc::Backend> {
    windows: &'a super::Windows<B>,
    pgd: PhysicalAddress,

    /// This is sorted by growing address so we can do binary searches
    vmas: Vec<Vma>,
}

impl<'a, B: ibc::Backend> Context<'a, B> {
    fn new(windows: &'a super::Windows<B>, proc: ibc::Process) -> IceResult<Self> {
        let pgd = windows.process_pgd(proc)?;
        let mut vmas = Vec::new();

        windows.process_for_each_vma(proc, &mut |vma| {
            vmas.push(Vma {
                start: windows.vma_start(vma)?,
                end: windows.vma_end(vma)?,
                vma,
                unwind_data: OnceCell::new(),
            });
            Ok(())
        })?;

        Ok(Self { windows, pgd, vmas })
    }

    fn virtual_to_physical(&self, addr: VirtualAddress) -> TranslationResult<PhysicalAddress> {
        self.windows.backend.virtual_to_physical(self.pgd, addr)
    }

    #[allow(dead_code)]
    fn is_valid(&self, addr: VirtualAddress) -> IceResult<bool> {
        Ok(self.virtual_to_physical(addr).maybe_invalid()?.is_some())
    }

    // TODO: this should probably move to core
    fn read_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> MemoryAccessResult<()> {
        let mut offset = 0;

        while offset < buf.len() {
            let max = core::cmp::min(offset + 0x1000, buf.len());
            let chunk = &mut buf[offset..max];

            match self
                .windows
                .read_virtual_memory(self.pgd, addr + offset as u64, chunk)
            {
                Ok(()) => (),
                Err(ibc::TranslationError::Invalid(mmu)) => {
                    chunk.fill(0);
                    log::debug!(
                        "Encountered unmapped page: 0x{:x} ({mmu:#x})",
                        addr + offset as u64
                    );
                }
                Err(ibc::TranslationError::Memory(err)) => return Err(err),
            }

            offset += 0x1000;
        }

        Ok(())
    }

    fn read_value<T: bytemuck::Pod>(&self, addr: VirtualAddress) -> TranslationResult<T> {
        let addr = self.virtual_to_physical(addr)?;
        Ok(self.windows.backend.read_value(addr)?)
    }

    /// Read a whole mapping
    fn read_range(
        &self,
        start: VirtualAddress,
        end: VirtualAddress,
        buf: &mut Vec<u8>,
    ) -> MemoryAccessResult<()> {
        assert!(start <= end);
        let vma_size = (end - start) as usize;
        buf.resize(vma_size, 0);
        self.read_memory(start, buf)
    }

    fn find_vma_by_address(&self, addr: VirtualAddress) -> Option<(&Vma, &UnwindData)> {
        let vma = match self.vmas.binary_search_by_key(&addr, |vma| vma.start) {
            Ok(i) => Some(&self.vmas[i]),
            Err(i) => {
                let vma = &self.vmas[i.checked_sub(1)?];
                vma.contains(addr).then(|| vma)
            }
        }?;

        let unwind_data = vma
            .unwind_data
            .get_or_try_init(|| self.init_unwind_data(vma))
            .map_err(|err| log::error!("Cannot get unwind data for 0x{addr:x}: {err}"))
            .ok()?;

        Some((vma, unwind_data))
    }

    fn parse_unwind_codes(&self, mut codes: &[u8], version: u8) -> Option<u32> {
        let mut stack_frame_size = 0;

        let codes = &mut codes;

        loop {
            if read_u8(codes).is_none() {
                break;
            }
            let op = read_u8(codes)?;

            let op_code = op & 0xf;
            let op_info = op >> 4;

            match op_code {
                UWOP_PUSH_NONVOL => stack_frame_size += 8,

                UWOP_ALLOC_LARGE => match op_info {
                    0 => stack_frame_size += read_u16(codes)? as u32 * 8,
                    1 => stack_frame_size += read_u32(codes)?,
                    _ => return None,
                },
                UWOP_ALLOC_SMALL => stack_frame_size += op_info as u32 * 8 + 8,
                UWOP_SET_FPREG => (),
                UWOP_SAVE_NONVOL => {
                    read_u16(codes)?;
                }
                UWOP_SAVE_NONVOL_FAR => {
                    read_u32(codes)?;
                }
                UWOP_EPILOG if version == 2 => {
                    // TODO: Handle this better. There is very few documentation
                    // about this at the moment, but this is not widly used.
                    read_u16(codes)?;
                }
                UWOP_SAVE_XMM128 => {
                    read_u16(codes)?;
                }
                UWOP_SAVE_XMM128_FAR => {
                    read_u32(codes)?;
                }
                UWOP_PUSH_MACHFRAME => match op_info {
                    0 => stack_frame_size += 0x28,
                    1 => stack_frame_size += 0x30,
                    _ => return None,
                },

                _ => return None,
            }
        }

        Some(stack_frame_size)
    }

    fn parse_directory_range(
        &self,
        pe: &[u8],
        (start, size): (u32, u32),
    ) -> Option<Vec<FunctionEntry>> {
        let data = pe.get(start as usize..(start + size) as usize)?;
        let runtime_functions: &[RuntimeFunction] = bytemuck::try_cast_slice(data).ok()?;

        let mut entries = Vec::with_capacity(runtime_functions.len());

        for &runtime_function in runtime_functions {
            let unwind_data = &mut pe.get(runtime_function.ptr as usize..)?;

            let version_flags = read_u8(unwind_data)?;
            let version = version_flags & 0x7;
            if version < 1 || version > 2 {
                log::error!("Unsupported unwind code version: {version}");
                return None;
            }

            let is_chained = version_flags & 0x20 != 0;
            let _prolog_size = read_u8(unwind_data)?;
            let unwind_code_count = read_u8(unwind_data)?;
            let frame_infos = read_u8(unwind_data)?;
            let frame_register = (frame_infos & 0x0f) as u32;
            let frame_register_offset = (frame_infos & 0xf0) as u32;

            let unwind_codes = read_slice(unwind_data, 2 * unwind_code_count as usize)?;
            let stack_frame_size = self
                .parse_unwind_codes(unwind_codes, version)
                .expect("bad unwind");

            let mother = if is_chained {
                let mother = read_slice(unwind_data, std::mem::size_of::<RuntimeFunction>())?;
                Some(bytemuck::try_pod_read_unaligned(mother).ok()?)
            } else {
                None
            };

            entries.push(FunctionEntry {
                start: runtime_function.start,
                end: runtime_function.end,
                stack_frame_size,
                frame_register,
                frame_register_offset,
                mother,
            });
        }
        Some(entries)
    }

    fn init_unwind_data(&self, vma: &Vma) -> IceResult<UnwindData> {
        let mut content = vec![0; (vma.end - vma.start) as usize];
        self.read_range(vma.start, vma.end, &mut content)?;

        let pe = object::read::pe::PeFile64::parse(&*content).context("failed to parse PE")?;
        let directory = pe
            .data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            .context("failed to get debug directory")?;

        let functions = self
            .parse_directory_range(&*content, directory.address_range())
            .ok_or("invalid debug directory")?;

        Ok(UnwindData {
            offset: vma.start,
            functions,
        })
    }
}

impl<B: Backend> Windows<B> {
    pub fn iter_process_callstack(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<()>,
    ) -> IceResult<()> {
        use ibc::arch::{Vcpu, Vcpus};

        let vcpus = self.backend.vcpus();

        // Get pointers from the current CPU
        let (instruction_pointer, stack_pointer, base_pointer) = 'res: loop {
            for i in 0..vcpus.count() {
                if self.current_process(i)? == proc {
                    let vcpu = vcpus.get(i);
                    break 'res (
                        vcpu.instruction_pointer(),
                        vcpu.stack_pointer(),
                        vcpu.base_pointer(),
                    );
                }
            }

            return Err(IceError::new("Not a running process"));
        };

        self.iter_callstack(proc, f, instruction_pointer, stack_pointer, base_pointer)
    }

    pub fn iter_callstack(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<()>,
        instruction_pointer: VirtualAddress,
        stack_pointer: VirtualAddress,
        _base_pointer: Option<VirtualAddress>,
    ) -> IceResult<()> {
        let ctx = Context::new(self, proc)?;

        // Start building the frame with the data we have
        let mut frame = ibc::StackFrame {
            instruction_pointer,
            stack_pointer,
            range: None,
            vma: ibc::Vma(VirtualAddress(0)),
            file: None,
        };

        loop {
            if instruction_pointer.is_kernel() {
                return Err(IceError::new("encountered kernel IP"));
            }

            // Where are we ?
            let (vma, unwind_data) = ctx
                .find_vma_by_address(frame.instruction_pointer)
                .ok_or("encountered unmapped page")?;
            frame.vma = vma.vma;

            f(&frame)?;

            let function = unwind_data.find_by_address(frame.instruction_pointer);

            // Move stack pointer to the upper frame
            let caller_sp = match function {
                Some(function) => {
                    if function.frame_register != 0 {
                        return Err("unsupported non-zero frame_register".into());
                    }

                    let mut sp = frame.stack_pointer + function.stack_frame_size as u64;

                    if let Some(mother) = function.mother {
                        let mother = unwind_data
                            .find_by_offset(mother.start)
                            .context("cannot find mother function")?;

                        sp += mother.stack_frame_size as u64;
                    }

                    sp
                }

                // This is a leaf function
                None => frame.stack_pointer,
            };

            frame.instruction_pointer = ctx.read_value(caller_sp)?;
            frame.stack_pointer = caller_sp + 8u64;

            if frame.instruction_pointer.is_null() {
                break Ok(());
            }
        }
    }
}
