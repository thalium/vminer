use core::ops::ControlFlow;
use ibc::{Backend, IceError, IceResult, Os, PhysicalAddress, ResultExt, VirtualAddress};
use once_cell::unsync::OnceCell;

use super::Windows;

struct Module {
    start: VirtualAddress,
    end: VirtualAddress,
    module: ibc::Module,
    unwind_data: OnceCell<UnwindData>,
}

impl Module {
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
    runtime_function: RuntimeFunction,
    stack_frame_size: u32,
    fp_offset: Option<u32>,
    frame_register_offset: Option<u8>,
    machframe_offset: Option<u32>,
    mother: Option<RuntimeFunction>,
}

impl FunctionEntry {
    fn contains(&self, addr: u32) -> bool {
        self.runtime_function.start <= addr && addr < self.runtime_function.end
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
        match self
            .functions
            .binary_search_by_key(&offset, |e| e.runtime_function.start)
        {
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
    proc: ibc::Process,
    pgd: PhysicalAddress,

    /// This is sorted by growing address so we can do binary searches
    modules: Vec<Module>,
}

impl<'a, B: ibc::Backend> Context<'a, B> {
    fn new(windows: &'a super::Windows<B>, proc: ibc::Process) -> IceResult<Self> {
        let pgd = windows.process_pgd(proc)?;
        let mut vmas = Vec::new();

        windows.process_for_each_module(proc, &mut |module| {
            let (start, end) = windows.module_span(module, proc)?;
            vmas.push(Module {
                start,
                end,
                module,
                unwind_data: OnceCell::new(),
            });
            Ok(ControlFlow::Continue(()))
        })?;

        windows.for_each_kernel_module(&mut |module| {
            let proc = ibc::Process(VirtualAddress(0));
            let (start, end) = windows.module_span(module, proc)?;
            vmas.push(Module {
                start,
                end,
                module,
                unwind_data: OnceCell::new(),
            });
            Ok(ControlFlow::Continue(()))
        })?;

        vmas.sort_unstable_by_key(|v| v.start);

        // println!("{:#x?}", vmas);

        Ok(Self {
            windows,
            proc,
            pgd,
            modules: vmas,
        })
    }

    fn pgd_for(&self, addr: VirtualAddress) -> ibc::PhysicalAddress {
        if addr.is_kernel() {
            self.windows.kpgd
        } else {
            self.pgd
        }
    }

    fn read_value<T: bytemuck::Pod>(&self, addr: VirtualAddress) -> IceResult<T> {
        let mut value = bytemuck::Zeroable::zeroed();
        let pgd = self.pgd_for(addr);
        self.windows.read_process_memory(
            self.proc,
            pgd,
            addr,
            bytemuck::bytes_of_mut(&mut value),
        )?;
        Ok(value)
    }

    fn find_module_by_address(&self, addr: VirtualAddress) -> Option<&Module> {
        match self.modules.binary_search_by_key(&addr, |m| m.start) {
            Ok(i) => Some(&self.modules[i]),
            Err(i) => {
                let vma = &self.modules[i.checked_sub(1)?];
                vma.contains(addr).then(|| vma)
            }
        }
    }

    fn get_unwind_data<'v>(&self, module: &'v Module) -> IceResult<&'v UnwindData> {
        module
            .unwind_data
            .get_or_try_init(|| self.init_unwind_data(module))
    }

    fn parse_unwind_codes(
        &self,
        mut codes: &[u8],
        version: u8,
    ) -> Option<(u32, Option<u32>, Option<u32>)> {
        const RSP: u8 = 5;

        let mut stack_frame_size = 0;
        let mut fp_offset = None;
        let mut machframe_offset = None;

        let codes = &mut codes;

        loop {
            if read_u8(codes).is_none() {
                break;
            }
            let op = read_u8(codes)?;

            let op_code = op & 0xf;
            let op_info = op >> 4;

            match op_code {
                UWOP_PUSH_NONVOL => {
                    if op_info == RSP {
                        fp_offset = Some(stack_frame_size);
                    }
                    stack_frame_size += 8;
                }
                UWOP_ALLOC_LARGE => match op_info {
                    0 => stack_frame_size += read_u16(codes)? as u32 * 8,
                    1 => stack_frame_size += read_u32(codes)?,
                    _ => return None,
                },
                UWOP_ALLOC_SMALL => stack_frame_size += op_info as u32 * 8 + 8,
                UWOP_SET_FPREG => (),
                UWOP_SAVE_NONVOL => {
                    let offset = read_u16(codes)? as u32 * 8;
                    if op_info == RSP {
                        fp_offset = Some(offset);
                    }
                }
                UWOP_SAVE_NONVOL_FAR => {
                    let offset = read_u32(codes)?;
                    if op_info == RSP {
                        fp_offset = Some(offset);
                    }
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
                UWOP_PUSH_MACHFRAME => {
                    match op_info {
                        0 => stack_frame_size += 0,
                        1 => stack_frame_size += 8,
                        _ => return None,
                    }
                    machframe_offset = Some(stack_frame_size);
                    stack_frame_size += 28;
                }

                _ => return None,
            }
        }

        Some((stack_frame_size, fp_offset, machframe_offset))
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
            let frame_register = frame_infos & 0x0f;
            let frame_register_offset = (frame_register != 0).then(|| frame_infos & 0xf0);

            let unwind_codes = read_slice(unwind_data, 2 * unwind_code_count as usize)?;
            let (stack_frame_size, fp_offset, machframe_offset) = self
                .parse_unwind_codes(unwind_codes, version)
                .expect("bad unwind");

            let mother = if is_chained {
                let mother = read_slice(unwind_data, std::mem::size_of::<RuntimeFunction>())?;
                Some(bytemuck::try_pod_read_unaligned(mother).ok()?)
            } else {
                None
            };

            entries.push(FunctionEntry {
                runtime_function,
                stack_frame_size,
                fp_offset,
                frame_register_offset,
                machframe_offset,
                mother,
            });
        }
        Some(entries)
    }

    fn init_unwind_data(&self, module: &Module) -> IceResult<UnwindData> {
        let mut content = vec![0; (module.end - module.start) as usize];
        let pgd = self.pgd_for(module.start);
        self.windows
            .try_read_process_memory(self.proc, pgd, module.start, &mut content)?;

        let pe = object::read::pe::PeFile64::parse(&*content).context("failed to parse PE")?;
        let directory = pe
            .data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            .context("failed to get debug directory")?;

        let functions = self
            .parse_directory_range(&*content, directory.address_range())
            .ok_or("invalid debug directory")?;

        Ok(UnwindData {
            offset: module.start,
            functions,
        })
    }
}

struct UnwindResult {
    next_sp: VirtualAddress,
    next_ip: VirtualAddress,
    fun_start: Option<VirtualAddress>,
}

fn unwind_function<B: Backend>(
    ctx: &Context<B>,
    module: &Module,
    frame: &ibc::StackFrame,
    base_pointer: &mut Option<VirtualAddress>,
) -> IceResult<UnwindResult> {
    let unwind_data = ctx
        .get_unwind_data(module)
        .context("cannot get unwind data")?;

    let (caller_sp, fun_start) = match unwind_data.find_by_address(frame.instruction_pointer) {
        Some(mut function) => {
            let frame_pointer = match function.frame_register_offset {
                None => frame.stack_pointer,
                Some(offset) => {
                    base_pointer.context("missing required frame pointer")? - offset as u64
                }
            };

            let mut next_sp = frame_pointer;
            loop {
                if let Some(offset) = function.fp_offset {
                    *base_pointer = Some(ctx.read_value(frame_pointer + offset)?);
                }

                if let Some(offset) = function.machframe_offset {
                    let machinst = frame_pointer + offset;
                    return Ok(UnwindResult {
                        next_ip: ctx.read_value(machinst)?,
                        next_sp: ctx.read_value(machinst + 0x18)?,
                        fun_start: Some(unwind_data.offset + function.runtime_function.start),
                    });
                }

                next_sp += function.stack_frame_size as u64;

                match function.mother {
                    Some(mother) => {
                        function = unwind_data
                            .find_by_offset(mother.start)
                            .context("cannot find mother function")?;
                    }
                    None => break,
                }
            }

            let fun_start = unwind_data.offset + function.runtime_function.start;
            (next_sp, Some(fun_start))
        }

        // This is a leaf function
        None => (frame.stack_pointer, None),
    };

    Ok(UnwindResult {
        next_ip: ctx.read_value(caller_sp)?,
        next_sp: caller_sp + 8u64,
        fun_start,
    })
}

impl<B: Backend> Windows<B> {
    pub fn iter_process_callstack(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<ControlFlow<()>>,
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
        f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<ControlFlow<()>>,
        instruction_pointer: VirtualAddress,
        stack_pointer: VirtualAddress,
        mut base_pointer: Option<VirtualAddress>,
    ) -> IceResult<()> {
        let ctx = Context::new(self, proc)?;

        // Start building the frame with the data we have
        let mut frame = ibc::StackFrame {
            instruction_pointer,
            stack_pointer,
            start: None,
            size: None,
            module: ibc::Module(VirtualAddress(0)),
        };

        loop {
            // Where are we ?
            let module = ctx
                .find_module_by_address(frame.instruction_pointer)
                .ok_or("encountered unmapped page")?;
            frame.module = module.module;

            // Move stack pointer to the upper frame
            let unwind_result = unwind_function(&ctx, module, &frame, &mut base_pointer);

            match unwind_result {
                Ok(infos) => {
                    frame.start = infos.fun_start;
                    if f(&frame)?.is_break() {
                        return Ok(());
                    }

                    frame.instruction_pointer = infos.next_ip;
                    frame.stack_pointer = infos.next_sp;
                }
                Err(err) => {
                    frame.start = None;
                    return match f(&frame)? {
                        ControlFlow::Continue(()) => Err(err),
                        ControlFlow::Break(()) => Ok(()),
                    };
                }
            }

            if frame.instruction_pointer.is_null() {
                break Ok(());
            }
        }
    }
}
