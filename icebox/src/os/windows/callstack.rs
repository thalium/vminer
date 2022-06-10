use alloc::collections::BTreeMap;
use core::ops::ControlFlow;
use ibc::{Backend, IceError, IceResult, Os, PhysicalAddress, ResultExt, VirtualAddress};

use super::Windows;

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

fn parse_unwind_codes(
    mut codes: &[u8],
    version: u8,
) -> Option<(u32, Option<u32>, Option<u32>, u8)> {
    const RSP: u8 = 5;

    let mut stack_frame_size = 0;
    let mut fp_offset = None;
    let mut machframe_offset = None;
    let mut prolog_size = 0;

    let codes = &mut codes;

    while let Some(op_offset) = read_u8(codes) {
        let op = read_u8(codes)?;

        let op_code = op & 0xf;
        let op_info = op >> 4;

        if matches!(
            op_code,
            UWOP_PUSH_NONVOL | UWOP_ALLOC_LARGE | UWOP_ALLOC_SMALL | UWOP_PUSH_MACHFRAME
        ) {
            prolog_size = core::cmp::max(prolog_size, op_offset)
        }

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

    Some((stack_frame_size, fp_offset, machframe_offset, prolog_size))
}

struct Module {
    start: VirtualAddress,
    end: VirtualAddress,
    module: ibc::Module,
    unwind_data: Option<UnwindData>,
}

impl Module {
    fn contains(&self, addr: VirtualAddress) -> bool {
        self.start <= addr && addr < self.end
    }

    fn get_unwind_data<B: ibc::Backend>(&mut self, ctx: &Context<B>) -> IceResult<&mut UnwindData> {
        if self.unwind_data.is_none() {
            let data = ctx.init_unwind_data(self)?;
            self.unwind_data = Some(data);
        }

        Ok(self.unwind_data.as_mut().unwrap())
    }
}

#[derive(Debug, Clone, Copy, bytemuck::Zeroable, bytemuck::Pod)]
#[repr(C)]
struct RuntimeFunction {
    start: u32,
    end: u32,
    ptr: u32,
}

impl RuntimeFunction {
    #[inline]
    fn contains(&self, addr: u32) -> bool {
        self.start <= addr && addr < self.end
    }

    #[inline]
    fn is_valid(&self) -> bool {
        // Fields in `RuntimeFunction` are not supposed to equal 0, so
        // meeting some means that we probably encountered an unmapped
        // page.
        self.start != 0 && self.end != 0 && self.ptr != 0
    }
}

#[derive(Debug, Clone)]
struct FunctionEntry {
    runtime_function: RuntimeFunction,
    mother: Option<RuntimeFunction>,

    prolog_size: u8,
    stack_frame_size: u32,

    fp_offset: Option<u32>,
    frame_register_offset: Option<u8>,
    machframe_offset: Option<u32>,
}

impl FunctionEntry {
    fn parse(pe: &[u8], runtime_function: RuntimeFunction) -> Option<Self> {
        let unwind_data = &mut pe.get(runtime_function.ptr as usize..)?;

        let version_flags = read_u8(unwind_data)?;
        let version = version_flags & 0x7;
        if !(1..=2).contains(&version) {
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
        let (stack_frame_size, fp_offset, machframe_offset, prolog_size) =
            parse_unwind_codes(unwind_codes, version).expect("bad unwind");

        let mother = if is_chained {
            let mother = read_slice(unwind_data, std::mem::size_of::<RuntimeFunction>())?;
            Some(bytemuck::try_pod_read_unaligned(mother).ok()?)
        } else {
            None
        };

        Some(Self {
            runtime_function,
            mother,

            stack_frame_size,
            prolog_size,

            fp_offset,
            frame_register_offset,
            machframe_offset,
        })
    }
}

/// Cached unwind data by module
struct UnwindData {
    offset: VirtualAddress,
    content: Vec<u8>,
    directory_range: (usize, usize),
    functions: BTreeMap<u32, FunctionEntry>,
}

impl UnwindData {
    fn find_runtime_function(
        functions: &[RuntimeFunction],
        offset: u32,
    ) -> IceResult<Option<RuntimeFunction>> {
        let mut corrupted = false;
        let pos = functions.binary_search_by_key(&offset, |rt| {
            if rt.is_valid() {
                rt.start
            } else {
                // In this case, we can't continue the binary search, so
                // we stop here.
                log::debug!("Encountered unmapped unwind info");
                corrupted = true;
                offset
            }
        });

        if corrupted {
            // If the binary search failed because of an unmapped page, we
            // fallback to a slower linear search.
            //
            // Not finding our function here may have two meanings:
            // - It is a leaf function
            // - Its unwind data is unmapped
            //
            // If we stop between two valid functions, we can assume the former
            // case, else we are conservative and return an error.
            let mut last_valid = None;

            for function in functions {
                if !function.is_valid() {
                    last_valid = None;
                    continue;
                }

                if offset < function.start {
                    // We're too far, we can stop there
                    break;
                } else if offset < function.end {
                    // It is the good one !
                    return Ok(Some(*function));
                }

                last_valid = Some(*function);
            }

            match last_valid {
                Some(_) => Ok(None),
                None => Err("Unmapped unwind data".into()),
            }
        } else {
            // The binary search succeded, so we known we're good.
            Ok(match pos {
                Ok(i) => Some(functions[i]),
                Err(i) => i.checked_sub(1).and_then(|i| {
                    let fun = functions[i];
                    fun.contains(offset).then(|| fun)
                }),
            })
        }
    }

    fn find_by_offset(&mut self, offset: u32) -> IceResult<Option<&FunctionEntry>> {
        Ok(self
            .get_function_start(offset)?
            .map(|start| &self.functions[&start]))
    }

    fn get_function_start(&mut self, offset: u32) -> IceResult<Option<u32>> {
        if let Some((start, function)) = self.functions.range(..=offset).last() {
            if offset < function.runtime_function.end {
                return Ok(Some(*start));
            }
        }

        self.insert_function(offset)
    }

    fn insert_function(&mut self, offset: u32) -> IceResult<Option<u32>> {
        let (start, end) = self.directory_range;
        let runtime_functions: &[RuntimeFunction] = bytemuck::cast_slice(&self.content[start..end]);

        let function = match Self::find_runtime_function(runtime_functions, offset)? {
            Some(f) => f,
            None => return Ok(None),
        };

        let function_start = function.start;
        let function = FunctionEntry::parse(&self.content, function).context("bad unwind codes")?;
        self.functions.insert(function_start, function);
        Ok(Some(function_start))
    }
}

struct Context<'a, B: ibc::Backend> {
    windows: &'a super::Windows<B>,
    proc: ibc::Process,
    pgd: PhysicalAddress,
}

struct AllModules(Vec<Module>);

impl AllModules {
    fn collect<B: ibc::Backend>(
        windows: &super::Windows<B>,
        proc: ibc::Process,
    ) -> IceResult<Self> {
        let mut modules = Vec::new();

        windows.process_for_each_module(proc, &mut |module| {
            let (start, end) = windows.module_span(module, proc)?;
            modules.push(Module {
                start,
                end,
                module,
                unwind_data: None,
            });
            Ok(ControlFlow::Continue(()))
        })?;

        windows.for_each_kernel_module(&mut |module| {
            let proc = ibc::Process(VirtualAddress(0));
            let (start, end) = windows.module_span(module, proc)?;
            modules.push(Module {
                start,
                end,
                module,
                unwind_data: None,
            });
            Ok(ControlFlow::Continue(()))
        })?;

        modules.sort_unstable_by_key(|v| v.start);

        Ok(Self(modules))
    }

    fn find_by_address(&mut self, addr: VirtualAddress) -> Option<&mut Module> {
        match self.0.binary_search_by_key(&addr, |m| m.start) {
            Ok(i) => Some(&mut self.0[i]),
            Err(i) => {
                let vma = &mut self.0[i.checked_sub(1)?];
                vma.contains(addr).then(|| vma)
            }
        }
    }
}

impl<'a, B: ibc::Backend> Context<'a, B> {
    fn new(windows: &'a super::Windows<B>, proc: ibc::Process) -> IceResult<Self> {
        let pgd = windows.process_pgd(proc)?;

        Ok(Self { windows, proc, pgd })
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

    fn init_unwind_data(&self, module: &Module) -> IceResult<UnwindData> {
        let mut content = vec![0; (module.end - module.start) as usize];
        let pgd = self.pgd_for(module.start);
        self.windows
            .try_read_process_memory(self.proc, pgd, module.start, &mut content)?;

        let pe = object::read::pe::PeFile64::parse(&*content).context("failed to parse PE")?;
        let directory = pe
            .data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION)
            .context("failed to get debug directory")?;

        let (start, size) = directory.address_range();
        let directory_start = start as usize;
        let directory_end = directory_start + size as usize;

        if directory_end > content.len()
            || size as usize % core::mem::size_of::<RuntimeFunction>() != 0
        {
            return Err(IceError::new("invalid exception directory size"));
        }

        Ok(UnwindData {
            offset: module.start,
            content,
            directory_range: (directory_start, directory_end),
            functions: BTreeMap::new(),
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
    module: &mut Module,
    frame: &ibc::StackFrame,
    base_pointer: &mut Option<VirtualAddress>,
) -> IceResult<UnwindResult> {
    let unwind_data = module
        .get_unwind_data(ctx)
        .context("cannot get unwind data")?;

    let offset_in_module = (frame.instruction_pointer - unwind_data.offset) as u32;
    let (caller_sp, fun_start) = match unwind_data.find_by_offset(offset_in_module)? {
        // This is a leaf function
        None => (frame.stack_pointer, None),

        Some(mut function) => {
            let mut function_start = function.runtime_function.start;

            let ip_offset = offset_in_module - function.runtime_function.start;
            if ip_offset < function.prolog_size as u32 {
                return Err("Unsupported function prolog".into());
            }

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
                        fun_start: Some(unwind_data.offset + function_start),
                    });
                }

                next_sp += function.stack_frame_size as u64;

                match function.mother {
                    Some(mother) => {
                        function = unwind_data
                            .find_by_offset(mother.start)?
                            .context("cannot find mother function")?;

                        function_start = function.runtime_function.start;
                    }
                    None => break,
                }
            }

            let fun_start = unwind_data.offset + function_start;
            (next_sp, Some(fun_start))
        }
    };

    Ok(UnwindResult {
        next_ip: ctx.read_value(caller_sp)?,
        next_sp: caller_sp + 8u64,
        fun_start,
    })
}

impl<B: Backend> Windows<B> {
    #[cold]
    fn handle_invalid_address(
        &self,
        proc: ibc::Process,
        frame: &mut ibc::StackFrame,
        f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        // Current IP is not in a module. If both IP and SP are
        // valid addresses, we can suppose that we went through
        // JIT code.

        let is_valid = |addr| {
            self.process_find_vma_by_address(proc, addr)
                .unwrap_or_else(|err| {
                    log::warn!("Failed to get VMA for {addr:#x}: {err}");
                    None
                })
                .is_some()
        };

        if is_valid(frame.instruction_pointer) && is_valid(frame.stack_pointer) {
            frame.start = None;
            frame.module = None;
            match f(&frame)? {
                ControlFlow::Continue(()) => Err("unwinding through JIT is unsupported".into()),
                ControlFlow::Break(()) => Ok(()),
            }
        } else {
            Err("invalid instruction pointer")
                .context("this is probably a bug or a function epilog")
        }
    }

    pub fn iter_process_callstack(
        &self,
        proc: ibc::Process,
        f: &mut dyn FnMut(&ibc::StackFrame) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        use ibc::arch::{Vcpu, Vcpus};

        let vcpus = self.backend.vcpus();

        // Get pointers from the current CPU
        #[allow(clippy::never_loop)]
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
        let mut modules = AllModules::collect(self, proc)?;

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
            let module = match modules.find_by_address(frame.instruction_pointer) {
                Some(m) => m,
                None => return self.handle_invalid_address(proc, &mut frame, f),
            };
            frame.module = Some(module.module);

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
