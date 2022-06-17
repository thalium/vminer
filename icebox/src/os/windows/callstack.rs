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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reg(u8);

impl Reg {
    const RBP: Self = Reg(5);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct XmmReg(u8);

#[derive(Debug, Clone, Copy)]
enum UnwindOp {
    Push(Reg),
    Alloc(u32),
    SetFpReg,
    Save(Reg, u32),
    Epilog,
    SaveXmm128(XmmReg, u32),
    PushMachFrame(bool),
}

struct UnwindOpIterator<'a> {
    version: u8,
    codes: &'a [u8],
}

impl Iterator for UnwindOpIterator<'_> {
    type Item = Option<(u8, UnwindOp)>;

    fn next(&mut self) -> Option<Self::Item> {
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

        let codes = &mut self.codes;

        let op_offset = read_u8(codes)?;

        let op = (|| {
            let op = read_u8(codes)?;

            let op_code = op & 0xf;
            let op_info = op >> 4;

            Some(match op_code {
                UWOP_PUSH_NONVOL => UnwindOp::Push(Reg(op_info)),

                UWOP_ALLOC_LARGE => match op_info {
                    0 => UnwindOp::Alloc(read_u16(codes)? as u32 * 8),
                    1 => UnwindOp::Alloc(read_u32(codes)?),
                    _ => return None,
                },
                UWOP_ALLOC_SMALL => UnwindOp::Alloc(op_info as u32 * 8 + 8),

                UWOP_SET_FPREG => UnwindOp::SetFpReg,

                UWOP_SAVE_NONVOL => UnwindOp::Save(Reg(op_info), read_u16(codes)? as u32 * 8),
                UWOP_SAVE_NONVOL_FAR => UnwindOp::Save(Reg(op_info), read_u32(codes)?),

                UWOP_EPILOG if self.version == 2 => {
                    read_u16(codes)?;
                    UnwindOp::Epilog
                }

                UWOP_SAVE_XMM128 => {
                    UnwindOp::SaveXmm128(XmmReg(op_info), read_u16(codes)? as u32 * 16)
                }
                UWOP_SAVE_XMM128_FAR => UnwindOp::SaveXmm128(XmmReg(op_info), read_u32(codes)?),

                UWOP_PUSH_MACHFRAME => match op_info {
                    0 => UnwindOp::PushMachFrame(false),
                    1 => UnwindOp::PushMachFrame(true),
                    _ => return None,
                },

                _ => return None,
            })
        })();

        Some(op.map(|op| (op_offset, op)))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let n_op = self.codes.len() / 2;
        ((n_op != 0) as usize, Some(n_op))
    }
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

    fn get_unwind_data<B: ibc::Backend>(&mut self, ctx: &Context<B>) -> IceResult<&UnwindData> {
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
struct FunctionEntry<'a> {
    mother: Option<RuntimeFunction>,
    version: u8,
    frame_register_offset: Option<u8>,
    unwind_codes: &'a [u8],
}

impl<'a> FunctionEntry<'a> {
    fn iter_codes(&self) -> UnwindOpIterator<'a> {
        UnwindOpIterator {
            version: self.version,
            codes: self.unwind_codes,
        }
    }
}

/// Cached unwind data by module
struct UnwindData {
    offset: VirtualAddress,
    content: Vec<u8>,
    directory_range: (usize, usize),
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
                None => Err("unmapped unwind data".into()),
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

    fn parse_function(&self, runtime_function: RuntimeFunction) -> Option<FunctionEntry> {
        let unwind_data = &mut self.content.get(runtime_function.ptr as usize..)?;

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

        let mother = if is_chained {
            let mother = read_slice(unwind_data, std::mem::size_of::<RuntimeFunction>())?;
            Some(bytemuck::pod_read_unaligned(mother))
        } else {
            None
        };

        Some(FunctionEntry {
            mother,
            version,
            frame_register_offset,
            unwind_codes,
        })
    }

    fn find_by_offset(&self, offset: u32) -> IceResult<Option<RuntimeFunction>> {
        let (start, end) = self.directory_range;
        let runtime_functions: &[RuntimeFunction] = bytemuck::cast_slice(&self.content[start..end]);
        Self::find_runtime_function(runtime_functions, offset)
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

        let mut push = |module| {
            let (start, end) = windows.module_span(module, proc)?;
            modules.push(Module {
                start,
                end,
                module,
                unwind_data: None,
            });
            Ok(ControlFlow::Continue(()))
        };

        windows.process_for_each_module(proc, &mut push)?;
        windows.for_each_kernel_module(&mut push)?;

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
        })
    }
}

enum NextSp {
    Value(VirtualAddress),
    Addr(VirtualAddress),
}

struct UnwindResult {
    next_sp: NextSp,
    next_ip_addr: VirtualAddress,
    next_bp_addr: Option<VirtualAddress>,
    fun_start: Option<VirtualAddress>,
}

/// Read instructions and emulate them if they match expectations for an epilog.
/// This is the common way to unwind an epilog in Windows x86_64
fn read_epilog(unwind_data: &UnwindData, frame: &ibc::StackFrame) -> Option<UnwindResult> {
    let offset = (frame.instruction_pointer - unwind_data.offset) as u32;
    let code = &mut unwind_data.content.get(offset as usize..)?;

    let mut next_sp = frame.stack_pointer;
    let mut next_bp_addr = None;

    loop {
        match read_u8(code)? {
            // pop r8-r15
            0x41 => match read_u8(code) {
                Some(0x58..=0x5f) => next_sp += 8,
                _ => return None,
            },
            // add rsp, [n]
            0x48 => {
                let op = read_u8(code)?;
                if read_u8(code)? != 0xc4 {
                    return None;
                }
                match op {
                    0x81 => next_sp += read_u32(code)? as _,
                    0x83 => next_sp += read_u8(code)? as _,
                    _ => return None,
                }
            }
            // pop rsp
            0x5c => {
                log::error!("unsupported 'pop rsp'");
                return None;
            }
            // pop rbp
            0x5d => {
                next_bp_addr = Some(next_sp);
                next_sp += 8;
            }
            // pop [reg] | popf
            0x58..=0x5f | 0x9d => next_sp += 8,
            // ret
            0xc3 => break,

            _ => return None,
        }
    }

    let fun_start = (|| {
        let mut runtime_function = unwind_data.find_by_offset(offset).unwrap_or_else(|err| {
            log::error!("Failed to get unwind data: {err}");
            None
        })?;

        loop {
            let function = unwind_data.parse_function(runtime_function)?;

            match function.mother {
                Some(mother) => runtime_function = mother,
                None => break Some(unwind_data.offset + runtime_function.start),
            }
        }
    })();

    Some(UnwindResult {
        next_sp: NextSp::Value(next_sp + 8),
        next_ip_addr: next_sp,
        next_bp_addr,
        fun_start,
    })
}

enum UnwindStep {
    MachInst(u32),
    SpOffset(u32),
}

/// Read raw unwind codes and apply their effect.
fn read_unwind_codes(
    function: &FunctionEntry,
    offset: Option<u32>,
) -> IceResult<(Option<u32>, UnwindStep)> {
    let mut codes = function.iter_codes();
    let mut sp_offset = 0;
    let mut bp_addr = None;

    while let Some(uwop) = codes.next() {
        let (op_offset, op) = uwop.context("invalid unwind code")?;

        if offset.is_some() && Some(op_offset as u32) > offset && !matches!(op, UnwindOp::Epilog) {
            log::trace!("Skipped part of function prolog");
            break;
        }

        match op {
            UnwindOp::Push(reg) => {
                if reg == Reg::RBP {
                    bp_addr = Some(sp_offset);
                }
                sp_offset += 8;
            }
            UnwindOp::Alloc(size) => sp_offset += size,
            UnwindOp::PushMachFrame(error) => {
                if codes.next().is_some() {
                    return Err("unsupported UWOP_MACHFRAME in the middle of unwind ops".into());
                } else if function.mother.is_some() {
                    return Err("unsupported UWOP_MACHFRAME with mother".into());
                }

                let offset = if error { 8 } else { 0 };
                return Ok((bp_addr, UnwindStep::MachInst(sp_offset + offset)));
            }
            UnwindOp::Save(reg, offset) if reg == Reg::RBP => bp_addr = Some(offset),
            _ => (),
        }
    }

    Ok((bp_addr, UnwindStep::SpOffset(sp_offset)))
}

fn unwind_with_infos(
    unwind_data: &UnwindData,
    runtime_function: RuntimeFunction,
    frame: &ibc::StackFrame,
    base_pointer: Option<VirtualAddress>,
) -> IceResult<UnwindResult> {
    let offset_in_module = (frame.instruction_pointer - unwind_data.offset) as u32;
    let mut ip_offset = Some(offset_in_module - runtime_function.start);

    let mut function = unwind_data
        .parse_function(runtime_function)
        .context("failed to parse unwind data")?;

    let fun_start = Some(unwind_data.offset + runtime_function.start);

    let frame_pointer = match function.frame_register_offset {
        None => frame.stack_pointer,
        Some(offset) => base_pointer.context("missing required frame pointer")? - offset as u64,
    };

    let mut next_sp = frame_pointer;
    let mut next_bp_addr = None;

    loop {
        let (bp_offset, step) = read_unwind_codes(&function, ip_offset)?;
        if let Some(offset) = bp_offset {
            next_bp_addr = Some(next_sp + offset);
        }

        match step {
            UnwindStep::MachInst(offset) => {
                return Ok(UnwindResult {
                    next_sp: NextSp::Addr(next_sp + offset + 0x18),
                    next_ip_addr: next_sp + offset,
                    next_bp_addr,
                    fun_start,
                })
            }
            UnwindStep::SpOffset(offset) => next_sp += offset as u64,
        }

        match function.mother {
            Some(mother) => {
                function = unwind_data
                    .parse_function(mother)
                    .context("failed to parse unwind data")?;
                ip_offset = None;
            }

            None => break,
        }
    }

    Ok(UnwindResult {
        next_ip_addr: next_sp,
        next_sp: NextSp::Value(next_sp + 8u64),
        next_bp_addr,
        fun_start,
    })
}

fn unwind_function<B: Backend>(
    ctx: &Context<B>,
    module: &mut Module,
    frame: &ibc::StackFrame,
    base_pointer: Option<VirtualAddress>,
) -> IceResult<UnwindResult> {
    let unwind_data = module
        .get_unwind_data(ctx)
        .context("cannot get unwind data")?;

    if let Some(result) = read_epilog(unwind_data, frame) {
        log::trace!("Found function epilog");
        return Ok(result);
    }

    let offset_in_module = (frame.instruction_pointer - unwind_data.offset) as u32;
    match unwind_data.find_by_offset(offset_in_module)? {
        Some(function) => unwind_with_infos(unwind_data, function, frame, base_pointer),

        // This is a leaf function
        None => Ok(UnwindResult {
            next_ip_addr: frame.stack_pointer,
            next_sp: NextSp::Value(frame.stack_pointer + 8u64),
            next_bp_addr: None,
            fun_start: None,
        }),
    }
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
            let unwind_result = unwind_function(&ctx, module, &frame, base_pointer);

            match unwind_result {
                Ok(infos) => {
                    frame.start = infos.fun_start;
                    if f(&frame)?.is_break() {
                        return Ok(());
                    }

                    frame.instruction_pointer = ctx.read_value(infos.next_ip_addr)?;
                    frame.stack_pointer = match infos.next_sp {
                        NextSp::Addr(addr) => ctx.read_value(addr)?,
                        NextSp::Value(addr) => addr,
                    };
                    if let Some(addr) = infos.next_bp_addr {
                        base_pointer = Some(ctx.read_value(addr)?);
                    }
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
