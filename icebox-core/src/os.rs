use crate::{IceResult, PhysicalAddress, VirtualAddress};
use alloc::{format, string::String, vec::Vec};
use core::ops::ControlFlow;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Module(pub VirtualAddress);

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Thread(pub VirtualAddress);

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Process(pub VirtualAddress);

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Vma(pub VirtualAddress);

#[derive(Debug, Clone, Copy)]
pub struct VmaFlags(pub u64);

impl VmaFlags {
    pub const READ: Self = Self(0x1);
    pub const WRITE: Self = Self(0x2);
    pub const EXEC: Self = Self(0x4);

    #[inline]
    pub fn is_read(self) -> bool {
        self.0 & Self::READ.0 != 0
    }

    #[inline]
    pub fn is_write(self) -> bool {
        self.0 & Self::WRITE.0 != 0
    }

    #[inline]
    pub fn is_exec(self) -> bool {
        self.0 & Self::EXEC.0 != 0
    }
}

impl core::ops::BitOr for VmaFlags {
    type Output = Self;

    #[inline]
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for VmaFlags {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

#[inline]
fn find<'a, T: Copy>(
    result: &'a mut Option<T>,
    mut predicate: impl FnMut(T) -> IceResult<bool> + 'a,
) -> impl FnMut(T) -> IceResult<ControlFlow<()>> + 'a {
    move |item| {
        Ok(if predicate(item)? {
            *result = Some(item);
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        })
    }
}

#[inline]
#[allow(clippy::needless_lifetimes)]
fn push_to<'a, T>(vec: &'a mut Vec<T>) -> impl FnMut(T) -> IceResult<ControlFlow<()>> + 'a {
    move |item| {
        vec.push(item);
        Ok(ControlFlow::Continue(()))
    }
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub start: Option<VirtualAddress>,
    pub size: Option<u64>,
    pub stack_pointer: VirtualAddress,
    pub instruction_pointer: VirtualAddress,
    pub module: Option<Module>,
}

pub trait Os: crate::HasVcpus {
    fn read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> IceResult<()>;

    fn try_read_virtual_memory(
        &self,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> IceResult<()>;

    fn read_process_memory(
        &self,
        _proc: Process,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> IceResult<()> {
        self.read_virtual_memory(mmu_addr, addr, buf)
    }

    fn try_read_process_memory(
        &self,
        _proc: Process,
        mmu_addr: PhysicalAddress,
        addr: VirtualAddress,
        buf: &mut [u8],
    ) -> IceResult<()> {
        self.try_read_virtual_memory(mmu_addr, addr, buf)
    }

    fn read_kernel_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()> {
        self.read_virtual_memory(self.kernel_pgd(), addr, buf)
    }

    fn kernel_pgd(&self) -> PhysicalAddress;

    fn for_each_kernel_module(
        &self,
        f: &mut dyn FnMut(Module) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()>;

    fn init_process(&self) -> IceResult<Process>;
    fn current_thread(&self, vcpu: crate::VcpuId) -> IceResult<Thread>;
    fn current_process(&self, vcpu: crate::VcpuId) -> IceResult<Process> {
        let thread = self.current_thread(vcpu)?;
        self.thread_process(thread)
    }
    fn find_process_by_name(&self, name: &str) -> IceResult<Option<Process>> {
        let mut proc = None;
        self.for_each_process(&mut find(&mut proc, |p| Ok(self.process_name(p)? == name)))?;
        Ok(proc)
    }
    fn find_process_by_id(&self, pid: u64) -> IceResult<Option<Process>> {
        let mut proc = None;
        self.for_each_process(&mut find(&mut proc, |p| Ok(self.process_id(p)? == pid)))?;
        Ok(proc)
    }

    fn process_is_kernel(&self, proc: Process) -> IceResult<bool>;
    fn process_id(&self, proc: Process) -> IceResult<u64>;
    fn process_name(&self, proc: Process) -> IceResult<String>;
    fn process_pgd(&self, proc: Process) -> IceResult<PhysicalAddress>;
    fn process_path(&self, proc: Process) -> IceResult<Option<String>>;
    fn process_parent(&self, proc: Process) -> IceResult<Process>;
    fn process_parent_id(&self, proc: Process) -> IceResult<u64>;
    fn process_for_each_child(
        &self,
        proc: Process,
        f: &mut dyn FnMut(Process) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()>;
    fn process_collect_children(&self, proc: Process) -> IceResult<Vec<Process>> {
        let mut procs = Vec::new();
        self.process_for_each_child(proc, &mut push_to(&mut procs))?;
        Ok(procs)
    }
    fn process_for_each_thread(
        &self,
        proc: Process,
        f: &mut dyn FnMut(Thread) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()>;
    fn process_collect_threads(&self, proc: Process) -> IceResult<Vec<Thread>> {
        let mut threads = Vec::new();
        self.process_for_each_thread(proc, &mut push_to(&mut threads))?;
        Ok(threads)
    }
    fn process_for_each_module(
        &self,
        proc: Process,
        f: &mut dyn FnMut(Module) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()>;

    fn process_collect_modules(&self, proc: Process) -> IceResult<Vec<Module>> {
        let mut modules = Vec::new();
        self.process_for_each_module(proc, &mut push_to(&mut modules))?;
        Ok(modules)
    }
    fn for_each_process(
        &self,
        f: &mut dyn FnMut(Process) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()>;
    fn collect_processes(&self) -> IceResult<Vec<Process>> {
        let mut procs = Vec::new();
        self.for_each_process(&mut push_to(&mut procs))?;
        Ok(procs)
    }
    fn process_for_each_vma(
        &self,
        proc: Process,
        f: &mut dyn FnMut(Vma) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()>;
    fn process_collect_vmas(&self, proc: Process) -> IceResult<Vec<Vma>> {
        let mut vmas = Vec::new();
        self.process_for_each_vma(proc, &mut push_to(&mut vmas))?;
        Ok(vmas)
    }

    fn process_find_vma_by_address(
        &self,
        proc: Process,
        addr: VirtualAddress,
    ) -> IceResult<Option<Vma>> {
        let mut vma = None;
        self.process_for_each_vma(proc, &mut find(&mut vma, |v| self.vma_contains(v, addr)))?;
        Ok(vma)
    }

    fn process_callstack(
        &self,
        proc: Process,
        f: &mut dyn FnMut(&StackFrame) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()> {
        // Get pointers from the current CPU
        #[allow(clippy::never_loop)]
        let (instruction_pointer, stack_pointer, base_pointer) = 'res: loop {
            for vcpu in self.iter_vcpus() {
                if self.current_process(vcpu)? == proc {
                    break 'res (
                        self.instruction_pointer(vcpu)?,
                        self.stack_pointer(vcpu)?,
                        self.base_pointer(vcpu)?,
                    );
                }
            }

            return Err(crate::IceError::new("Not a running process"));
        };

        self.process_callstack_with_regs(proc, instruction_pointer, stack_pointer, base_pointer, f)
    }

    fn process_callstack_with_regs(
        &self,
        proc: Process,
        instruction_pointer: VirtualAddress,
        stack_pointer: VirtualAddress,
        base_pointer: Option<VirtualAddress>,
        f: &mut dyn FnMut(&StackFrame) -> IceResult<ControlFlow<()>>,
    ) -> IceResult<()>;

    fn thread_process(&self, thread: Thread) -> IceResult<Process>;
    fn thread_id(&self, thread: Thread) -> IceResult<u64>;
    fn thread_name(&self, thread: Thread) -> IceResult<Option<String>>;

    fn vma_path(&self, vma: Vma) -> IceResult<Option<String>>;
    fn vma_start(&self, vma: Vma) -> IceResult<VirtualAddress>;
    fn vma_end(&self, vma: Vma) -> IceResult<VirtualAddress>;
    fn vma_flags(&self, vma: Vma) -> IceResult<VmaFlags>;
    fn vma_contains(&self, vma: Vma, addr: VirtualAddress) -> IceResult<bool> {
        Ok(self.vma_start(vma)? <= addr && addr < self.vma_end(vma)?)
    }

    fn module_span(
        &self,
        module: Module,
        proc: Process,
    ) -> IceResult<(VirtualAddress, VirtualAddress)>;

    #[inline]
    fn module_contains(
        &self,
        module: Module,
        proc: Process,
        addr: VirtualAddress,
    ) -> IceResult<bool> {
        let (start, end) = self.module_span(module, proc)?;
        Ok((start..end).contains(&addr))
    }
    fn module_name(&self, module: Module, proc: Process) -> IceResult<String>;
    fn module_path(&self, module: Module, proc: Process) -> IceResult<String>;
    fn find_module_by_address(
        &self,
        proc: Process,
        addr: VirtualAddress,
    ) -> IceResult<Option<Module>> {
        let mut result = None;

        {
            let mut find = find(&mut result, |m| self.module_contains(m, proc, addr));
            if addr.is_kernel() {
                self.for_each_kernel_module(&mut find)?;
            } else {
                self.process_for_each_module(proc, &mut find)?;
            }
        }

        Ok(result)
    }

    fn module_symbols(
        &self,
        proc: Process,
        module: Module,
    ) -> IceResult<Option<&crate::ModuleSymbols>>;

    fn module_resolve_symbol_exact(
        &self,
        addr: VirtualAddress,
        proc: Process,
        module: Module,
    ) -> IceResult<Option<&str>> {
        let syms = match self.module_symbols(proc, module)? {
            Some(syms) => syms,
            None => return Ok(None),
        };

        let (mod_start, mod_end) = self.module_span(module, proc)?;
        if !(mod_start..mod_end).contains(&addr) {
            return Err(crate::IceError::new("address not in module"));
        }
        let addr = VirtualAddress((addr - mod_start) as u64);

        Ok(syms.get_symbol(addr))
    }

    fn module_resolve_symbol(
        &self,
        addr: VirtualAddress,
        proc: Process,
        module: Module,
    ) -> IceResult<Option<(&str, u64)>> {
        let syms = match self.module_symbols(proc, module)? {
            Some(syms) => syms,
            None => return Ok(None),
        };

        let (mod_start, mod_end) = self.module_span(module, proc)?;
        if !(mod_start..mod_end).contains(&addr) {
            return Err(crate::IceError::new("address not in module"));
        }
        let addr = VirtualAddress((addr - mod_start) as u64);

        Ok(syms.get_symbol_inexact(addr))
    }

    fn resolve_symbol_exact(&self, addr: VirtualAddress, proc: Process) -> IceResult<Option<&str>> {
        match self.find_module_by_address(proc, addr)? {
            Some(module) => self.module_resolve_symbol_exact(addr, proc, module),
            None => Ok(None),
        }
    }

    fn resolve_symbol(
        &self,
        addr: VirtualAddress,
        proc: Process,
    ) -> IceResult<Option<(&str, u64)>> {
        match self.find_module_by_address(proc, addr)? {
            Some(module) => self.module_resolve_symbol(addr, proc, module),
            None => Ok(None),
        }
    }

    fn format_symbol(&self, proc: Process, addr: VirtualAddress) -> IceResult<String> {
        match self.find_module_by_address(proc, addr)? {
            Some(module) => self.format_symbol_with_module(proc, module, addr, None),
            None => format_symbol_without_module(self, proc, addr, None),
        }
    }

    fn format_symbol_with_module(
        &self,
        proc: Process,
        module: Module,
        addr: VirtualAddress,
        fun_start: Option<VirtualAddress>,
    ) -> IceResult<String> {
        let (mod_start, _) = self.module_span(module, proc)?;
        let mod_name = self.module_name(module, proc)?;

        let symbol = match fun_start {
            Some(fun_start) => self
                .module_resolve_symbol_exact(fun_start, proc, module)
                .map(|s| s.map(|s| (s, (addr - fun_start) as u64))),
            None => self.module_resolve_symbol(addr, proc, module),
        };
        let symbol = symbol.unwrap_or_else(|err| {
            log::error!("{err}");
            None
        });

        Ok(match symbol {
            Some((symbol, 0)) => format!("{mod_name}!{symbol}"),
            Some((symbol, offset)) => format!("{mod_name}!{symbol}+{offset:#x}"),
            None => match fun_start {
                Some(fun_start) => format!(
                    "{mod_name}!{:#x}+{:#x}",
                    fun_start - mod_start,
                    addr - fun_start
                ),
                None => format!("{mod_name}!{:#x}", addr - mod_start),
            },
        })
    }

    fn format_stackframe_symbol(&self, proc: Process, frame: &StackFrame) -> IceResult<String> {
        let addr = frame.instruction_pointer;
        match frame.module {
            Some(module) => self.format_symbol_with_module(proc, module, addr, frame.start),
            None => format_symbol_without_module(self, proc, addr, frame.start),
        }
    }
}

fn format_symbol_without_module<O: Os + ?Sized>(
    os: &O,
    proc: Process,
    addr: VirtualAddress,
    fun_start: Option<VirtualAddress>,
) -> IceResult<String> {
    let vma_start = match os.process_find_vma_by_address(proc, addr)? {
        Some(vma) => Some(os.vma_start(vma)?),
        None => None,
    };

    Ok(match (vma_start, fun_start) {
        (Some(vma_start), Some(fun_start)) => format!(
            "{vma_start:#x}!{:#x}+{:#x}",
            vma_start - fun_start,
            addr - fun_start
        ),
        (Some(vma_start), None) => format!("{vma_start:#x}!{:#x}", addr - vma_start),
        (None, Some(fun_start)) => format!("{fun_start:#x}+{:#x}", addr - fun_start),
        (None, None) => format!("{addr:#x}"),
    })
}
