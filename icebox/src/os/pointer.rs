use core::{fmt, marker::PhantomData};
use ibc::{IceResult, VirtualAddress};

pub trait HasLayout<L, Ctx = KernelSpace>: ibc::Os {
    fn get_layout(&self) -> &L;
}

pub struct StructOffset<T> {
    pub offset: u64,
    _typ: core::marker::PhantomData<T>,
}

impl<T> fmt::Debug for StructOffset<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StructOffset")
            .field("offset", &self.offset)
            .finish()
    }
}

impl<T> Clone for StructOffset<T> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for StructOffset<T> {}

impl<T> StructOffset<T> {
    #[inline]
    pub fn new(layout: ibc::symbols::Struct, field_name: &str) -> IceResult<Self> {
        let offset = layout.find_offset(field_name)?;
        Ok(Self::from_offset(offset))
    }

    #[inline]
    pub const fn from_offset(offset: u64) -> Self {
        Self {
            offset,
            _typ: PhantomData,
        }
    }
}

pub trait Context<Os: ibc::Os>: Copy {
    fn read_memory(self, os: &Os, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()>;
}

#[derive(Clone, Copy)]
pub struct NoContext;

#[derive(Clone, Copy)]
pub struct KernelSpace;

impl<Os: ibc::Os> Context<Os> for KernelSpace {
    #[inline]
    fn read_memory(self, os: &Os, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()> {
        os.read_kernel_memory(addr, buf)
    }
}

#[derive(Clone, Copy)]
pub struct ProcSpace {
    proc: ibc::Process,
    pgd: ibc::PhysicalAddress,
}

impl<Os: ibc::Os> Context<Os> for ProcSpace {
    #[inline]
    fn read_memory(self, os: &Os, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()> {
        if addr.is_kernel() {
            os.read_kernel_memory(addr, buf)
        } else {
            os.read_process_memory(self.proc, self.pgd, addr, buf)
        }
    }
}

pub trait Readable<Os: ibc::Os>: Sized {
    fn read<Ctx: Context<Os>>(os: &Os, ctx: Ctx, addr: VirtualAddress) -> IceResult<Self>;
}

impl<T: bytemuck::Pod, Os: ibc::Os> Readable<Os> for T {
    #[inline]
    fn read<Ctx: Context<Os>>(os: &Os, ctx: Ctx, addr: VirtualAddress) -> IceResult<Self> {
        let mut value = bytemuck::Zeroable::zeroed();
        ctx.read_memory(os, addr, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }
}

pub struct RawPointer<T> {
    pub addr: VirtualAddress,
    _typ: PhantomData<T>,
}

pub struct Pointer<'a, T, Os, Ctx = KernelSpace> {
    pub addr: VirtualAddress,
    pub os: &'a Os,
    pub ctx: Ctx,
    _typ: PhantomData<T>,
}

impl<T, Os, Ctx: Copy> Clone for Pointer<'_, T, Os, Ctx> {
    #[inline]
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, Os, Ctx: Copy> Copy for Pointer<'_, T, Os, Ctx> {}

impl<T, U, Os, Ctx> PartialEq<Pointer<'_, U, Os, Ctx>> for Pointer<'_, T, Os, Ctx> {
    #[inline]
    fn eq(&self, other: &Pointer<U, Os, Ctx>) -> bool {
        self.addr == other.addr
    }
}

impl<T, Os, Ctx> Eq for Pointer<'_, T, Os, Ctx> {}

impl<T, Os, Ctx> fmt::Debug for Pointer<'_, T, Os, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.addr.fmt(f)
    }
}

impl<'a, T, Os, Ctx> Pointer<'a, T, Os, Ctx> {
    #[inline]
    pub fn new(addr: VirtualAddress, os: &'a Os, ctx: Ctx) -> Self {
        Pointer {
            addr,
            os,
            ctx,
            _typ: PhantomData,
        }
    }

    #[inline]
    pub fn is_null(self) -> bool {
        self.addr.is_null()
    }

    #[inline]
    pub fn map_non_null<U>(self, f: impl FnOnce(Self) -> IceResult<U>) -> IceResult<Option<U>> {
        if self.addr.is_null() {
            Ok(None)
        } else {
            Some(f(self)).transpose()
        }
    }

    #[inline]
    pub fn switch_context<N>(self, ctx: N) -> Pointer<'a, T, Os, N> {
        Pointer::new(self.addr, self.os, ctx)
    }

    #[inline]
    pub fn monomorphize(self) -> Pointer<'a, T::Mono, Os, Ctx>
    where
        T: Monomorphize,
    {
        Pointer::new(self.addr, self.os, self.ctx)
    }
}

impl<'a, T, Os: ibc::Os, Ctx: Context<Os>> Pointer<'a, T, Os, Ctx> {
    #[inline]
    #[allow(dead_code)]
    pub fn read(self) -> IceResult<T>
    where
        T: Readable<Os>,
    {
        T::read(self.os, self.ctx, self.addr)
    }

    #[inline]
    pub fn field<U, F>(self, get_offset: F) -> IceResult<Pointer<'a, U, Os, Ctx>>
    where
        F: FnOnce(&T) -> StructOffset<U>,
        Os: HasLayout<T, Ctx>,
    {
        if self.addr.is_null() {
            return Err(ibc::IceError::deref_null_ptr());
        }

        let offset = get_offset(self.os.get_layout()).offset;
        Ok(Pointer::new(self.addr + offset, self.os, self.ctx))
    }

    #[inline]
    pub fn read_field<U, F>(self, get_offset: F) -> IceResult<U>
    where
        F: FnOnce(&T) -> StructOffset<U>,
        U: Readable<Os>,
        Os: HasLayout<T, Ctx>,
    {
        if self.addr.is_null() {
            return Err(ibc::IceError::deref_null_ptr());
        }

        let offset = get_offset(self.os.get_layout()).offset;
        U::read(self.os, self.ctx, self.addr + offset)
    }

    #[inline]
    pub fn read_pointer_field<U, F>(self, get_offset: F) -> IceResult<Pointer<'a, U, Os, Ctx>>
    where
        F: FnOnce(&T) -> StructOffset<RawPointer<U>>,
        Os: HasLayout<T, Ctx>,
    {
        if self.addr.is_null() {
            return Err(ibc::IceError::deref_null_ptr());
        }

        let offset = get_offset(self.os.get_layout()).offset;
        let addr = VirtualAddress::read(self.os, self.ctx, self.addr + offset)?;
        Ok(Pointer::new(addr, self.os, self.ctx))
    }

    #[inline]
    pub fn switch_to_userspace(
        self,
        proc: ibc::Process,
    ) -> IceResult<Pointer<'a, T, Os, ProcSpace>> {
        let pgd = self.os.process_pgd(proc)?;
        let proc_space = ProcSpace { proc, pgd };
        Ok(self.switch_context(proc_space))
    }
}

pub trait Monomorphize {
    type Mono;
}
