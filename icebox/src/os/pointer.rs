use core::{fmt, marker::PhantomData};
use ibc::{IceResult, VirtualAddress};

pub trait HasLayout<L>: Context {
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

pub trait Context: Copy {
    fn read_memory(&self, addr: VirtualAddress, buf: &mut [u8]) -> IceResult<()>;
}

#[derive(Clone, Copy)]
pub struct NoContext;

pub trait Readable: Sized {
    fn read<Ctx: Context>(ctx: Ctx, addr: VirtualAddress) -> IceResult<Self>;
}

impl<T: bytemuck::Pod> Readable for T {
    #[inline]
    fn read<Ctx: Context>(ctx: Ctx, addr: VirtualAddress) -> IceResult<Self> {
        let mut value = bytemuck::Zeroable::zeroed();
        ctx.read_memory(addr, bytemuck::bytes_of_mut(&mut value))?;
        Ok(value)
    }
}

pub struct Pointer<T, Ctx = NoContext> {
    pub addr: VirtualAddress,
    pub ctx: Ctx,
    _typ: PhantomData<T>,
}

impl<T, Ctx: Copy> Clone for Pointer<T, Ctx> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T, Ctx: Copy> Copy for Pointer<T, Ctx> {}

impl<T, Ctx> PartialEq for Pointer<T, Ctx> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl<T, Ctx> Eq for Pointer<T, Ctx> {}

impl<T, Ctx> fmt::Debug for Pointer<T, Ctx> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.addr.fmt(f)
    }
}

impl<T, Ctx> Pointer<T, Ctx> {
    #[inline]
    pub fn new(addr: VirtualAddress, ctx: Ctx) -> Self {
        Pointer {
            addr,
            ctx,
            _typ: PhantomData,
        }
    }

    #[inline]
    pub fn is_null(self) -> bool {
        self.addr.is_null()
    }

    #[inline]
    pub fn switch_context<N: Context>(self, ctx: N) -> Pointer<T, N> {
        Pointer::new(self.addr, ctx)
    }
}

impl<T, Ctx: Context> Pointer<T, Ctx> {
    #[inline]
    #[allow(dead_code)]
    pub fn read(self) -> IceResult<T>
    where
        T: Readable,
    {
        T::read(self.ctx, self.addr)
    }

    #[inline]
    pub fn field<U, F>(self, get_offset: F) -> IceResult<Pointer<U, Ctx>>
    where
        F: FnOnce(&T) -> StructOffset<U>,
        Ctx: HasLayout<T>,
    {
        let offset = get_offset(self.ctx.get_layout()).offset;
        Ok(Pointer::new(self.addr + offset, self.ctx))
    }

    #[inline]
    pub fn read_field<U, F>(self, get_offset: F) -> IceResult<U>
    where
        F: FnOnce(&T) -> StructOffset<U>,
        U: Readable,
        Ctx: HasLayout<T>,
    {
        let offset = get_offset(self.ctx.get_layout()).offset;
        U::read(self.ctx, self.addr + offset)
    }

    #[inline]
    pub fn read_pointer_field<U, F>(self, get_offset: F) -> IceResult<Pointer<U, Ctx>>
    where
        F: FnOnce(&T) -> StructOffset<Pointer<U>>,
        Ctx: HasLayout<T>,
    {
        let offset = get_offset(self.ctx.get_layout()).offset;
        let addr = VirtualAddress::read(self.ctx, self.addr + offset)?;
        Ok(Pointer::new(addr, self.ctx))
    }
}
