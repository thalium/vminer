#[cfg(any(feature = "linux", feature = "windows"))]
mod pointer;

#[cfg(any(feature = "linux", feature = "windows"))]
macro_rules! pointer_defs {
    ( $( $core_ty:path = $ptr:ty; )* ) => {
        trait ToPointer<T> {
            fn to_pointer<Os, Ctx>(self, os: &Os, ctx: Ctx) -> Pointer<T, Os, Ctx>;
        }

        $(
            impl ToPointer<$ptr> for $core_ty {
                #[inline]
                fn to_pointer<Os, Ctx>(self, os: &Os, ctx: Ctx) -> Pointer<$ptr, Os, Ctx> {
                    Pointer::new(self.0, os, ctx)
                }
            }

            impl<Os, Ctx> From<Pointer<'_, $ptr, Os, Ctx>> for $core_ty {
                #[inline]
                fn from(ptr: Pointer<$ptr, Os, Ctx>) -> $core_ty {
                    $core_ty(ptr.addr)
                }
            }
        )*
    };
}

#[cfg(feature = "linux")]
pub mod linux;
#[cfg(feature = "linux")]
pub use linux::Linux;

#[cfg(feature = "windows")]
pub mod windows;
#[cfg(feature = "windows")]
pub use windows::Windows;

use alloc::string::String;
use ibc::IceResult;

pub trait Buildable<B: ibc::Backend>: Sized {
    fn quick_check(_backend: &B) -> Option<OsBuilder> {
        None
    }

    fn build(backend: B, builder: OsBuilder) -> IceResult<Self>;
}

#[derive(Debug, Default)]
pub struct OsBuilder {
    pub symbols: Option<ibc::SymbolsIndexer>,
    pub kpgd: Option<ibc::PhysicalAddress>,
    pub kaslr: Option<ibc::VirtualAddress>,
    pub version: Option<String>,
}

impl OsBuilder {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn with_symbols(mut self, symbols: ibc::SymbolsIndexer) -> Self {
        self.symbols = Some(symbols);
        self
    }

    #[inline]
    pub fn with_kpgd(mut self, kpgd: ibc::PhysicalAddress) -> Self {
        self.kpgd = Some(kpgd);
        self
    }

    #[inline]
    pub fn with_kaslr(mut self, kaslr: ibc::VirtualAddress) -> Self {
        self.kaslr = Some(kaslr);
        self
    }

    #[inline]
    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }

    #[inline]
    pub fn build<B: ibc::Backend, Os: Buildable<B>>(self, backend: B) -> IceResult<Os> {
        Os::build(backend, self)
    }
}

#[inline]
pub fn os_builder() -> OsBuilder {
    OsBuilder::new()
}
