#[cfg(any(feature = "linux", feature = "windows"))]
mod pointer;

#[cfg(any(feature = "linux", feature = "windows"))]
macro_rules! pointer_defs {
    ( $( $core_ty:path = $ptr:ty; )* ) => {
        trait AsPointer<T> {
            fn as_pointer<Ctx>(self, ctx: Ctx) -> Pointer<T, Ctx>;
        }

        $(
            impl AsPointer<$ptr> for $core_ty {
                #[inline]
                fn as_pointer<Ctx>(self, ctx: Ctx) -> Pointer<$ptr, Ctx> {
                    Pointer::new(self.0, ctx)
                }
            }

            impl<Ctx> From<Pointer<$ptr, Ctx>> for $core_ty {
                #[inline]
                fn from(ptr: Pointer<$ptr, Ctx>) -> $core_ty {
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

use ibc::{Backend, IceResult};

pub trait OsBuilder<B: Backend> {
    fn quick_check(_backend: &B) -> IceResult<bool> {
        Ok(false)
    }
}
