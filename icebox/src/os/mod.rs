#[cfg(any(feature = "linux", feature = "windows"))]
macro_rules! pointer_defs {
    ( $( $core_ty:ty = $ptr:ty; )* ) => {
        $(
            impl From<$core_ty> for Pointer<$ptr> {
                #[inline]
                fn from(val: $core_ty) -> Self {
                    Self::new(val.0)
                }
            }

            impl From<Pointer<$ptr>> for $core_ty {
                #[inline]
                fn from(ptr: Pointer<$ptr>) -> Self {
                    Self(ptr.addr)
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
