use crate::error::{self, Error};
use crate::{c_char, cstring};
use alloc::boxed::Box;
use ibc::SymbolsIndexer;

#[derive(Default)]
pub struct Symbols(pub SymbolsIndexer);

#[no_mangle]
pub extern "C" fn symbols_new() -> Box<Symbols> {
    Default::default()
}

#[no_mangle]
pub unsafe extern "C" fn symbols_load_from_bytes(
    indexer: &mut Symbols,
    name: *const c_char,
    data: *const u8,
    len: usize,
) -> *mut Error {
    error::wrap_unit(|| {
        let data = core::slice::from_raw_parts(data, len);
        let name = cstring::from_ut8(name)?.into();
        indexer.0.load_from_bytes(name, data)?;
        Ok(())
    })
}

#[cfg(feature = "std")]
#[no_mangle]
pub unsafe extern "C" fn symbols_load_from_file(
    indexer: &mut Symbols,
    path: *const c_char,
) -> *mut Error {
    error::wrap_unit(|| {
        let path = cstring::from_ut8(path)?;
        indexer.0.load_from_file(path)?;
        Ok(())
    })
}

#[cfg(feature = "std")]
#[no_mangle]
pub unsafe extern "C" fn symbols_load_dir(
    indexer: &mut Symbols,
    path: *const c_char,
) -> *mut Error {
    error::wrap_unit(|| {
        let path = cstring::from_ut8(path)?;
        indexer.0.load_dir(path)
    })
}

#[no_mangle]
pub extern "C" fn symbols_free(indexer: Option<Box<Symbols>>) {
    drop(indexer)
}
