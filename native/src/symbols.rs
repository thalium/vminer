use crate::{
    c_char, cstring,
    error::{self, Error},
};
use alloc::boxed::Box;
use ibc::SymbolsIndexer;

#[derive(Default)]
pub struct Symbols(pub SymbolsIndexer);

#[no_mangle]
pub extern "C" fn symbols_new() -> Box<Symbols> {
    Default::default()
}

#[no_mangle]
pub unsafe extern "C" fn symbols_read_object(
    indexer: &mut Symbols,
    data: *const u8,
    len: usize,
) -> *mut Error {
    let data = core::slice::from_raw_parts(data, len);
    error::wrap_unit_result(indexer.0.read_object_from_bytes(data))
}

#[no_mangle]
pub unsafe extern "C" fn symbols_read_object_from_file(
    indexer: &mut Symbols,
    path: *const c_char,
) -> *mut Error {
    error::wrap_unit(|| {
        let path = cstring::from_ut8(path)?;
        indexer.0.read_object_file(path)
    })
}

#[no_mangle]
pub extern "C" fn symbols_free(indexer: Option<Box<Symbols>>) {
    drop(indexer)
}
