use crate::{c_char, cstring};
use core::{
    fmt::{self, Write},
    mem, ptr,
};
use ibc::IceError;

#[inline]
unsafe fn error_ref(err: &*const Error) -> &IceError {
    mem::transmute(err)
}

#[inline]
unsafe fn error_from(err: *mut Error) -> IceError {
    mem::transmute(err)
}

#[inline]
fn error_into(err: IceError) -> *mut Error {
    unsafe { mem::transmute(err) }
}

pub struct Error;

#[inline]
pub fn wrap_result<T, U>(result: ibc::IceResult<U>, res: &mut mem::MaybeUninit<T>) -> *mut Error
where
    U: Into<T>,
{
    match result {
        Ok(val) => {
            res.write(val.into());
            ptr::null_mut()
        }
        Err(err) => error_into(err),
    }
}

#[inline]
pub fn wrap<F, T>(res: &mut mem::MaybeUninit<T>, f: F) -> *mut Error
where
    F: FnOnce() -> ibc::IceResult<T>,
{
    wrap_result(f(), res)
}

#[inline]
pub fn wrap_unit_result(result: ibc::IceResult<()>) -> *mut Error {
    match result {
        Ok(()) => ptr::null_mut(),
        Err(err) => error_into(err),
    }
}

#[inline]
pub fn wrap_unit(f: impl FnOnce() -> ibc::IceResult<()>) -> *mut Error {
    wrap_unit_result(f())
}

#[no_mangle]
pub unsafe extern "C" fn error_with_message(err: *mut Error, context: *mut c_char) -> *mut Error {
    let context = cstring::from_ut8_lossy(context);
    let err = IceError::with_context(context, error_from(err));
    error_into(err)
}

#[no_mangle]
pub unsafe extern "C" fn error_missing_symbol(sym: *mut c_char) -> *mut Error {
    let err = IceError::missing_symbol(&cstring::from_ut8_lossy(sym));
    error_into(err)
}

#[no_mangle]
pub unsafe extern "C" fn error_print(err: *const Error, str: *mut c_char, max_len: usize) -> usize {
    let mut fmt = cstring::Formatter::new(str, max_len);
    if err.is_null() {
        let _ = fmt.write_str("success");
    } else {
        let err = error_ref(&err);
        let _ = fmt::write(&mut fmt, format_args!("{:#}", err));
    }
    fmt.finish()
}

#[no_mangle]
pub unsafe extern "C" fn error_free(err: *mut Error) {
    drop(error_from(err));
}
