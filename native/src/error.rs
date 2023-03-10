use crate::cstring;
use core::{
    cell::Cell,
    ffi::{c_char, c_int},
    fmt::{self, Write},
    mem,
};
use ibc::IceError;

thread_local! {
    static ERROR: Cell<Option<IceError>> = const { Cell::new(None) };
}

fn set_error(error: IceError) {
    ERROR.with(|e| e.set(Some(error)))
}

fn clear_error() {
    ERROR.with(|e| e.set(None))
}

fn take_error() -> Option<IceError> {
    ERROR.with(|e| e.take())
}

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
pub fn wrap_result<T, U>(res: Option<&mut mem::MaybeUninit<T>>, result: ibc::IceResult<U>) -> c_int
where
    U: Into<T>,
{
    match result {
        Ok(val) => {
            if let Some(res) = res {
                res.write(val.into());
            }
            0
        }
        Err(err) => {
            set_error(err);
            1
        }
    }
}

#[inline]
pub fn wrap<F, T>(res: Option<&mut mem::MaybeUninit<T>>, f: F) -> c_int
where
    F: FnOnce() -> ibc::IceResult<T>,
{
    wrap_result(res, f())
}

#[inline]
pub fn wrap_unit_result(result: ibc::IceResult<()>) -> c_int {
    match result {
        Ok(()) => {
            clear_error();
            0
        }
        Err(err) => {
            set_error(err);
            -1
        }
    }
}

#[inline]
pub fn wrap_unit(f: impl FnOnce() -> ibc::IceResult<()>) -> c_int {
    wrap_unit_result(f())
}

#[inline]
pub fn wrap_box_result<T>(result: ibc::IceResult<Box<T>>) -> Option<Box<T>> {
    match result {
        Ok(res) => {
            clear_error();
            Some(res)
        }
        Err(err) => {
            set_error(err);
            None
        }
    }
}

#[inline]
pub fn wrap_box<T>(f: impl FnOnce() -> ibc::IceResult<Box<T>>) -> Option<Box<T>> {
    wrap_box_result(f())
}

#[inline]
pub fn wrap_usize(f: impl FnOnce() -> ibc::IceResult<usize>) -> isize {
    match f() {
        Ok(n) => {
            clear_error();
            n as isize
        }
        Err(err) => {
            set_error(err);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn take_last_error() -> *mut Error {
    match take_error() {
        Some(err) => error_into(err),
        None => core::ptr::null_mut(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn print_last_error(str: *mut c_char, max_len: usize) -> usize {
    let mut fmt = cstring::Formatter::new(str, max_len);
    ERROR.with(|e| match e.take() {
        Some(err) => {
            let _ = fmt::write(&mut fmt, format_args!("{err:#}"));
            e.set(Some(err));
        }
        None => {
            let _ = fmt.write_str("success");
        }
    });
    fmt.finish()
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
        let _ = fmt::write(&mut fmt, format_args!("{err:#}"));
    }
    fmt.finish()
}

#[no_mangle]
pub unsafe extern "C" fn error_free(err: *mut Error) {
    drop(error_from(err));
}
