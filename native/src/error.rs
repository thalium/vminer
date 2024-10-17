use crate::cstring;
use core::{
    cell::Cell,
    ffi::{c_char, c_int},
    fmt::{self, Write},
    mem,
};
use vmc::{VmError, VmResult};

thread_local! {
    static ERROR: Cell<Option<VmError>> = const { Cell::new(None) };
}

fn set_error(error: VmError) {
    ERROR.with(|e| e.set(Some(error)))
}

fn clear_error() {
    ERROR.with(|e| e.set(None))
}

fn take_error() -> Option<VmError> {
    ERROR.with(|e| e.take())
}

#[inline]
unsafe fn error_ref(err: &*const Error) -> &VmError {
    mem::transmute(err)
}

#[inline]
unsafe fn error_from(err: *mut Error) -> VmError {
    mem::transmute(err)
}

#[inline]
fn error_into(err: VmError) -> *mut Error {
    unsafe { mem::transmute(err) }
}

pub struct Error;

#[cfg(feature = "std")]
#[inline]
fn catch_unwind<T>(f: impl FnOnce() -> VmResult<T>) -> Option<T> {
    #[cold]
    fn convert_panic_payload(payload: Box<dyn std::any::Any + Send>) -> VmError {
        if let Some(string) = payload.downcast_ref::<String>() {
            VmError::new(format!("panic at: {string}"))
        } else if let Some(s) = payload.downcast_ref::<&str>() {
            VmError::new(format!("panic at: {s}"))
        } else {
            VmError::new("panic")
        }
    }

    let res = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(res) => res,
        Err(payload) => Err(convert_panic_payload(payload)),
    };

    match res {
        Ok(val) => {
            clear_error();
            Some(val)
        }
        Err(error) => {
            set_error(error);
            None
        }
    }
}

#[cfg(not(feature = "std"))]
#[inline]
fn catch_unwind<T>(f: impl FnOnce() -> VmResult<T>) -> VmResult<T> {
    match f() {
        Ok(val) => {
            clear_error();
            Some(val)
        }
        Err(error) => {
            set_error(error);
            None
        }
    }
}

#[inline]
pub fn wrap<F, T, U>(res: Option<&mut mem::MaybeUninit<T>>, f: F) -> c_int
where
    F: FnOnce() -> VmResult<U>,
    U: Into<T>,
{
    match catch_unwind(f) {
        Some(val) => {
            if let Some(res) = res {
                res.write(val.into());
            }
            0
        }
        None => 1,
    }
}

#[inline]
pub fn wrap_unit(f: impl FnOnce() -> VmResult<()>) -> c_int {
    match catch_unwind(f) {
        Some(()) => 0,
        None => -1,
    }
}

#[inline]
pub fn wrap_box<T>(f: impl FnOnce() -> VmResult<Box<T>>) -> Option<Box<T>> {
    catch_unwind(f)
}

#[inline]
pub fn wrap_usize(f: impl FnOnce() -> VmResult<usize>) -> isize {
    match catch_unwind(f) {
        Some(n) => n as isize,
        None => -1,
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
    let err = VmError::with_context(context, error_from(err));
    error_into(err)
}

#[no_mangle]
pub unsafe extern "C" fn error_missing_symbol(sym: *mut c_char) -> *mut Error {
    let err = VmError::missing_symbol(&cstring::from_ut8_lossy(sym));
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
