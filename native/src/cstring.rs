use alloc::{borrow::Cow, string::String};
use core::{cmp, fmt, num::NonZeroUsize, ptr, slice};

use crate::c_char;

pub unsafe fn strlen(str: *const c_char) -> usize {
    let mut len = 0;

    while *str.add(len) != 0 {
        len += 1;
    }

    len
}

pub unsafe fn from_ut8_lossy<'a>(str: *const c_char) -> Cow<'a, str> {
    let len = strlen(str);
    let bytes = slice::from_raw_parts(str, len);
    String::from_utf8_lossy(bytes)
}

pub struct Formatter {
    ptr: *mut c_char,
    len: usize,
    written: usize,
}

impl Formatter {
    pub unsafe fn new(ptr: *mut c_char, len: NonZeroUsize) -> Self {
        Self {
            ptr,
            len: len.get() - 1,
            written: 0,
        }
    }

    pub fn finish(self) -> usize {
        unsafe {
            self.ptr.write(0);
        }
        self.written
    }
}

impl fmt::Write for Formatter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();

        let n = cmp::min(bytes.len(), self.len);

        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), self.ptr, n);
        }

        self.ptr = unsafe { self.ptr.add(n) };
        self.len -= n;
        self.written += n;

        if bytes.len() > n {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}
