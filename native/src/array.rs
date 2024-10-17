use core::{ops::ControlFlow, ptr::NonNull};

pub struct Array<T> {
    array: Option<NonNull<T>>,
    max_size: usize,
    cursor: usize,
}

impl<T> Array<T> {
    #[inline]
    unsafe fn new(ptr: *mut T, max_size: usize) -> Self {
        Self {
            array: NonNull::new(ptr),
            max_size,
            cursor: 0,
        }
    }

    #[inline]
    pub fn push(&mut self, val: T) -> ControlFlow<()> {
        match self.array {
            Some(array) => unsafe {
                if self.cursor < self.max_size {
                    array.as_ptr().add(self.cursor).write(val);
                    self.cursor += 1;
                    ControlFlow::Continue(())
                } else {
                    ControlFlow::Break(())
                }
            },
            None => {
                self.cursor += 1;
                ControlFlow::Continue(())
            }
        }
    }
}

impl<T> Drop for Array<T> {
    fn drop(&mut self) {
        if let Some(array) = self.array {
            let slice = core::ptr::slice_from_raw_parts_mut(array.as_ptr(), self.cursor);
            unsafe {
                core::ptr::drop_in_place(slice);
            }
        }
    }
}

pub unsafe fn fill<T>(
    ptr: *mut T,
    max_size: usize,
    f: impl FnOnce(&mut Array<T>) -> vmc::VmResult<()>,
) -> isize {
    crate::error::wrap_usize(|| {
        let mut array = Array::new(ptr, max_size);
        f(&mut array)?;
        let n = array.cursor;
        core::mem::forget(array);
        Ok(n)
    })
}
