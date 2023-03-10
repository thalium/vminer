use core::{ops::ControlFlow, ptr::NonNull};

pub struct Array<T> {
    ptr: Option<NonNull<T>>,
    max_size: usize,
    size: usize,
}

impl<T> Array<T> {
    #[inline]
    unsafe fn new(ptr: *mut T, max_size: usize) -> Self {
        Self {
            ptr: NonNull::new(ptr),
            max_size,
            size: 0,
        }
    }

    #[inline]
    pub fn push(&mut self, val: T) -> ControlFlow<()> {
        unsafe {
            match &mut self.ptr {
                Some(ptr) => {
                    if self.size < self.max_size {
                        ptr.as_ptr().write(val);
                        *ptr = NonNull::new_unchecked(ptr.as_ptr().add(1));
                        self.size += 1;
                        ControlFlow::Continue(())
                    } else {
                        ControlFlow::Break(())
                    }
                }
                None => {
                    self.size += 1;
                    ControlFlow::Continue(())
                }
            }
        }
    }
}

pub unsafe fn fill<T>(
    ptr: *mut T,
    max_size: usize,
    f: impl FnOnce(&mut Array<T>) -> ibc::IceResult<()>,
) -> isize {
    crate::error::wrap_usize(|| {
        let mut array = Array::new(ptr, max_size);
        f(&mut array)?;
        Ok(array.size)
    })
}
