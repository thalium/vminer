use core::{ops::ControlFlow, ptr::NonNull};

pub struct Array<T> {
    ptr: Option<NonNull<T>>,
    max_size: usize,
    size: *mut usize,
}

impl<T> Array<T> {
    #[inline]
    pub unsafe fn new(ptr: *mut T, size: *mut usize) -> Self {
        let max_size = if size.is_null() {
            0
        } else {
            let s = *size;
            *size = 0;
            s
        };

        Self {
            ptr: NonNull::new(ptr),
            max_size,
            size,
        }
    }

    #[inline]
    pub fn push(&mut self, val: T) -> ControlFlow<()> {
        unsafe {
            match &mut self.ptr {
                Some(ptr) => {
                    if *self.size < self.max_size {
                        ptr.as_ptr().write(val);
                        *ptr = NonNull::new_unchecked(ptr.as_ptr().add(1));
                        *self.size += 1;
                        ControlFlow::Continue(())
                    } else {
                        ControlFlow::Break(())
                    }
                }
                None => {
                    if !self.size.is_null() {
                        *self.size += 1;
                    }
                    ControlFlow::Continue(())
                }
            }
        }
    }
}
