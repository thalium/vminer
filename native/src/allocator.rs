use alloc::alloc;
use core::ffi::{c_int, c_void};

#[global_allocator]
static ALLOCATOR: GlobalAllocator = GlobalAllocator::new();

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Allocator {
    data: *mut c_void,
    alloc: unsafe extern "C" fn(*mut c_void, usize, usize) -> *mut c_void,
    dealloc: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, usize),
    realloc: unsafe extern "C" fn(*mut c_void, *mut c_void, usize, usize, usize) -> *mut c_void,
}

unsafe impl Send for Allocator {}
unsafe impl Sync for Allocator {}

impl Allocator {
    #[cfg(feature = "std")]
    const SYSTEM: Self = {
        use std::alloc::{GlobalAlloc, System};

        unsafe extern "C" fn alloc(_data: *mut c_void, size: usize, align: usize) -> *mut c_void {
            let layout = alloc::Layout::from_size_align_unchecked(size, align);
            System.alloc(layout).cast()
        }

        unsafe extern "C" fn dealloc(
            _data: *mut c_void,
            ptr: *mut c_void,
            size: usize,
            align: usize,
        ) {
            let layout = alloc::Layout::from_size_align_unchecked(size, align);
            System.dealloc(ptr.cast(), layout)
        }

        unsafe extern "C" fn realloc(
            _data: *mut c_void,
            ptr: *mut c_void,
            size: usize,
            align: usize,
            new_size: usize,
        ) -> *mut c_void {
            let layout = alloc::Layout::from_size_align_unchecked(size, align);
            System.realloc(ptr.cast(), layout, new_size).cast()
        }

        Self {
            data: core::ptr::null_mut(),
            alloc,
            dealloc,
            realloc,
        }
    };
}

struct GlobalAllocator(spin::Once<Allocator>);

impl GlobalAllocator {
    #[inline]
    const fn new() -> Self {
        Self(spin::Once::new())
    }

    #[cfg(feature = "std")]
    #[inline]
    fn get(&self) -> Option<&Allocator> {
        Some(self.0.call_once(|| Allocator::SYSTEM))
    }

    #[cfg(not(feature = "std"))]
    #[inline]
    fn get(&self) -> Option<&Allocator> {
        self.0.get()
    }
}

unsafe impl alloc::GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: alloc::Layout) -> *mut u8 {
        match self.get() {
            Some(alloc) => (alloc.alloc)(alloc.data, layout.size(), layout.align()).cast(),
            None => core::ptr::null_mut(),
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: alloc::Layout) {
        if let Some(alloc) = self.get() {
            (alloc.dealloc)(alloc.data, ptr.cast(), layout.size(), layout.align());
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: alloc::Layout, new_size: usize) -> *mut u8 {
        match self.get() {
            Some(alloc) => (alloc.realloc)(
                alloc.data,
                ptr.cast(),
                layout.size(),
                layout.align(),
                new_size,
            )
            .cast(),
            None => core::ptr::null_mut(),
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn set_allocator(allocator: Allocator) -> c_int {
    let mut set = 0;
    ALLOCATOR.0.call_once(|| {
        set = 1;
        allocator
    });
    set
}

#[no_mangle]
pub unsafe extern "C" fn allocate(size: usize, align: usize) -> *mut c_void {
    let layout = alloc::Layout::from_size_align_unchecked(size, align);
    alloc::alloc(layout).cast()
}

#[no_mangle]
pub unsafe extern "C" fn deallocate(ptr: *mut c_void, size: usize, align: usize) {
    let layout = alloc::Layout::from_size_align_unchecked(size, align);
    alloc::dealloc(ptr.cast(), layout)
}

#[no_mangle]
pub unsafe extern "C" fn reallocate(
    ptr: *mut c_void,
    size: usize,
    align: usize,
    new_size: usize,
) -> *mut c_void {
    let layout = alloc::Layout::from_size_align_unchecked(size, align);
    alloc::realloc(ptr.cast(), layout, new_size).cast()
}
