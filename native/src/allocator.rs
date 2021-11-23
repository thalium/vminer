use alloc::alloc;
use core::{mem, ptr};

use crate::c_void;

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

impl Allocator {
    #[cfg(not(feature = "std"))]
    const DEFAULT: Self = {
        unsafe extern "C" fn alloc(_data: *mut c_void, _size: usize, _align: usize) -> *mut c_void {
            ptr::null_mut()
        }

        unsafe extern "C" fn dealloc(
            _data: *mut c_void,
            _ptr: *mut c_void,
            _size: usize,
            _align: usize,
        ) {
        }

        unsafe extern "C" fn realloc(
            _data: *mut c_void,
            _ptr: *mut c_void,
            _size: usize,
            _align: usize,
            _new_size: usize,
        ) -> *mut c_void {
            ptr::null_mut()
        }

        Self {
            data: ptr::null_mut(),
            alloc,
            dealloc,
            realloc,
        }
    };

    #[cfg(feature = "std")]
    const DEFAULT: Self = {
        use std::alloc::{GlobalAlloc, System};

        unsafe extern "C" fn alloc(_data: *mut c_void, size: usize, align: usize) -> *mut c_void {
            let layout = alloc::Layout::from_size_align_unchecked(size, align);
            System.alloc(layout)
        }

        unsafe extern "C" fn dealloc(
            _data: *mut c_void,
            ptr: *mut c_void,
            size: usize,
            align: usize,
        ) {
            let layout = alloc::Layout::from_size_align_unchecked(size, align);
            System.dealloc(ptr, layout)
        }

        unsafe extern "C" fn realloc(
            _data: *mut c_void,
            ptr: *mut c_void,
            size: usize,
            align: usize,
            new_size: usize,
        ) -> *mut c_void {
            let layout = alloc::Layout::from_size_align_unchecked(size, align);
            System.realloc(ptr, layout, new_size)
        }

        Self {
            data: ptr::null_mut(),
            alloc,
            dealloc,
            realloc,
        }
    };
}

struct GlobalAllocator(spin::Mutex<Allocator>);

impl GlobalAllocator {
    const fn new() -> Self {
        Self(spin::Mutex::new(Allocator::DEFAULT))
    }
}

unsafe impl alloc::GlobalAlloc for GlobalAllocator {
    unsafe fn alloc(&self, layout: alloc::Layout) -> *mut c_void {
        let (data, alloc) = {
            let allocator = &*self.0.lock();
            (allocator.data, allocator.alloc)
        };
        alloc(data, layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut c_void, layout: alloc::Layout) {
        let (data, dealloc) = {
            let allocator = &*self.0.lock();
            (allocator.data, allocator.dealloc)
        };
        dealloc(data, ptr, layout.size(), layout.align())
    }

    unsafe fn realloc(
        &self,
        ptr: *mut c_void,
        layout: alloc::Layout,
        new_size: usize,
    ) -> *mut c_void {
        let (data, realloc) = {
            let allocator = &*self.0.lock();
            (allocator.data, allocator.realloc)
        };
        realloc(data, ptr, layout.size(), layout.align(), new_size)
    }
}

#[no_mangle]
pub unsafe extern "C" fn set_allocator(allocator: Option<&Allocator>) {
    *ALLOCATOR.0.lock() = *allocator.unwrap_or(&Allocator::DEFAULT)
}

#[no_mangle]
pub unsafe extern "C" fn get_allocator(allocator: Option<&mut mem::MaybeUninit<Allocator>>) {
    if let Some(allocator) = allocator {
        allocator.write(*ALLOCATOR.0.lock());
    }
}

#[no_mangle]
pub unsafe extern "C" fn allocate(size: usize, align: usize) -> *mut c_void {
    let layout = alloc::Layout::from_size_align_unchecked(size, align);
    alloc::alloc(layout).cast()
}

#[no_mangle]
pub unsafe extern "C" fn deallocate(ptr: *mut c_void, size: usize, align: usize) {
    let layout = alloc::Layout::from_size_align_unchecked(size, align);
    alloc::dealloc(ptr, layout)
}

#[no_mangle]
pub unsafe extern "C" fn reallocate(
    ptr: *mut c_void,
    size: usize,
    align: usize,
    new_size: usize,
) -> *mut c_void {
    let layout = alloc::Layout::from_size_align_unchecked(size, align);
    alloc::realloc(ptr, layout, new_size).cast()
}
