use crate::IceResult;

#[cfg(feature = "std")]
type OnceCellImp<T> = once_cell::sync::OnceCell<T>;

#[cfg(not(feature = "std"))]
struct OnceCellImp<T>(once_cell::race::OnceBox<T>);

#[cfg(not(feature = "std"))]
impl<T> OnceCellImp<T> {
    pub const fn new() -> Self {
        Self(once_cell::race::OnceBox::new())
    }

    pub fn get_or_init<F>(&self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        self.0.get_or_init(|| alloc::boxed::Box::new(f()))
    }

    pub fn get_or_try_init<F>(&self, f: F) -> IceResult<&T>
    where
        F: FnOnce() -> IceResult<T>,
    {
        self.0.get_or_try_init(|| Ok(alloc::boxed::Box::new(f()?)))
    }
}

pub struct OnceCell<T>(OnceCellImp<T>);

#[allow(unused)]
impl<T> OnceCell<T> {
    pub const fn new() -> Self {
        Self(OnceCellImp::new())
    }

    pub fn get_or_init<F>(&self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        self.0.get_or_init(f)
    }

    pub fn get_or_try_init<F>(&self, f: F) -> IceResult<&T>
    where
        F: FnOnce() -> IceResult<T>,
    {
        self.0.get_or_try_init(f)
    }
}

impl<T> Default for OnceCell<T> {
    fn default() -> Self {
        Self::new()
    }
}
