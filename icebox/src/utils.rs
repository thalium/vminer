use ibc::IceResult;

#[cfg(feature = "std")]
type OnceCellImp<T> = once_cell::sync::OnceCell<T>;

#[cfg(all(not(feature = "std"), feature = "no_std_sync"))]
struct OnceCellImp<T>(spin::Once<T>);

#[cfg(all(not(feature = "std"), feature = "no_std_sync"))]
impl<T> OnceCellImp<T> {
    pub const fn new() -> Self {
        Self(spin::Once::new())
    }

    pub fn get_or_init<F>(&self, f: F) -> &T
    where
        F: FnOnce() -> T,
    {
        self.0.call_once(f)
    }

    pub fn get_or_try_init<F>(&self, f: F) -> IceResult<&T>
    where
        F: FnOnce() -> IceResult<T>,
    {
        // TODO: fix this when https://github.com/mvdnes/spin-rs/pull/116 is merged
        Ok(self.0.call_once(|| f().unwrap()))
    }
}

#[cfg(all(not(feature = "std"), not(feature = "no_std_sync")))]
type OnceCellImp<T> = once_cell::unsync::OnceCell<T>;

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
