use crate::mask_range;

use super::mask;
use core::ops::Sub;
use core::ops::SubAssign;
use core::{
    fmt,
    ops::{Add, AddAssign},
};

#[derive(
    Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, bytemuck::Pod, bytemuck::Zeroable,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct PhysicalAddress(pub u64);

impl fmt::LowerHex for PhysicalAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::UpperHex for PhysicalAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Add<u64> for PhysicalAddress {
    type Output = PhysicalAddress;

    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl AddAssign<u64> for PhysicalAddress {
    #[inline]
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Add<i64> for PhysicalAddress {
    type Output = Self;

    #[inline]
    fn add(self, rhs: i64) -> Self {
        let (res, o) = self.0.overflowing_add(rhs as u64);

        if cfg!(debug_assertions) && (o ^ (rhs < 0)) {
            panic!("attempt to add with overflow");
        }

        Self(res)
    }
}

impl AddAssign<i64> for PhysicalAddress {
    #[inline]
    fn add_assign(&mut self, rhs: i64) {
        *self = *self + rhs;
    }
}

impl Sub<PhysicalAddress> for PhysicalAddress {
    type Output = i64;

    #[inline]
    fn sub(self, rhs: PhysicalAddress) -> Self::Output {
        self.0.wrapping_sub(rhs.0) as i64
    }
}

impl Sub<u64> for PhysicalAddress {
    type Output = PhysicalAddress;

    #[inline]
    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

#[derive(
    Debug,
    Default,
    Clone,
    Copy,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    bytemuck::Pod,
    bytemuck::Zeroable,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[repr(transparent)]
pub struct VirtualAddress(pub u64);

impl VirtualAddress {
    #[inline]
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    #[inline]
    pub const fn is_kernel(self) -> bool {
        (self.0 as i64) < 0
    }

    #[inline]
    pub const fn pml4e(self) -> u64 {
        (self.0 >> 39) & mask(9)
    }

    #[inline]
    pub const fn pdpe(self) -> u64 {
        (self.0 >> 30) & mask(9)
    }

    #[inline]
    pub const fn pde(self) -> u64 {
        (self.0 >> 21) & mask(9)
    }

    #[inline]
    pub const fn pte(self) -> u64 {
        (self.0 >> 12) & mask(9)
    }

    /// Offset for normal pages (4Ko)
    #[inline]
    pub const fn page_offset(self) -> u64 {
        self.0 & mask(12)
    }

    /// Offset for large pages (2Mo)
    #[inline]
    pub const fn large_page_offset(self) -> u64 {
        self.0 & mask(21)
    }

    /// Offset for huge pages (1Go)
    #[inline]
    pub const fn huge_page_offset(self) -> u64 {
        self.0 & mask(30)
    }
}

impl Add<u64> for VirtualAddress {
    type Output = VirtualAddress;

    #[inline]
    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl Add<i32> for VirtualAddress {
    type Output = VirtualAddress;

    #[inline]
    fn add(self, rhs: i32) -> Self::Output {
        self + rhs as i64
    }
}

impl Add<u32> for VirtualAddress {
    type Output = VirtualAddress;

    #[inline]
    fn add(self, rhs: u32) -> Self::Output {
        Self(self.0 + rhs as u64)
    }
}

impl AddAssign<u64> for VirtualAddress {
    #[inline]
    fn add_assign(&mut self, rhs: u64) {
        self.0 += rhs;
    }
}

impl Add<i64> for VirtualAddress {
    type Output = VirtualAddress;

    #[inline]
    fn add(self, rhs: i64) -> Self::Output {
        let (res, o) = self.0.overflowing_add(rhs as u64);

        if cfg!(debug_assertions) && (o ^ (rhs < 0)) {
            panic!("attempt to add with overflow");
        }

        Self(res)
    }
}

impl Sub<VirtualAddress> for VirtualAddress {
    type Output = i64;

    #[inline]
    fn sub(self, rhs: VirtualAddress) -> i64 {
        self.0.wrapping_sub(rhs.0) as i64
    }
}

impl Sub<u64> for VirtualAddress {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: u64) -> Self {
        Self(self.0 - rhs)
    }
}

impl SubAssign<u64> for VirtualAddress {
    #[inline]
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}

impl fmt::LowerHex for VirtualAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::UpperHex for VirtualAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Clone, Copy, Debug, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(transparent)]
pub struct MmuEntry(pub u64);

impl MmuEntry {
    #[inline]
    pub const fn take_bits(self, from: u32, to: u32) -> PhysicalAddress {
        PhysicalAddress(self.0 & mask_range(from, to))
    }
}

impl core::ops::Sub<u64> for MmuEntry {
    type Output = Self;

    #[inline]
    fn sub(self, rhs: u64) -> Self {
        Self(self.0 - rhs)
    }
}

impl core::ops::SubAssign<u64> for MmuEntry {
    #[inline]
    fn sub_assign(&mut self, rhs: u64) {
        self.0 -= rhs;
    }
}
