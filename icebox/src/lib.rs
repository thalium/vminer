#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use ibc as core;

pub mod backends;
pub mod os;
