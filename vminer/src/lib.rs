#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate vminer_core as vmc;

pub use vminer_core as core;

pub mod backends;
pub mod os;
