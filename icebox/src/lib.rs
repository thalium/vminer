#![cfg_attr(not(feature = "std"), no_std)]

pub use ibc::*;

pub mod backend {
    pub use icebox_backend_dumb_dump::DumbDump;
    pub use icebox_backend_kvm::Kvm;
}

pub mod os {
    pub use icebox_os_linux::Linux;
}
