#![cfg_attr(not(feature = "std"), no_std)]

pub use ibc::*;

pub mod backend {
    #[cfg(feature = "icebox_backend_dumb_dump")]
    pub use icebox_backend_dumb_dump::DumbDump;
    #[cfg(feature = "icebox_backend_kvm")]
    pub use icebox_backend_kvm::Kvm;
}

pub mod os {
    #[cfg(feature = "icebox_os_linux")]
    pub use icebox_os_linux::Linux;
}
