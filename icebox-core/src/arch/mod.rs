pub mod aarch64;
pub use aarch64::Aarch64;

pub mod runtime;
pub use runtime::Architecture as RuntimeArchitecture;

pub mod x86_64;
pub use x86_64::X86_64;

pub trait Architecture {
    type Vcpu: Vcpu<Arch = Self> + 'static;
    type Registers;

    fn runtime_arch(&self) -> RuntimeArchitecture;
}
pub trait Vcpu {
    type Arch: Architecture;

    fn get_regs(&self) -> <Self::Arch as Architecture>::Registers;
}
