#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    ),
    feature = "kvm"
))]
pub mod kvm;

#[cfg(feature = "dump")]
pub mod kvm_dump;
