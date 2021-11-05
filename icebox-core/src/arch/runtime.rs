use crate::arch;

#[derive(Debug, Clone, Copy)]
pub enum Architecture {
    X86_64,
    Aarch64,
}

pub enum Vcpu {
    X86_64(arch::x86_64::Vcpu),
    Aarch64(arch::aarch64::Vcpu),
}

impl arch::Vcpu for Vcpu {
    type Arch = Architecture;

    fn get_regs(&self) -> Registers {
        match self {
            Vcpu::X86_64(vcpu) => Registers::X86_64(vcpu.get_regs()),
            Vcpu::Aarch64(vcpu) => Registers::Aarch64(vcpu.get_regs()),
        }
    }
}

#[derive(Clone, Copy)]
pub enum Registers {
    X86_64(arch::x86_64::Registers),
    Aarch64(arch::aarch64::Registers),
}

impl arch::Architecture for Architecture {
    type Registers = Registers;
    type Vcpu = Vcpu;

    #[inline]
    fn runtime_arch(&self) -> Architecture {
        *self
    }
}
