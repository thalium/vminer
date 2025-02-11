pub use vmc::arch::riscv64 as Arch;
pub use vmc::arch::riscv64::Vcpu;

pub const INSTRUCTIONS: [u8; 8] = [
    0x67, 0x80, 0x02, 0x00, // jr t0
    0x73, 0x00, 0x10, 0x00, // ebreak
];

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Registers(libc::user_regs_struct);

unsafe impl bytemuck::Zeroable for Registers {}
unsafe impl bytemuck::Pod for Registers {}

impl Registers {
    pub fn instruction_pointer(&self) -> u64 {
        self.0.pc
    }

    pub fn set_instruction_pointer(&mut self, addr: u64) {
        self.0.pc = addr;
    }

    pub fn move_stack(&mut self) {
        self.0.sp -= 0x100;
        self.0.sp &= !0xf;
    }

    pub fn prepare_funcall0(&mut self, addr: u64) {
        self.0.t0 = addr;
    }

    pub fn prepare_funcall1(&mut self, addr: u64, a: u64) {
        self.0.t0 = addr;
        self.0.a0 = a;
    }

    pub fn prepare_funcall2(&mut self, addr: u64, a: u64, b: u64) {
        self.0.t0 = addr;
        self.0.a0 = a;
        self.0.a1 = b;
    }

    pub fn prepare_funcall6(&mut self, addr: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) {
        self.0.t0 = addr;
        self.0.a0 = a;
        self.0.a1 = b;
        self.0.a2 = c;
        self.0.a3 = d;
        self.0.a4 = e;
        self.0.a5 = f;
    }

    pub fn return_value(&self) -> u64 {
        self.0.a0
    }
}
