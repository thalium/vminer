pub use ibc::arch::aarch64::Vcpu;
pub use ibc::arch::Aarch64 as Arch;

pub const INSTRUCTIONS: [u8; 8] = [
    0x00, 0x01, 0x3f, 0xd6, // blr x8
    0x00, 0x00, 0x20, 0xd4, // brk #0
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
        self.0.regs[8] = addr;
    }

    pub fn prepare_funcall1(&mut self, addr: u64, a: u64) {
        self.0.regs[8] = addr;
        self.0.regs[0] = a;
    }

    pub fn prepare_funcall2(&mut self, addr: u64, a: u64, b: u64) {
        self.0.regs[8] = addr;
        self.0.regs[0] = a;
        self.0.regs[1] = b;
    }

    pub fn prepare_funcall6(&mut self, addr: u64, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) {
        self.0.regs[8] = addr;
        self.0.regs[0] = a;
        self.0.regs[1] = b;
        self.0.regs[2] = c;
        self.0.regs[3] = d;
        self.0.regs[4] = e;
        self.0.regs[5] = f;
    }

    pub fn return_value(&self) -> u64 {
        self.0.regs[0]
    }
}
