pub const INSTRUCTIONS: [u8; 8] = [
    0x00, 0x01, 0x3f, 0xd6, // blr x8
    0x00, 0x00, 0x20, 0xd4, // brk #0
];

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct Registers(libc::user_regs_struct);

impl Registers {
    pub fn instruction_pointer(&self) -> u64 {
        self.0.pc
    }

    pub fn move_stack(&mut self, amount: u64) {
        self.0.sp -= amount;
    }

    pub fn prepare_funcall0(&mut self, ip: u64, addr: u64) {
        self.0.pc = ip;
        self.0.regs[8] = addr;
    }

    pub fn prepare_funcall2(&mut self, ip: u64, addr: u64, a: u64, b: u64) {
        self.0.pc = ip;
        self.0.regs[8] = addr;
        self.0.regs[0] = a;
        self.0.regs[1] = b;
    }

    pub fn prepare_funcall6(
        &mut self,
        ip: u64,
        addr: u64,
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
    ) {
        self.0.pc = ip;
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
