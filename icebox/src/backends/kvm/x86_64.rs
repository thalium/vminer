pub const INSTRUCTIONS: [u8; 3] = [
    0xff, 0xd0, // call rax
    0xcc, // trap
];

#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct Registers(libc::user_regs_struct);

impl Registers {
    pub fn instruction_pointer(&self) -> u64 {
        self.0.rip
    }

    pub fn move_stack(&mut self, amount: u64) {
        self.0.rsp -= amount;
    }

    pub fn prepare_funcall0(&mut self, ip: u64, addr: u64) {
        self.0.rip = ip;
        self.0.rax = addr;
    }

    pub fn prepare_funcall2(&mut self, ip: u64, addr: u64, a: u64, b: u64) {
        self.0.rip = ip;
        self.0.rax = addr;
        self.0.rdi = a;
        self.0.rsi = b;
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
        self.0.rip = ip;
        self.0.rax = addr;
        self.0.rdi = a;
        self.0.rsi = b;
        self.0.rdx = c;
        self.0.rcx = d;
        self.0.r8 = e;
        self.0.r9 = f;
    }

    pub fn return_value(&self) -> u64 {
        self.0.rax
    }
}
