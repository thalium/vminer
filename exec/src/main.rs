#![allow(clippy::fn_to_numeric_cast, clippy::unnecessary_cast, dead_code)]

mod kvm;
pub use kvm::Vm;
mod dumb_dump;
pub use dumb_dump::DumbDump;

use std::io;
#[derive(Clone, Copy, Debug)]
struct GuestPhysAddr(u64);


pub fn dump_vm(vm: &Vm) -> io::Result<DumbDump> {
    let mut mem = vec![0; 2 << 30];
    vm.read_memory(GuestPhysAddr(0), &mut mem).unwrap();

    let dump = dumb_dump::DumbDump { regs: *vm.get_regs(), sregs: *vm.get_sregs(),  mem };
    Ok(dump)
}

trait Backend {
    fn get_regs(&self) -> &kvm_common::kvm_regs;
    fn get_sregs(&self) -> &kvm_common::kvm_sregs;

    fn read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> io::Result<()>;
    fn write_memory(&mut self, addr: GuestPhysAddr, buf: &[u8]) -> io::Result<()>;
}

fn main() {
    let mut args = std::env::args();
    let pid = args.nth(1).expect("missing pid");
    let pid = pid.parse().unwrap();
    /*
    let len = args.next().expect("missing len");
    let len = len.parse().unwrap();
    let addr = args.next().expect("missing phys_addr");
    let addr = if addr.starts_with("0x") {
        &addr[2..]
    } else {
        &addr
    };
    let addr = u64::from_str_radix(addr, 16).unwrap();
    */

    
    let vm = Vm::connect(pid, 2 << 30).unwrap();
    let dump = DumbDump::read("dump").unwrap();
    //dump.write("dump").unwrap();

    assert_eq!(vm.get_regs().rip, dump.get_regs().rip);
}
