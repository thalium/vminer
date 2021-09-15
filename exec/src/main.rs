#![allow(clippy::fn_to_numeric_cast, clippy::unnecessary_cast, dead_code)]

mod addr;
use addr::{GuestPhysAddr, GuestVirtAddr, MmPte};

mod os;
use os::Os;

mod kvm;
use bytemuck::Zeroable;
pub use kvm::Vm;
mod dumb_dump;
pub use dumb_dump::DumbDump;

use anyhow::ensure;
use std::io;

pub fn dump_vm(vm: &Vm) -> io::Result<DumbDump> {
    let mut mem = vec![0; 2 << 30];
    vm.read_memory(GuestPhysAddr(0), &mut mem).unwrap();

    let dump = dumb_dump::DumbDump {
        regs: *vm.get_regs(),
        sregs: *vm.get_sregs(),
        mem: dumb_dump::Mem::Bytes(mem),
    };
    Ok(dump)
}

pub trait Backend {
    fn get_regs(&self) -> &kvm_common::kvm_regs;
    fn get_sregs(&self) -> &kvm_common::kvm_sregs;

    fn read_memory(&self, addr: GuestPhysAddr, buf: &mut [u8]) -> io::Result<()>;
    fn write_memory(&mut self, addr: GuestPhysAddr, buf: &[u8]) -> io::Result<()>;
}

const fn mask(size: u32) -> u64 {
    !(!0 << size)
}

fn virtual_to_physical<B>(backend: &B, addr: GuestVirtAddr) -> anyhow::Result<GuestPhysAddr>
where
    B: Backend,
{
    let mut mmu_entry = MmPte::zeroed();

    let cr3 = backend.get_sregs().cr3;

    let pml4e_addr = GuestPhysAddr(cr3 & (mask(40) << 12)) + 8 * addr.pml4e();
    backend.read_memory(pml4e_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
    ensure!(mmu_entry.is_valid(), "invalid PLM4E: 0x{:016x}", mmu_entry);
    ensure!(!mmu_entry.is_large(), "large PLM4E");

    let pdpe_addr = mmu_entry.page_frame() + 8 * addr.pdpe();
    backend.read_memory(pdpe_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
    ensure!(mmu_entry.is_valid(), "invalid PDPE: 0x{:016x}", mmu_entry);

    if mmu_entry.is_large() {
        let phys_addr = mmu_entry.huge_page_frame() + addr.huge_page_offset();
        return Ok(phys_addr);
    }

    let pde_addr = mmu_entry.page_frame() + 8 * addr.pde();
    backend.read_memory(pde_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
    ensure!(mmu_entry.is_valid(), "invalid PDE: 0x{:016x}", mmu_entry);

    if mmu_entry.is_large() {
        let phys_addr = mmu_entry.large_page_frame() + addr.large_page_offset();
        return Ok(phys_addr);
    }

    let pte_addr = mmu_entry.page_frame() + 8 * addr.pte();
    backend.read_memory(pte_addr, bytemuck::bytes_of_mut(&mut mmu_entry))?;
    ensure!(mmu_entry.is_valid(), "invalid PTE: 0x{:016x}", mmu_entry);
    ensure!(!mmu_entry.is_large(), "large PTE");

    let phys_addr = mmu_entry.page_frame() + addr.page_offset();
    Ok(phys_addr)
}

fn main() {
    let mut args = std::env::args();
    let pid = args.nth(1).expect("missing pid");
    let pid: libc::pid_t = pid.parse().unwrap();
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
    //let vm = DumbDump::read("linux.dump").unwrap();
    //dump_vm(&vm).unwrap().write("grub.dump").unwrap();

    //let addr = virtual_to_physical(&vm, GuestVirtAddr(vm.get_regs().rip)).unwrap();
    let _ = dbg!(os::Linux::quick_check(&vm));
    //println!("0x{:x}", addr);
}
