use icebox::backends::kvm_dump;
use icebox::core::{self as ice, Backend};
use icebox::os;

fn main() {
    env_logger::init();

    // let mut args = std::env::args();
    // let pid = args.nth(1).expect("missing pid");
    // let pid: i32 = pid.parse().unwrap();
    // let vm = icebox::backends::kvm::Kvm::connect(pid, 2 << 30).unwrap();

    let vm = kvm_dump::DumbDump::read("kvm.dump").unwrap();

    for vcpu in vm.vcpus() {
        println!("{:016x}", vcpu.special_registers.gs.base);
        println!("{:016x}", vcpu.gs_kernel_base);
    }

    //let addr = virtual_to_physical(&vm, GuestVirtAddr(vm.get_regs().rip)).unwrap();
    //let _ = dbg!(os::Linux::quick_check(&vm));
    //println!("0x{:x}", addr);

    let mut syms = ice::SymbolsIndexer::new();
    let kallsyms = std::io::BufReader::new(std::fs::File::open("../kallsyms").unwrap());
    os::linux::profile::parse_kallsyms(kallsyms, &mut syms).unwrap();
    syms.read_object_file("../elf");
    let profile = os::linux::Profile::new(syms);

    let linux = os::Linux::create(profile);
    // let kaslr = dbg!(linux.get_aslr(&vm).unwrap());
    // linux.read_all_tasks(&vm, kaslr).unwrap();

    for cpuid in 0..2 {
        let proc = linux.current_process(&vm, cpuid).unwrap();
        let pid = linux.read_process_id(&vm, proc).unwrap();
        let name = linux.read_process_comm_to_string(&vm, proc).unwrap();
        let cr3 = vm.vcpus()[cpuid].special_registers.cr3;
        let pgd = linux.read_process_pgd(&vm, proc).unwrap();
        println!("{}: {} ({:016x} -> {:016x})", pid, name, cr3, pgd);
    }

    // linux.read_current_task(&vm, 0).unwrap();
    // linux.read_current_task(&vm, 1).unwrap();
}
