use icebox::backends::kvm_dump;
use icebox::core::{self as ice, Backend, Os};
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

    //let addr = virtual_to_physical(GuestVirtAddr(vm.get_regs().rip)).unwrap();
    //let _ = dbg!(os::Linux::quick_check());
    //println!("0x{:x}", addr);

    let mut syms = ice::SymbolsIndexer::new();
    let kallsyms = std::io::BufReader::new(std::fs::File::open("../kallsyms").unwrap());
    os::linux::profile::parse_kallsyms(kallsyms, &mut syms).unwrap();
    syms.read_object_file("../elf").unwrap();
    let profile = os::linux::Profile::new(syms).unwrap();

    let linux = os::Linux::create(vm, profile).unwrap();

    linux
        .for_each_process(&mut |proc| {
            println!(
                "{}: {}",
                linux.process_pid(proc).unwrap(),
                linux.process_name(proc).unwrap(),
            );
            Ok(())
        })
        .unwrap();

    /*
    for cpuid in 0..2 {
        let proc = linux.current_process(cpuid).unwrap();
        let pid = proc.pid().unwrap();
        let name = proc.comm().unwrap();
        let cr3 = vm.vcpus()[cpuid].special_registers.cr3;
        let pgd = proc.pgd().unwrap();
        println!("{}: {} ({:016x} -> {:016x})", pid, name, cr3, pgd);
    }
    */

    // linux.read_current_task(0).unwrap();
    // linux.read_current_task(1).unwrap();
}
