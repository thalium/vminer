use icebox::backends::kvm_dump;
use icebox::core as ice;
use icebox::core::Os;
use icebox::os;

fn main() {
    env_logger::init();

    // let mut args = std::env::args();
    // let pid = args.nth(1).expect("missing pid");
    // let pid: i32 = pid.parse().unwrap();
    // let vm = icebox::backends::kvm::Kvm::connect(pid, 2 << 30).unwrap();

    let vm = kvm_dump::DumbDump::read("linux.dump").unwrap();

    //let addr = virtual_to_physical(&vm, GuestVirtAddr(vm.get_regs().rip)).unwrap();
    let _ = dbg!(os::linux::Linux::quick_check(&vm));
    //println!("0x{:x}", addr);

    let mut syms = ice::SymbolsIndexer::new();
    let kallsyms = std::io::BufReader::new(std::fs::File::open("../kallsyms").unwrap());
    os::linux::profile::parse_kallsyms(kallsyms, &mut syms).unwrap();

    let mut profile = os::linux::Profile::new(syms);
    profile.read_object_file("../elf");

    let linux = os::linux::Linux::create(profile);
    let kaslr = dbg!(linux.get_aslr(&vm).unwrap());
    linux.read_all_tasks(&vm, kaslr).unwrap();
    //linux.read_current_task(&vm).unwrap();
}
