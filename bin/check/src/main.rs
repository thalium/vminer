use icebox::backends::kvm_dump;
use icebox::core::{self as ice, Backend, Os};
use icebox::os;

fn main() {
    env_logger::init();

    let arch = "aarch64";

    // let mut args = std::env::args();
    // let pid = args.nth(1).expect("missing pid");
    // let pid: i32 = pid.parse().unwrap();
    // let vm = icebox::backends::kvm::Kvm::connect(pid).unwrap();

    let vm = kvm_dump::DumbDump::read(format!("data/linux-5.10-{arch}/dump")).unwrap();

    //let addr = virtual_to_physical(GuestVirtAddr(vm.get_regs().rip)).unwrap();
    //let _ = dbg!(os::Linux::quick_check());
    //println!("0x{:x}", addr);

    let mut syms = ice::SymbolsIndexer::new();
    let kallsyms = std::io::BufReader::new(
        std::fs::File::open(format!("data/linux-5.10-{arch}/kallsyms")).unwrap(),
    );
    os::linux::profile::parse_symbol_file(kallsyms, &mut syms).unwrap();
    syms.read_object_file(format!("data/linux-5.10-{arch}/elf"))
        .unwrap();
    let profile = os::linux::Profile::new(syms).unwrap();

    let linux = os::Linux::create(vm, profile).unwrap();

    let proc = 'ok: loop {
        for i in 0..2 {
            let proc = linux.current_process(i).unwrap();
            if !linux.process_is_kernel(proc).unwrap() {
                break 'ok proc;
            }
        }

        panic!("No proc found");
    };

    linux
        .process_callstack(proc, &mut |frame| {
            let file = linux.path_to_string(frame.file.unwrap())?;
            let range = match &frame.range {
                Some((start, size)) => format!("(0x{start:x} [+0x{size:x}])"),
                None => format!("<unknown>"),
            };
            println!(
                "Frame: 0x{:x} [0x{:x}] (in {file}) {range}",
                frame.instruction_pointer, frame.stack_pointer
            );
            Ok(())
        })
        .unwrap();

    /*
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
    */

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
