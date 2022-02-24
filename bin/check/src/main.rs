use std::collections::{hash_map, HashMap};

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

    let profile = os::linux::Profile::read_from_dir(format!("data/linux-5.10-{arch}")).unwrap();

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

    let mut libs = HashMap::new();
    linux
        .process_for_each_vma(proc, &mut |vma| {
            if let Some(path) = linux.vma_file(vma)? {
                let file = linux.path_to_string(path)?;
                if file.rsplit_once('/').is_some() {
                    match libs.entry(path) {
                        hash_map::Entry::Occupied(_) => (),
                        hash_map::Entry::Vacant(entry) => {
                            let vma_start = linux.vma_start(vma)?;
                            entry.insert(vma_start);
                        }
                    }
                }
            }
            Ok(())
        })
        .unwrap();

    linux
        .process_callstack(proc, &mut |frame| {
            let file = linux.path_to_string(frame.file.unwrap())?;
            let addr = match frame.range {
                Some((start, _)) => {
                    let diff = frame.instruction_pointer - start;
                    let symbol = (|| {
                        let (_, lib) = file.rsplit_once('/')?;
                        let lib_start = *libs.get(&frame.file?)?;
                        let addr = ice::VirtualAddress((start - lib_start) as u64);
                        linux.find_symbol(lib, addr)
                    })();
                    match symbol {
                        Some(sym) => format!("<{sym}+0x{diff:x}>"),
                        None => format!("<0x{start:x}+0x{diff:x}>"),
                    }
                }
                None => String::from("<unknown>"),
            };
            println!(
                "Frame: 0x{:x} | 0x{:x} ({addr} in {file})",
                frame.stack_pointer, frame.instruction_pointer
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
