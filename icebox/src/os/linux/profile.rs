extern crate alloc;

use alloc::string::String;

use crate::core as ice;

pub(crate) struct FastSymbols {
    pub(crate) per_cpu_start: ice::GuestVirtAddr,
    pub(crate) current_task: ice::GuestVirtAddr,
}

pub(super) struct FastOffsets {
    pub(super) mm_struct_pgd: u64,
    pub(super) task_struct_active_mm: u64,
    pub(super) task_struct_comm: u64,
    pub(super) task_struct_mm: u64,
    pub(super) task_struct_pid: u64,
}

pub struct Profile {
    pub(crate) syms: ice::SymbolsIndexer,
    pub(crate) fast_syms: FastSymbols,
    pub(super) fast_offsets: FastOffsets,
}

impl Profile {
    pub fn new(syms: ice::SymbolsIndexer) -> Profile {
        let per_cpu_start = syms.get_addr("__per_cpu_start").unwrap();
        let current_task = syms.get_addr("current_task").unwrap();

        let task_struct = syms.get_struct("task_struct").unwrap();
        let task_struct_pid = task_struct.find_offset("pid").unwrap();
        let task_struct_comm = task_struct.find_offset("comm").unwrap();
        let task_struct_mm = task_struct.find_offset("mm").unwrap();
        let task_struct_active_mm = task_struct.find_offset("active_mm").unwrap();

        let mm_struct = syms.get_struct("mm_struct").unwrap();
        //dbg!(mm_struct);
        let mm_struct_pgd = mm_struct.find_offset("pgd").unwrap();

        Profile {
            syms,
            fast_syms: FastSymbols {
                per_cpu_start,
                current_task,
            },
            fast_offsets: FastOffsets {
                mm_struct_pgd,
                task_struct_active_mm,
                task_struct_comm,
                task_struct_mm,
                task_struct_pid,
            },
        }
    }
}

#[derive(Debug)]
pub struct Sym {
    addr: u64,
    name: String,
    kind: u8,
}

#[cfg(feature = "std")]
pub fn parse_kallsyms<R: std::io::BufRead>(
    mut r: R,
    syms: &mut ice::SymbolsIndexer,
) -> std::io::Result<()> {
    let mut line = String::with_capacity(200);

    loop {
        if r.read_line(&mut line)? == 0 {
            break;
        }

        let sym = (|| {
            let (start, rest) = line.split_at(19);
            let addr = u64::from_str_radix(&start[0..16], 16).ok()?;

            match start.as_bytes()[17] {
                b'T' | b't' | b'A' | b'D' => (),
                _ => return None,
            }

            let name = match rest.find(&['\t', '\n'][..]) {
                Some(i) => &rest[..i],
                None => rest,
            }
            .to_owned();

            Some((name, addr))
        })();

        if let Some((name, addr)) = sym {
            syms.insert_addr(name, ice::GuestVirtAddr(addr));
        }

        line.clear();
    }

    Ok(())
}
