use alloc::string::String;

use crate::core::{self as ice, IceResult};

pub(crate) struct FastSymbols {
    pub(crate) per_cpu_start: ice::VirtualAddress,
    pub(crate) current_task: ice::VirtualAddress,

    pub(super) init_task: ice::VirtualAddress,
}

pub(super) struct FastOffsets {
    pub(super) list_head_next: u64,
    #[allow(unused)]
    pub(super) list_head_prev: u64,

    pub(super) mm_struct_pgd: u64,

    pub(super) task_struct_active_mm: u64,
    pub(super) task_struct_children: u64,
    pub(super) task_struct_comm: u64,
    pub(super) task_struct_group_leader: u64,
    pub(super) task_struct_mm: u64,
    pub(super) task_struct_real_parent: u64,
    pub(super) task_struct_pid: u64,
    pub(super) task_struct_sibling: u64,
    pub(super) task_struct_tasks: u64,
    pub(super) task_struct_tgid: u64,
    pub(super) task_struct_thread_group: u64,
}

pub struct Profile {
    pub(crate) syms: ice::SymbolsIndexer,
    pub(crate) fast_syms: FastSymbols,
    pub(super) fast_offsets: FastOffsets,
}

impl Profile {
    pub fn new(syms: ice::SymbolsIndexer) -> IceResult<Self> {
        let per_cpu_start = syms.get_addr("__per_cpu_start")?;
        let current_task = syms.get_addr("current_task")?;
        let init_task = syms.get_addr("init_task")?;

        let list_head = syms.get_struct("list_head")?;
        let list_head_next = list_head.find_offset("next")?;
        let list_head_prev = list_head.find_offset("prev")?;

        let task_struct = syms.get_struct("task_struct")?;
        let task_struct_active_mm = task_struct.find_offset("active_mm")?;
        let task_struct_children = task_struct.find_offset("children")?;
        let task_struct_comm = task_struct.find_offset("comm")?;
        let task_struct_group_leader = task_struct.find_offset("group_leader")?;
        let task_struct_mm = task_struct.find_offset("mm")?;
        let task_struct_parent = task_struct.find_offset("real_parent")?;
        let task_struct_pid = task_struct.find_offset("pid")?;
        let task_struct_sibling = task_struct.find_offset("sibling")?;
        let task_struct_tasks = task_struct.find_offset("tasks")?;
        let task_struct_tgid = task_struct.find_offset("tgid")?;
        let task_struct_thread_group = task_struct.find_offset("thread_group")?;

        let mm_struct = syms.get_struct("mm_struct")?;
        let mm_struct_pgd = mm_struct.find_offset("pgd")?;

        Ok(Self {
            syms,
            fast_syms: FastSymbols {
                per_cpu_start,
                current_task,

                init_task,
            },
            fast_offsets: FastOffsets {
                mm_struct_pgd,

                list_head_next,
                list_head_prev,

                task_struct_active_mm,
                task_struct_children,
                task_struct_comm,
                task_struct_group_leader,
                task_struct_mm,
                task_struct_real_parent: task_struct_parent,
                task_struct_pid,
                task_struct_tasks,
                task_struct_tgid,
                task_struct_sibling,
                task_struct_thread_group,
            },
        })
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
            syms.insert_addr(name, ice::VirtualAddress(addr));
        }

        line.clear();
    }

    Ok(())
}
