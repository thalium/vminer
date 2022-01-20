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

    pub(super) mm_struct_exe_file: u64,
    pub(super) mm_struct_pgd: u64,
    pub(super) mm_struct_mmap: u64,

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

    pub(super) vm_area_struct_vm_end: u64,
    pub(super) vm_area_struct_vm_flags: u64,
    pub(super) vm_area_struct_vm_next: u64,
    pub(super) vm_area_struct_vm_start: u64,
    pub(super) vm_area_struct_vm_file: u64,

    pub(super) file_f_path: u64,
    pub(super) path_d_entry: u64,
    pub(super) dentry_d_name: u64,
    pub(super) dentry_d_parent: u64,
    pub(super) qstr_name: u64,
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

        let dentry = syms.get_struct("dentry")?;
        let dentry_d_name = dentry.find_offset("d_name")?;
        let dentry_d_parent = dentry.find_offset("d_parent")?;

        let file = syms.get_struct("file")?;
        let file_f_path = file.find_offset("f_path")?;

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
        let mm_struct_exe_file = mm_struct.find_offset("exe_file")?;
        let mm_struct_pgd = mm_struct.find_offset("pgd")?;
        let mm_struct_mmap = mm_struct.find_offset("mmap")?;

        let path = syms.get_struct("path")?;
        let path_d_entry = path.find_offset("dentry")?;

        let qstr = syms.get_struct("qstr")?;
        let qstr_name = qstr.find_offset("name")?;

        let vm_area_struct = syms.get_struct("vm_area_struct")?;
        let vm_area_struct_vm_end = vm_area_struct.find_offset("vm_end")?;
        let vm_area_struct_vm_flags = vm_area_struct.find_offset("vm_flags")?;
        let vm_area_struct_vm_next = vm_area_struct.find_offset("vm_next")?;
        let vm_area_struct_vm_start = vm_area_struct.find_offset("vm_start")?;
        let vm_area_struct_vm_file = vm_area_struct.find_offset("vm_file")?;

        Ok(Self {
            syms,
            fast_syms: FastSymbols {
                per_cpu_start,
                current_task,

                init_task,
            },
            fast_offsets: FastOffsets {
                dentry_d_name,
                dentry_d_parent,

                file_f_path,

                mm_struct_exe_file,
                mm_struct_pgd,
                mm_struct_mmap,

                list_head_next,
                list_head_prev,

                path_d_entry,

                qstr_name,

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

                vm_area_struct_vm_end,
                vm_area_struct_vm_flags,
                vm_area_struct_vm_next,
                vm_area_struct_vm_start,
                vm_area_struct_vm_file,
            },
        })
    }
}

trait BufRead {
    fn read_one_line(&mut self, buf: &mut String) -> IceResult<usize>;
}

#[cfg(feature = "std")]
// #[cfg(not(feature = "std"))]
impl<R: std::io::BufRead> BufRead for R {
    fn read_one_line(&mut self, buf: &mut String) -> IceResult<usize> {
        Ok(self.read_line(buf)?)
    }
}

#[cfg(not(feature = "std"))]
impl BufRead for &[u8] {
    fn read_one_line(&mut self, buf: &mut String) -> IceResult<usize> {
        let line = match memchr::memchr(b'\n', self) {
            Some(i) => &self[..i],
            None => self,
        };

        buf.push_str(core::str::from_utf8(line).map_err(ibc::IceError::new)?);
        Ok(line.len())
    }
}

#[cfg(feature = "std")]
pub fn parse_symbol_file<R: std::io::BufRead>(
    r: R,
    syms: &mut ice::SymbolsIndexer,
) -> IceResult<()> {
    parse_symbol_file_inner(r, syms)
}

pub fn parse_symbol_file_from_bytes(bytes: &[u8], syms: &mut ice::SymbolsIndexer) -> IceResult<()> {
    parse_symbol_file_inner(bytes, syms)
}

#[cfg(feature = "std")]
fn parse_symbol_file_inner<R: BufRead>(mut r: R, syms: &mut ice::SymbolsIndexer) -> IceResult<()> {
    let mut line = String::with_capacity(200);

    loop {
        if r.read_one_line(&mut line)? == 0 {
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
