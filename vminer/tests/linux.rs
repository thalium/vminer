use std::{fmt, ops::ControlFlow};

use once_cell::sync::Lazy;
use vmc::{arch::HasVcpus, Os, VirtualAddress, VmResult};
use vminer::{backends::kvm_dump::DumbDump, os::Linux};

#[derive(Clone, Copy)]
enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    fn linux(self) -> &'static Linux<impl vmc::Backend> {
        match self {
            Arch::X86_64 => &LINUX_X86_64,
            Arch::Aarch64 => &LINUX_AARCH64,
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => f.write_str("x86_64"),
            Self::Aarch64 => f.write_str("aarch64"),
        }
    }
}

fn read_linux(arch: Arch) -> VmResult<Linux<DumbDump<vmc::mem::File>>> {
    let backend = DumbDump::read(format!("../data/linux-5.10-{arch}-dump"))?;
    let mut profile = vmc::SymbolsIndexer::new();
    profile.load_dir(format!("../data/linux-5.10-{arch}"))?;
    Linux::create(backend, profile)
}

static LINUX_X86_64: Lazy<Linux<DumbDump<vmc::mem::File>>> =
    Lazy::new(|| read_linux(Arch::X86_64).expect("Failed to initialize OS"));
static LINUX_AARCH64: Lazy<Linux<DumbDump<vmc::mem::File>>> =
    Lazy::new(|| read_linux(Arch::Aarch64).expect("Failed to initialize OS"));

fn assert_match_expected<T>(arch: Arch, name: &str, result: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + Eq + std::fmt::Debug,
{
    let result_path = format!("tests/results/linux-{arch}-{name}.json");

    if std::env::var_os("VMINER_BLESS_TESTS").is_some() {
        let mut file = std::io::BufWriter::new(std::fs::File::create(&result_path).unwrap());
        serde_json::to_writer_pretty(&mut file, &result).unwrap();
    }

    let mut file = std::io::BufReader::new(std::fs::File::open(result_path).unwrap());
    let expected: T = serde_json::from_reader(&mut file).unwrap();

    assert_eq!(result, &expected);
}

fn proc_tree(arch: Arch) {
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Thread {
        tid: u64,
        name: Option<String>,
    }

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Proc {
        pid: u64,
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        children: Vec<Proc>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        threads: Vec<Thread>,
    }

    fn collect_proc_tree(os: &impl Os, proc: vmc::Process) -> VmResult<Proc> {
        let pid = os.process_id(proc)?;
        let name = os.process_name(proc)?;

        let mut children = Vec::new();
        os.process_for_each_child(proc, &mut |child| {
            assert_eq!(os.process_parent(child).unwrap(), proc);

            let proc = collect_proc_tree(os, child)?;
            children.push(proc);
            Ok(ControlFlow::Continue(()))
        })?;

        let mut threads = Vec::new();
        os.process_for_each_thread(proc, &mut |thread| {
            assert_eq!(os.thread_process(thread).unwrap(), proc);

            let tid = os.thread_id(thread)?;
            let name = os.thread_name(thread)?;
            threads.push(Thread { tid, name });
            Ok(ControlFlow::Continue(()))
        })?;

        Ok(Proc {
            pid,
            name,
            children,
            threads,
        })
    }

    let linux = arch.linux();
    let init = linux.init_process().unwrap();
    let procs = collect_proc_tree(linux, init).unwrap();

    assert_match_expected(arch, "proc-tree", &procs);
}

#[test]
fn proc_tree_x86_64() {
    proc_tree(Arch::X86_64)
}

#[test]
fn proc_tree_aarch64() {
    proc_tree(Arch::Aarch64)
}

#[test]
fn current_process_x86_64() {
    let linux = Arch::X86_64.linux();

    for (vcpu, pid) in linux.iter_vcpus().zip([0, 651]) {
        let proc = linux.current_process(vcpu).unwrap();
        assert_eq!(linux.process_id(proc).unwrap(), pid);
    }
}

#[test]
fn current_process_aarch64() {
    let linux = Arch::Aarch64.linux();

    for (vcpu, pid) in linux.iter_vcpus().zip([420, 0]) {
        let proc = linux.current_process(vcpu).unwrap();
        assert_eq!(linux.process_id(proc).unwrap(), pid);
    }
}

fn vmas(arch: Arch) {
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Vma {
        start: VirtualAddress,
        end: VirtualAddress,
        #[serde(skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    }

    let linux = arch.linux();

    let proc = linux.find_process_by_name("callstack").unwrap().unwrap();

    let mut vmas = Vec::new();
    linux
        .process_for_each_vma(proc, &mut |vma| {
            let start = linux.vma_start(vma)?;
            let end = linux.vma_end(vma)?;
            let path = linux.vma_path(vma)?;

            vmas.push(Vma { start, end, path });
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();

    assert_match_expected(arch, "vmas", &vmas);
}

#[test]
fn vmas_x86_64() {
    vmas(Arch::X86_64)
}

#[test]
fn vmas_aarch64() {
    vmas(Arch::Aarch64)
}

fn callstack(arch: Arch) {
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct StackFrame {
        start: Option<VirtualAddress>,
        size: Option<u64>,
        stack_pointer: VirtualAddress,
        instruction_pointer: VirtualAddress,
        #[serde(skip_serializing_if = "Option::is_none")]
        symbol: Option<String>,
    }

    let linux = arch.linux();
    let proc = linux
        .iter_vcpus()
        .find_map(|vcpu| {
            let proc = linux.current_process(vcpu).unwrap();
            (!linux.process_is_kernel(proc).unwrap()).then(|| proc)
        })
        .unwrap();

    let mut frames = Vec::new();
    linux
        .process_callstack(proc, &mut |frame| {
            let &vmc::StackFrame {
                start,
                size,
                stack_pointer,
                instruction_pointer,
                module,
            } = frame;

            let symbol = match (module, start) {
                (None, _) => None,
                (Some(module), Some(start)) => linux
                    .module_resolve_symbol_exact(start, proc, module)?
                    .map(|sym| vmc::symbols::demangle(sym).into_owned()),
                (Some(module), None) => linux
                    .module_resolve_symbol(instruction_pointer, proc, module)?
                    .map(|(sym, _)| vmc::symbols::demangle(sym).into_owned()),
            };

            frames.push(StackFrame {
                start,
                size,
                stack_pointer,
                instruction_pointer,
                symbol,
            });
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();

    assert_match_expected(arch, "callstack", &frames);
}

#[test]
fn callstack_x86_64() {
    callstack(Arch::X86_64)
}

#[test]
fn callstack_aarch64() {
    callstack(Arch::Aarch64)
}
