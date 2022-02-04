use ibc::{IceResult, Os, VirtualAddress};
use icebox::{backends::kvm_dump::DumbDump, os::Linux};
use once_cell::sync::Lazy;

static LINUX: Lazy<Linux<DumbDump<ibc::File>>> = Lazy::new(|| {
    let res = (|| {
        let backend = DumbDump::read("../data/linux-5.10/dump")?;
        let mut syms = ibc::SymbolsIndexer::new();
        let kallsyms = std::io::BufReader::new(std::fs::File::open("../data/linux-5.10/kallsyms")?);
        icebox::os::linux::profile::parse_symbol_file(kallsyms, &mut syms)?;
        syms.read_object_file("../data/linux-5.10/elf")?;
        let profile = icebox::os::linux::Profile::new(syms)?;
        Linux::create(backend, profile)
    })();
    res.expect("Failed to initialize OS")
});

#[test]
fn proc_tree() {
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Thread {
        tid: u32,
        name: String,
    }

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Proc {
        pid: u32,
        name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        children: Vec<Proc>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        threads: Vec<Thread>,
    }

    fn collect_proc_tree(os: &impl Os, proc: ibc::Process) -> IceResult<Proc> {
        let pid = os.process_pid(proc)?;
        let name = os.process_name(proc)?;

        let mut children = Vec::new();
        os.process_for_each_child(proc, &mut |child| {
            assert_eq!(os.process_parent(child).unwrap(), proc);

            let proc = collect_proc_tree(os, child)?;
            children.push(proc);
            Ok(())
        })?;

        let mut threads = Vec::new();
        os.process_for_each_thread(proc, &mut |thread| {
            assert_eq!(os.thread_process(thread).unwrap(), proc);

            let tid = os.thread_id(thread)?;
            let name = os.thread_name(thread)?;
            threads.push(Thread { tid, name });
            Ok(())
        })?;

        Ok(Proc {
            pid,
            name,
            children,
            threads,
        })
    }

    let linux = &*LINUX;
    let result_path = "tests/results/linux-proc-tree.json";

    let init = linux.init_process().unwrap();
    let procs = collect_proc_tree(linux, init).unwrap();

    // Code to generate the expected result
    // let mut file = std::io::BufWriter::new(std::fs::File::create(result_path).unwrap());
    // serde_json::to_writer_pretty(&mut file, &procs).unwrap();
    // drop(file);

    let mut file = std::io::BufReader::new(std::fs::File::open(result_path).unwrap());
    let expected = serde_json::from_reader(&mut file).unwrap();

    assert_eq!(procs, expected);
}

#[test]
fn current_process() {
    let linux = &*LINUX;

    let proc = linux.current_process(0).unwrap();
    assert_eq!(linux.process_pid(proc).unwrap(), 0);

    let proc = linux.current_process(1).unwrap();
    assert_eq!(linux.process_pid(proc).unwrap(), 651);
}

#[test]
fn vmas() {
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct Vma {
        start: VirtualAddress,
        end: VirtualAddress,
        path: Option<String>,
    }

    let linux = &*LINUX;
    let result_path = "tests/results/linux-vmas.json";

    let proc = linux.find_process_by_name("callstack").unwrap().unwrap();
    assert_eq!(linux.process_pid(proc).unwrap(), 651);

    let mut vmas = Vec::new();
    linux
        .process_for_each_vma(proc, &mut |vma| {
            let start = linux.vma_start(vma)?;
            let end = linux.vma_end(vma)?;
            let path = linux
                .vma_file(vma)?
                .map(|path| linux.path_to_string(path).unwrap());

            vmas.push(Vma { start, end, path });
            Ok(())
        })
        .unwrap();

    // Code to generate the expected result
    // let mut file = std::io::BufWriter::new(std::fs::File::create(result_path).unwrap());
    // serde_json::to_writer_pretty(&mut file, &vmas).unwrap();
    // drop(file);

    let mut file = std::io::BufReader::new(std::fs::File::open(result_path).unwrap());
    let expected: Vec<Vma> = serde_json::from_reader(&mut file).unwrap();

    assert_eq!(vmas, expected);
}

#[test]
fn callstack() {
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct StackFrame {
        start: VirtualAddress,
        size: u64,
        stack_pointer: VirtualAddress,
        instruction_pointer: VirtualAddress,
    }

    let linux = &*LINUX;
    let result_path = "tests/results/linux-callstack.json";

    let proc = linux.current_process(1).unwrap();
    assert_eq!(linux.process_pid(proc).unwrap(), 651);

    let mut frames = Vec::new();
    linux
        .process_callstack(proc, &mut |frame| {
            let &ibc::StackFrame {
                start,
                size,
                stack_pointer,
                instruction_pointer,
                ..
            } = frame;

            frames.push(StackFrame {
                start,
                size,
                stack_pointer,
                instruction_pointer,
            });
            Ok(())
        })
        .unwrap();

    // Code to generate the expected result
    // let mut file = std::io::BufWriter::new(std::fs::File::create(result_path).unwrap());
    // serde_json::to_writer_pretty(&mut file, &frames).unwrap();
    // drop(file);

    let mut file = std::io::BufReader::new(std::fs::File::open(result_path).unwrap());
    let expected: Vec<StackFrame> = serde_json::from_reader(&mut file).unwrap();

    assert_eq!(frames, expected);
}
