use alloc::{string::String, vec::Vec};
use std::io;

pub(crate) struct FastSymbols {
    pub(crate) per_cpu_start: u64,
    pub(crate) current_task: u64,
}

pub struct Profile {
    pub(crate) syms: ibc::SymbolsIndexer,
    pub(crate) fast_syms: FastSymbols,
}

impl Profile {
    pub fn new(kallsyms_path: &std::path::Path) -> Profile {
        let kallsyms = io::BufReader::new(std::fs::File::open(kallsyms_path).unwrap());
        let kallsyms = parse_kallsyms(kallsyms).unwrap();

        let per_cpu_start = kallsyms
            .iter()
            .find(|sym| sym.name == "__per_cpu_start")
            .unwrap()
            .addr;
        let current_task = kallsyms
            .iter()
            .find(|sym| sym.name == "current_task")
            .unwrap()
            .addr;

        Profile {
            syms: ibc::SymbolsIndexer::new(),
            fast_syms: FastSymbols {
                per_cpu_start,
                current_task,
            },
        }
    }

    #[cfg(feature = "object")]
    pub fn read_object_file<P: AsRef<std::path::Path>>(&mut self, path: P) {
        let content = std::fs::read(path).unwrap();
        let obj = obj::File::parse(&*content).unwrap();
        self.read_object(&obj);
    }

    #[cfg(feature = "object")]
    pub fn read_object(&mut self, obj: &obj::File) {
        icebox_dwarf::load_types(obj, &mut self.syms).unwrap()
    }
}

#[derive(Debug)]
pub struct Sym {
    addr: u64,
    name: String,
    kind: u8,
}

pub fn parse_kallsyms<R: io::BufRead>(mut r: R) -> io::Result<Vec<Sym>> {
    let mut line = String::with_capacity(200);
    let mut v = Vec::new();

    loop {
        if r.read_line(&mut line)? == 0 {
            break;
        }

        let sym = (|| {
            let addr = u64::from_str_radix(&line[0..16], 16).ok()?;
            let rest = &line[19..];
            let kind = line.as_bytes()[17];
            let name = match rest.find(&['\t', '\n'][..]) {
                Some(i) => &rest[..i],
                None => rest,
            }
            .to_owned();

            Some(Sym { addr, name, kind })
        })();

        if let Some(sym) = sym {
            v.push(sym);
        }

        line.clear();
    }

    Ok(v)
}
