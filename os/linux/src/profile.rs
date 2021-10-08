use alloc::string::String;
use ibc::GuestVirtAddr;
use std::io;

pub(crate) struct FastSymbols {
    pub(crate) per_cpu_start: GuestVirtAddr,
    pub(crate) current_task: GuestVirtAddr,
}

pub struct Profile {
    pub(crate) syms: ibc::SymbolsIndexer,
    pub(crate) fast_syms: FastSymbols,
}

impl Profile {
    pub fn new(syms: ibc::SymbolsIndexer) -> Profile {
        let per_cpu_start = syms.get_addr("__per_cpu_start").unwrap();
        let current_task = syms.get_addr("current_task").unwrap();

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

pub fn parse_kallsyms<R: io::BufRead>(mut r: R, syms: &mut ibc::SymbolsIndexer) -> io::Result<()> {
    let mut line = String::with_capacity(200);

    loop {
        if r.read_line(&mut line)? == 0 {
            break;
        }

        let sym = (|| {
            let (start, rest) = line.split_at(19);
            let addr = u64::from_str_radix(&start[0..16], 16).ok()?;

            match start.as_bytes()[17] {
                b'T' | b't' | b'A' => (),
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
            syms.insert_addr(name, ibc::GuestVirtAddr(addr));
        }

        line.clear();
    }

    Ok(())
}
