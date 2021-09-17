use ibc::{Backend, GuestVirtAddr, Os};
use std::io;
pub struct Linux;

impl Linux {
    pub const fn is_kernel_addr(addr: GuestVirtAddr) -> bool {
        (addr.0 as i64) < 0
    }
}

impl Os for Linux {
    fn quick_check<B: Backend>(backend: &B) -> ibc::MemoryAccessResult<bool> {
        const OFFSET: usize = 0x1000;
        const TARGET: &[u8] = b"Linux version";

        const KERNEL_START: u64 = 0xffffffff80000000;
        const KERNEL_END: u64 = 0xfffffffffff00000;

        let mut buf = [0; OFFSET + TARGET.len()];
        let finder = memchr::memmem::Finder::new(TARGET);

        for addr in (KERNEL_START..KERNEL_END).step_by(OFFSET) {
            let addr = GuestVirtAddr(addr);
            if let Ok(Some(paddr)) = backend.virtual_to_physical(addr) {
                backend.read_memory(paddr, &mut buf)?;

                if finder.find(&buf).is_some() {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

pub struct Sym {
    addr: u64,
    name: String,
}

pub fn parse_kallsyms<R: io::BufRead>(r: &mut R) -> io::Result<Vec<Sym>> {
    let mut line = String::with_capacity(200);
    let mut total_len = 0;

    loop {
        if r.read_line(&mut line)? == 0 {
            break;
        }

        let sym = (|| {
            let addr = u64::from_str_radix(&line[0..16], 16).ok()?;
            let rest = &line[19..];
            let name = match rest.find(' ') {
                Some(i) => &rest[..i],
                None => rest,
            }
            .to_owned();

            Some(Sym { addr, name })
        })();

        if let Some(sym) = sym {
            total_len += sym.name.len();
        } else {
            dbg!(&line);
        }

        line.clear();
    }

    dbg!(total_len);

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use icebox_backend_dumb_dump::DumbDump;

    #[test]
    fn quick_check() {
        let vm = DumbDump::read("../linux.dump").unwrap();
        assert!(Linux::quick_check(&vm).unwrap());

        let vm = DumbDump::read("../grub.dump").unwrap();
        assert!(!Linux::quick_check(&vm).unwrap());
    }
}
