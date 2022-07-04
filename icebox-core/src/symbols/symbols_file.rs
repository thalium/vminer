use crate::{symbols::ModuleSymbolsBuilder, IceResult};
use alloc::string::String;
#[cfg(feature = "std")]
use std::io;

trait BufRead {
    fn read_one_line(&mut self, buf: &mut String) -> IceResult<usize>;
}

#[cfg(feature = "std")]
impl<R: io::BufRead> BufRead for R {
    fn read_one_line(&mut self, buf: &mut String) -> IceResult<usize> {
        Ok(self.read_line(buf)?)
    }
}

#[cfg(not(feature = "std"))]
impl BufRead for &[u8] {
    fn read_one_line(&mut self, buf: &mut String) -> IceResult<usize> {
        let (line, rest) = match memchr::memchr(b'\n', self) {
            Some(i) => self.split_at(i),
            None => (&**self, &[][..]),
        };
        *self = rest;

        buf.push_str(core::str::from_utf8(line).map_err(crate::IceError::new)?);
        Ok(line.len())
    }
}

#[cfg(feature = "std")]
pub fn parse_symbol_file<R: io::BufRead>(r: R, syms: &mut ModuleSymbolsBuilder) -> IceResult<()> {
    parse_symbol_file_inner(r, syms)
}

pub fn read_from_bytes(bytes: &[u8], syms: &mut ModuleSymbolsBuilder) -> IceResult<()> {
    parse_symbol_file_inner(bytes, syms)
}

fn parse_symbol_file_inner<R: BufRead>(mut r: R, syms: &mut ModuleSymbolsBuilder) -> IceResult<()> {
    let mut line = String::with_capacity(200);

    loop {
        if r.read_one_line(&mut line)? == 0 {
            break;
        }

        // Each line has this format:
        // ffffffffba000200 D linux_banner

        let sym = (|| {
            let (start, rest) = line.split_at(19);
            let addr = u64::from_str_radix(&start[0..16], 16).ok()?;

            // Filter interesting symbols kinds
            match start.as_bytes()[17].to_ascii_uppercase() {
                b'T' | b'A' | b'D' | b'R' => (),
                _ => return None,
            }

            let name = match rest.find(&['\t', '\n'][..]) {
                Some(i) => &rest[..i],
                None => rest,
            };

            Some((name, addr))
        })();

        if let Some((name, addr)) = sym {
            syms.push(crate::VirtualAddress(addr), name);
        }

        line.clear();
    }

    Ok(())
}
