#[cfg(target_os = "windows")]
mod windows;

fn usage() -> ! {
    eprintln!("Usage: force_mmap PID");
    std::process::exit(1);
}

pub fn main() {
    let mut args = std::env::args_os().skip(1);

    let pid = (|| args.next()?.to_str()?.parse().ok())().unwrap_or_else(|| usage());
    if args.next().is_some() {
        usage();
    }

    if let Err(err) = force_mmap(pid) {
        eprintln!("Error: {}", err);
        std::process::exit(1);
    }
}

#[cfg(target_os = "windows")]
use crate::windows::force_mmap;

#[cfg(target_os = "linux")]
fn force_mmap(pid: i32) -> std::io::Result<()> {
    use std::{
        fs,
        io::{self, BufRead},
    };
    use sync_file::ReadAt;

    let maps = fs::File::open(format!("/proc/{}/maps", pid))?;
    let mut maps = io::BufReader::new(maps);
    let mem = sync_file::RandomAccessFile::open(format!("/proc/{}/mem", pid))?;

    let mut buffer = Vec::new();
    let mut line = String::with_capacity(128);

    while maps.read_line(&mut line)? != 0 {
        let (start, end, readable) = (|| {
            let (start, line) = line.split_at(line.find('-')?);
            let (end, line) = line[1..].split_at(line[1..].find(' ')?);
            let readable = match line.as_bytes()[1] {
                b'r' => true,
                b'-' => false,
                _ => return None,
            };

            let start = u64::from_str_radix(start, 16).ok()?;
            let end = u64::from_str_radix(end, 16).ok()?;

            Some((start, end, readable))
        })()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;

        if readable {
            println!("Mapping {:x}-{:x}", start, end);
            buffer.resize((end - start) as usize, 0);
            mem.read_exact_at(&mut buffer, start)?;
        }

        line.clear();
    }

    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux",)))]
fn force_mmap(_: u32) -> std::io::Result<()> {
    eprintln!("This tool is not supported on your OS");
    std::process::exit(1);
}
