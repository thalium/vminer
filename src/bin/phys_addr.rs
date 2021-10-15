use std::{fs, io, mem, os::unix::prelude::*};

const PAGE_SIZE: usize = 0x1000;

fn get_phys_addr_of(addr: usize) -> io::Result<usize> {
    const ENTRY_SIZE: usize = mem::size_of::<u64>();

    let mapping = fs::File::open("/proc/self/pagemap")?;

    let page_offset = (addr / PAGE_SIZE) * ENTRY_SIZE;
    let mut buf = [0; ENTRY_SIZE];
    mapping.read_exact_at(&mut buf, page_offset as _)?;

    let page_data = u64::from_ne_bytes(buf);
    println!("{:x?}", page_data);

    if page_data & (1 << 63) == 0 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "address is not in RAM",
        ));
    }

    const INDEX_MASK: u64 = (1 << 54) - 1;
    let physical_page_addr = ((page_data & INDEX_MASK) * PAGE_SIZE as u64) as usize;

    Ok(physical_page_addr + addr % PAGE_SIZE)
}

fn main() {
    let s = String::from("This text lives in the VM");
    let addr = s.as_str() as *const str as *const u8 as usize;
    let phys_addr = get_phys_addr_of(addr).unwrap();

    println!(
        "Buffer of size {} is at physical address 0x{:x}",
        s.len(),
        phys_addr
    );

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
