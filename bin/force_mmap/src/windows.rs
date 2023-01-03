use windows::Win32::System::{
    Diagnostics::Debug::ReadProcessMemory,
    Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION, MEM_FREE, MEM_RESERVE, PAGE_NOACCESS},
    Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
};

pub fn force_mmap(pid: u32) -> std::io::Result<()> {
    let process = unsafe { OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, pid)? };

    let mut region = MEMORY_BASIC_INFORMATION::default();
    let dwlength = std::mem::size_of_val(&region);

    let mut address = std::ptr::null();

    let mut buffer = Vec::<u8>::new();
    let mut bytes_read = 0;

    loop {
        let read = unsafe { VirtualQueryEx(process, Some(address), &mut region, dwlength) };
        if read == 0 {
            return Ok(());
        }

        address = (region.BaseAddress as usize + region.RegionSize) as *const _;

        if region.State == MEM_FREE
            || region.State == MEM_RESERVE
            || region.Protect & PAGE_NOACCESS == PAGE_NOACCESS
        {
            continue;
        }

        println!(
            "Mapping {:x}-{:x}",
            region.BaseAddress as usize,
            region.BaseAddress as usize + region.RegionSize
        );

        buffer.reserve(region.RegionSize);

        let res = unsafe {
            ReadProcessMemory(
                process,
                region.BaseAddress,
                buffer.as_mut_ptr().cast(),
                region.RegionSize,
                Some(&mut bytes_read),
            )
        };

        if let Err(err) = res.ok() {
            println!("Error: {err}");
        } else if bytes_read != region.RegionSize {
            println!(
                "Did not read everything: {bytes_read:#x}/{:#x}",
                region.RegionSize
            );
        }
    }
}
