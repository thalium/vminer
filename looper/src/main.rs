fn main() {
    let pid = std::process::id();
    let mut i = 0;

    loop {
        println!("My PID: {} ({})", pid, i);
        i += 1;
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
