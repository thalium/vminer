#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod inner {
    use clap::Parser;

    use icebox::backends::kvm;
    use icebox::backends::kvm_dump;

    fn parse_hex(src: &str) -> Result<u64, std::num::ParseIntError> {
        let sub = src.trim_start_matches("0x");
        u64::from_str_radix(sub, 16)
    }

    #[derive(Parser, Debug)]
    struct Args {
        #[clap(short = 'p', long = "pid", about = "input KVM PID")]
        pid: i32,
        #[clap(
            short = 'o',
            long = "output",
            default_value = "kvm.dump",
            about = "output file path"
        )]
        output: std::path::PathBuf,
        #[clap(
        short = 'm',
        long = "mem_size",
        parse(try_from_str = parse_hex),
        default_value = "0x80000000",
        about = "target KVM mapping memory size"
    )]
        mem_size: u64,
    }

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        env_logger::init();
        let args = Args::parse();
        let vm = kvm::Kvm::connect(args.pid, args.mem_size)?;
        kvm_dump::DumbDump::dump_vm(&vm)?.write(args.output)?;
        Ok(())
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod inner {
    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("This tool is not available on your platform");
        std::process::exit(1);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    inner::main()
}
