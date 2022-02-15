#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod inner {
    use clap::Parser;

    use icebox::backends::kvm;
    use icebox::backends::kvm_dump;

    #[derive(Parser, Debug)]
    struct Args {
        #[clap(short = 'p', long = "pid", help = "input KVM PID")]
        pid: i32,
        #[clap(
            short = 'o',
            long = "output",
            default_value = "kvm.dump",
            help = "output file path"
        )]
        output: std::path::PathBuf,
    }

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        env_logger::init();
        let args = Args::parse();
        let vm = kvm::Kvm::connect(args.pid)?;
        kvm_dump::DumbDump::dump_vm(&vm)?.write(args.output)?;
        Ok(())
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
mod inner {
    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        eprintln!("This tool is not available on your platform");
        std::process::exit(1);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    inner::main()
}
