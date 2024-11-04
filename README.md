# vminer

Vminer is a VMI (Virtual Machine Introspection) tool, which means that it can retrieve data from a virtual machine without the help of a guest tool. Because it does not need executing data on the host, it can also work with a memory dump.

## Features

- Support multiple guest OS and architectures (see section below)
- Independent of a specific backend (hypervisor, dump format, etc)
- Automatic detection of kernel page directory and ASLR
- Getting common OS information (running processes, memory areas, PIDs, etc)
- Getting backtrace/callstack of processes
- Automatic download of debug information (Windows guests only)
- [Software address translation] on Windows guests

[Software address translation]: https://blog.thalium.re/posts/windows-full-memory-introspection-with-icebox/

### Guest support

- Windows:
  - x86_64 (tested from 7 to 11)
- Linux:
  - x86_64
  - aarch64[^arm_current_thread]

[^arm_current_thread]: Finding the current thread on aarch64 is currently limited to finding the current process.

## Example

For a C example, see `native/vminer.c`.

### Rust

Print a list of running processes on a QEMU/KVM Windows VM:

```rust
use vminer::core::Os;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the PID from the command line
    let mut args = std::env::args();
    let pid: i32 = args.nth(1).expect("missing pid").parse()?;

    // Attach to KVM
    let vm = vminer::backends::kvm::Kvm::with_default_qemu_mappings(pid)?;
    // Attach to Windows
    let mut os = vminer::os::Windows::create(vm, Default::default())?;

    // Loop on all process
    os.for_each_process(&mut |proc| {
        // Retrieve process info and print them
        let pid = os.process_id(proc)?;
        let name = os.process_name(proc)?;
        let path = match os.process_path(proc)? {
            Some(path) => format!(" (path: {path})"),
            None => String::new(),
        };

        println!("{pid:5} - {name}{path}");

        Ok(std::ops::ControlFlow::Continue(()))
    })?;

    Ok(())
}
```

### Python

Print a tree of all processes and their threads on a Linux dump:

```python
import vminer

dump = vminer.Dump("data/linux-5.linux-5.10-x86_64/dump")
linux = vminer.Os(dump, "data/linux-5.linux-5.10-x86_64/")

def print_proc(proc, depth):
    threads = ", ".join(f"{t.name} ({t.tid})" for t in proc.threads())
    threads = f" [{threads}]" if threads else ""
    print(f"{depth * '    '}{proc.pid}: {proc.name}{threads}")
    for child in proc.children():
        print_proc(child, depth + 1)

print_proc(linux.init_process(), 0)
```

## Setting things up

### Guest data

- To target Linux guests, you need the kernel's debug information and the `System.map` file from the exact same kernel.
  - On Debian, it is typically found in the `linux-image-amd64-dbg` package (`/usr/lib/debug/boot/System.map-$version-amd64/`)
  - The `/proc/kallsyms` (read from root) file should also work, but you have to rename it `System.map` for vminer to recognize it.
  - You can also build a module with debug information and call it `module.ko`.
- For Windows systems, required PDBs are downloaded automatically.

### KVM

Vminer offers a way to do introspection in a VM running with KVM without patching the Linux kernel. It works by injecting a thread into the process that control KVM and from there, send the data that vminer needs.

To use it, build the patch and copy it to `/usr/lib/libvminer_kvm_patch.so`:

```sh
cargo build -p kvm_patch --release && sudo cp target/release/libvminer_kvm_patch.so /usr/lib/
```

Start the guest using KVM (eg with QEMU) and get the PID of the process using KVM.
You can then use that to attach the VM using vminer. It is strongly advised to pause the VM while running vminer on it.

You will probably need to disable Apparmor or SELinux, which may prevent the KVM process to `dlopen` an unexpected library.

### Make sure that data is available in memory

By default, OS don't always map data in physical memory, but do it lazily on access. This prevents vminer from retrieving it. If you want to analyze a specific process and have a running VM, run the `force_mmap` program on it. It forces the OS to map all memory pages by reading them all.

Another common source of unmapped pages is swap/paging files, think of disabling them.

### Python

To build vminer for use in Python, start by building the library:

```sh
cargo build -p vminer-python --release
```

Once built, rename and rename (or symlink) the library from Cargo's `target/` directory to your desired output directory:
- Linux: rename `libvminer.so` to `vminer.so`
- Windows: rename `libvminer.dll` to `vminer.pyd`
- MacOs: rename `libvminer.dylib` to `vminer.so`

You can then open a Python shell in the output directory and you'll be able to run `import vminer`.

## Technical details

This section provides an more in-depth look at how vminer works internally. While it's not necessary to read this section to use the tool, it offers valuable insights for those interested in the technical aspects of vminer.

### Connecting to KVM

Existing solutions to do VMI with KVM involve patching KVM, which is a built-in kernel module. This means that you have to recompile the whole kernel, which is not always possible. Vminer offers a more convenient solution by enabling reading data from VMs running on unpatched KVM instances on Linux hosts.

This is achieved through a novel solution that injects a DLL into the host process using the `ptrace` API, which sends register values through a Unix socket. Initially, the idea was to send file descriptors from KVM through a Unix socket. However, this approach proved not feasible as these descriptors are not sharable between processes.

The physical memory of the VM can be read using `/proc/{pid}/mem` or `process_vm_readv`.

Nevertheless, there's a subtlety: the KVM process might not provide a single linear block of physical memory, and physical memory may not start at zero. This challenge was encountered during the development of Linux aarch64 and Windows backends, which initially led to difficulties with address translation.

Combining register reads with memory access provides everything needed for vminer's VMI (Virtual Machine Introspection) work.

Having a first working backend in place is a significant step forward. At this point, a simple dump format was also implemented to ensure that vminer wasn't too tightly coupled to KVM and that one could continue work on it without an actual VM running.

With this done, the stage was set for actual VMI work.

### Reading virtual memory

The first challenge in filling the "semantic gap" is reading virtual memory. Thanks to vminer's backend work, access to physical memory of the VM is available. However, programs rarely use physical memory directly; instead, they rely on virtual memory. The hardware component responsible for translating virtual addresses is known as the [Memory Management Unit (MMU)](https://en.wikipedia.org/wiki/Memory_management_unit).

To translate virtual addresses, we need a virtual address, obviously, but also the address of the [page table](https://en.wikipedia.org/wiki/Page_table) (TLB), which is the data structure that stores the virtual-to-physical mapping. This is called the Page Global Directory (PGD) on Linux and the Directory Table Base (DTB) on Windows.

On modern operating system, there is a different page table for each process and for the kernel. Luckily, the kernel knows the PGD of each process so if we know how to read data from the kernel (which is our goal anyway), we can read the memory of every process.

### Linux guests

Detecting a Linux guest is relatively straightforward by finding the Linux banner: a string describing the kernel build. This recognizable string always starts with `"Linux version"`. Detecting this banner not only allows us to identify the Linux guest, but also enables bypassing the [ASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization) of the kernel, which in turn makes use of the symbols values possible.

On compilation, Linux also randomizes the order of some struct fields, such as `task_struct`, which represents a process or thread. However, this can be bypassed by utilizing the debug information of the kernel, which can be obtained from the debug package of the distribution or by compiling a kernel module with debug information enabled.

The main drawback is that a VMI session must be prepared in advance by gathering all necessary debug information and symbols from the VM or the Linux distribution[^debuginfod].

To facilitate reading kernel structures, vminer employs a macro that defines what we expect to exist within the kernel and their respective types. Upon startup, vminer retrieves the correct offsets for these fields directly from the debug information^[check_types].

```rust
define_kernel_structs! {
    struct Layouts { .. }

    #[kernel_name(file)]
    struct File {
        f_path: Path,
    }

    #[kernel_name(mm_struct)]
    struct MmStruct {
        exe_file: Pointer<File>,
        mmap: Pointer<VmAreaStruct>,
        pgd: VirtualAddress,
    }

    #[kernel_name(vm_area_struct)]
    struct VmAreaStruct {
        vm_end: VirtualAddress,
        vm_file: Pointer<File>,
        vm_flags: u64,
        vm_next: Pointer<VmAreaStruct>,
        vm_start: VirtualAddress,
        vm_pgoff: u64,
    }
}
```

This code defines structures that can be initialized with the right field offsets found in debug information.

This done, one can simply read kernel structures without manually calculating offsets or dereferencing fields. If a wrong operation is tried, the program won't even compile! Thanks type safety!

```rust
fn module_path(&self, module: ibc::Module, _proc: ibc::Process) -> IceResult<String> {
    self.pointer_of(module)
        .read_pointer_field(|vma| vma.vm_file)?
        .field(|file| file.f_path)?
        .read_file_path()
}
```

> **A note on ARM support**
>
> On aarch64 (or arm64, ARMv8, or whatever you call it), in kernel space, Linux stores the current process it in a register named `SP_EL0` (which is the stack pointer in userspace). In user space, because it is used as stack pointer, we cannot use it to get the current task [^arm_current_task]. As a workaround, we can look at the current PGD and find a matching one in the process tree. However, this can only find the current _process_ and not the current _thread_.

[^debuginfod]: There are now [`debuginfod`](https://sourceware.org/elfutils/Debuginfod.html) servers that could provide some of them automatically.

### Windows guests

Support for Windows guests was facilitated by prior work on Linux. Unlike Linux, however, there's no access to Windows source code available. Fortunately, PDB files of the kernel provide valuable information. Previous work by Thalium and others has also been helpful in this regard.

Support for [software address translation] and the work that was done in Icebox about it was also integrated and works well, even if the lack of VM control means that not everything is possible.

One significant advantage of Windows support is that most PDB files from Microsoft programs can be downloaded automatically, eliminating the need for preparing a profile for the guest OS. This greatly enhances the user experience!

[software address translation]: https://blog.thalium.re/posts/windows-full-memory-introspection-with-icebox/

## Future work

- Retrieve more data from guests
- Support more backends: hypervisors (eg QEMU), dumps formats, libraries (eg libmicrovmi), etc
- Improve C and Python bindings
- Support new platforms (eg Windows ARM/ARMte, Android)
