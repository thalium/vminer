# vminer

Virtual Machine Introspection

## KVM

Vminer enable VMI with an unpatched KVM.

It works by injecting a thread into the process that control KVM and from there,
send the data that vminer needs.

## Setting things up

- Build the patch and copy it to `/usr/lib/libvminer_kvm_patch.so`
- To target Linux guests, you need the debug info of the kernel and the
  `System.map` file. The debug info and the `System.map` of the exact same
  kernel is required.
  - On Debian, it is typically found in the `linux-image-amd64-dbg` package
    (`/usr/lib/debug/boot/System.map-$version-amd64/`)
  - You can also build a module with debug infos and call it `module.ko`.
- For Windows systems, required PDBs are downloaded automatically.
