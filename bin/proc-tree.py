import icebox

dump = icebox.Dump("kvm.dump")
linux = icebox.Os(dump)

def print_proc(proc, depth):
    print(f"{depth * '    '}{proc.pid}: {proc.name}")
    for child in proc.children():
        print_proc(child, depth + 1)

print_proc(linux.init_process(), 0)
