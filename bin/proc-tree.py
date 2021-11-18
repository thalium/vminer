import icebox

dump = icebox.Dump("kvm.dump")
linux = icebox.Os(dump)

def print_proc(proc, depth):
    threads = ", ".join(f"{t.name} ({t.tid})" for t in proc.threads())
    threads = f" [{threads}]" if threads else ""
    print(f"{depth * '    '}{proc.pid}: {proc.name}{threads}")
    for child in proc.children():
        print_proc(child, depth + 1)

print_proc(linux.init_process(), 0)
