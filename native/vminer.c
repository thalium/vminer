#include <stdlib.h>
#include <stdio.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define STD
#include "vminer.h"
#undef STD

#define CHECK(expr) do { err = expr; if (err) goto error; } while(0)

void send_log(void* data, const LogRecord *record) {
	static const char* NAMES[] = {"ERROR", "WARN ", "INFO ", "DEBUG", "TRACE"};

	fprintf(stderr, "%s [%s] %s\n", NAMES[record->level], record->target, record->message);
}

static Logger LOGGER = {
	.data = NULL,
	.enabled = NULL,
	.flush = NULL,
	.log = send_log,
};

typedef struct X86_64Vcpu {
  struct X86_64Registers registers;
  struct X86_64SpecialRegisters special_registers;
  struct X86_64OtherRegisters other_registers;
} X86_64Vcpu;

typedef struct {
	X86_64Vcpu *vcpus;
	int n_vcpus;
	MemoryMapping mappings;
	int file_fd;
	uint64_t offset;
} MyBackend;

int32_t read_physical_memory(const void *data, struct PhysicalAddress addr, void *buf, uintptr_t size) {
	const MyBackend *backend_data = data;
	uint64_t offset = addr.val + backend_data->offset;

	if(offset + size > backend_data->mappings.maps->end.val) {
		return -1;
	}

	while (size != 0) {
		int res = pread(backend_data->file_fd, buf, size, offset);

		switch (res) {
			case -1: return errno;
			case 0: return -1;
			default:
				size -= res;
				offset += res;
		}
	}
	return 0;
}

MemoryMapping memory_mappings(const void *data) {
	const MyBackend *backend_data = data;
	return backend_data->mappings;
}

struct X86_64Registers get_registers(const void *data, uintptr_t vcpu) {
	const MyBackend *backend_data = data;
	return backend_data->vcpus[vcpu].registers;
}

struct X86_64SpecialRegisters get_special_registers(const void *data, uintptr_t vcpu) {
	const MyBackend *backend_data = data;
	return backend_data->vcpus[vcpu].special_registers;
}

struct X86_64OtherRegisters get_other_registers(const void *data, uintptr_t vcpu) {
	const MyBackend *backend_data = data;
	return backend_data->vcpus[vcpu].other_registers;
}

void drop(void *data) {
	MyBackend *backend_data = data;
	close(backend_data->file_fd);
	free(backend_data->vcpus);
	free(backend_data);
}

struct DumpHeader {
	uint32_t magic;
	uint32_t arch;
	uint32_t n_mappings;
	uint32_t n_vcpus;
};

Backend *make_dump(const char *path) {
	struct DumpHeader header;

	MyBackend *backend_data = malloc(sizeof *backend_data);

	backend_data->file_fd = open(path, O_RDONLY | O_CLOEXEC);

	if(read(backend_data->file_fd, &header, sizeof header) != sizeof header) {
		perror("read header");
		goto error0;
	}

	if(header.arch != 0) {
		printf("Wrong arch: %d\n", header.arch);
		goto error0;
	}

	backend_data->mappings.len = header.n_mappings;
	int n_mappings = header.n_mappings * sizeof(MemoryMapping);
	MemoryMap *maps = malloc(n_mappings);
	if(read(backend_data->file_fd, maps, n_mappings) != n_mappings) {
		perror("read mappings");
		goto error1;
	}
	backend_data->mappings.maps = maps;

	backend_data->n_vcpus = header.n_vcpus;
	int vcpu_size = header.n_vcpus * sizeof(X86_64Vcpu);
	backend_data->vcpus = malloc(vcpu_size);
	if(read(backend_data->file_fd, backend_data->vcpus, vcpu_size) != vcpu_size) {
		perror("read vcpus");
		goto error2;
	}

	if((int)(backend_data->offset = lseek(backend_data->file_fd, 0, SEEK_CUR)) == -1) {
		perror("lseek");
		goto error2;
	}

	X86_64Backend x86_64_dump = {
		.data = backend_data,
		.vcpus_count = header.n_vcpus,
		.read_physical_memory = read_physical_memory,
		.memory_mappings = memory_mappings,
		.registers = get_registers,
		.special_registers = get_special_registers,
		.other_registers = get_other_registers,
		.drop = drop,
	};

	return backend_make(x86_64_dump);

error2:
	free(backend_data->vcpus);
error1:
	free(maps);
error0:
	if(close(backend_data->file_fd) == -1) {
		perror("close");
	}
	free(backend_data);
	return NULL;
}

int main() {
	Process *procs = NULL;
	char name[30];
	uint64_t pid;
	ssize_t n_procs;

	set_logger(&LOGGER);

	Backend *dump = make_dump("../data/linux-5.10-x86_64-dump");
	if(dump == NULL) goto error;

	Symbols *symbols = symbols_new();
	symbols_load_dir(symbols, "../data/linux-5.10-x86_64");

	Os *os = os_new_linux(dump, symbols);
	if(os == NULL) goto error;

	n_procs = os_processes(os, NULL, 0);
	if(n_procs < 0) goto error;

	procs = malloc(n_procs * sizeof *procs);
	n_procs = os_processes(os, procs, n_procs);
	if(n_procs < 0) goto error;

	for(size_t i = 0; i < n_procs; ++i) {
		if(process_name(os, procs[i], name, sizeof name) < 0) goto error;
		if(process_id(os, procs[i], &pid) < 0) goto error;

		printf("%ld: %s\n", pid, name);
	}
	return 0;

error:
	char buf[200];
	print_last_error(buf, 200);
	printf("Error: %s", buf);
	return 1;
}
