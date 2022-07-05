#include <stdlib.h>
#include <stdio.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define STD
#include "icebox.h"
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

typedef struct {
	X86_64Vcpu *vcpus;
	int n_vcpus;
	MemoryMapping mappings;
	int file_fd;
	uint64_t offset;
} MyBackend;

int32_t read_memory(const void *data, struct PhysicalAddress addr, void *buf, uintptr_t size) {
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

MemoryMapping memory_mapping(const void *data) {
	const MyBackend *backend_data = data;
	return backend_data->mappings;
}

struct X86_64Vcpus get_vcpus(const void *data) {
	const MyBackend *backend_data = data;
	return (X86_64Vcpus){
		.pointer = backend_data->vcpus,
		.len = backend_data->n_vcpus,
	};
}

void drop(void *data) {
	MyBackend *backend_data = data;
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
		return NULL;
	}

	if(header.arch != 0) {
		printf("Wrong arch: %d\n", header.arch);
		return NULL;
	}

	backend_data->mappings.len = header.n_mappings;
	int n_mappings = header.n_mappings * sizeof(MemoryMapping);
	MemoryMap *maps = malloc(n_mappings);
	if(read(backend_data->file_fd, maps, n_mappings) != n_mappings) {
		perror("read vcpus");
		return NULL;
	}
	backend_data->mappings.maps = maps;

	backend_data->n_vcpus = header.n_vcpus;
	int vcpu_size = header.n_vcpus * sizeof(X86_64Vcpu);
	backend_data->vcpus = malloc(vcpu_size);
	if(read(backend_data->file_fd, backend_data->vcpus, vcpu_size) != vcpu_size) {
		perror("read vcpus");
		return NULL;
	}

	X86_64Backend x86_64_dump = {
		.data = backend_data,
		.read_memory = read_memory,
		.memory_mapping = memory_mapping,
		.get_vcpus = get_vcpus,
		.drop = drop,
	};

	return backend_make(x86_64_dump);
}

int main() {
	Error *err = NULL;
	Os *os = NULL;
	Process *procs = NULL;
	char name[30];
	uint64_t pid;
	size_t n_procs;

	set_logger(&LOGGER);

	Backend *dump = make_dump("../data/linux-5.10-x86_64-dump");
	if(dump == NULL) {
		puts("Error");
		return 1;
	}

	Symbols *symbols = symbols_new();
	CHECK(symbols_load_dir(symbols, "../data/linux-5.10-x86_64"));

	err = os_new_linux(dump, symbols, &os);
	symbols = NULL;
	CHECK(err);
	CHECK(os_processes(os, NULL, &n_procs));
	procs = malloc(n_procs * sizeof *procs);
	CHECK(os_processes(os, procs, &n_procs));

	for(size_t i = 0; i < n_procs; ++i) {
		CHECK(process_name(os, procs[i], name, sizeof name));
		CHECK(process_id(os, procs[i], &pid));

		printf("%ld: %s\n", pid, name);
	}

error:
	free(procs);

	if(os != NULL) {
		os_free(os);
	} else {
		symbols_free(symbols);
	}

	if(err) {
		char error[200];
		error_print(err, error, 200);
		puts(error);
		error_free(err);
		return 1;
	} else {
		return 0;
	}
}
