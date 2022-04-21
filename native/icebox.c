#include <stdlib.h>
#include <stdio.h>

#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


#include "icebox.h"

#define CHECK(expr) do { err = expr; if (err) goto error; } while(0)

void send_log(void* data, LogRecord *record) {
	static const char* NAMES[] = {"ERROR", "WARN ", "INFO ", "DEBUG", "TRACE"};

	fprintf(stderr, "%s [%s] %s\n", NAMES[record.level], record.target, record.message);
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
	int file_fd;
	uint64_t offset;
	uint64_t mem_size;
} MyBackend;

int32_t read_memory(const void *data, struct PhysicalAddress addr, void *buf, uintptr_t size) {
	const MyBackend *backend_data = data;
	uint64_t offset = addr.val + backend_data->offset;

	if(offset + size > backend_data->mem_size) {
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

uint64_t memory_size(const void *data) {
	const MyBackend *backend_data = data;
	return backend_data->mem_size;
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

Backend *make_dump(const char *path) {
	uint32_t data;
	struct stat stats;

	MyBackend *backend_data = malloc(sizeof *backend_data);

	backend_data->file_fd = open(path, O_RDONLY | O_CLOEXEC);

	if(read(backend_data->file_fd, &data, 4) != 4) {
		perror("read arch");
		return NULL;
	}

	if(data != 0) {
		printf("Wrong arch: %d\n", data);
		return NULL;
	}

	if(read(backend_data->file_fd, &data, 4) != 4) {
		perror("read n vcpus");
		return NULL;
	}

	backend_data->n_vcpus = data;
	int vcpu_size = data * sizeof(X86_64Vcpu);
	backend_data->offset = vcpu_size + 8;

	backend_data->vcpus = malloc(vcpu_size);

	if(read(backend_data->file_fd, backend_data->vcpus, vcpu_size) != vcpu_size) {
		perror("read vcpus");
		return NULL;
	}

	if(fstat(backend_data->file_fd, &stats) != 0) {
		perror("fstat");
		return NULL;
	}
	backend_data->mem_size = stats.st_size - backend_data->offset;

	X86_64Backend x86_64_dump = {
		.data = backend_data,
		.read_memory = read_memory,
		.memory_size = memory_size,
		.get_vcpus = get_vcpus,
		.drop = drop,
	};

	return backend_make(x86_64_dump);
}

int main() {
	Error *err = NULL;
	Os *os = NULL;
	Process procs[200];
	char name[30];
	uint64_t pid;
	size_t n_procs = (sizeof procs)/(sizeof *procs);

	set_logger(&LOGGER);

	Backend *dump = make_dump("../data/linux-5.10-x86_64/dump");
	if(dump == NULL) {
		puts("Error");
		return 1;
	}

	CHECK(os_new(dump, &os));
	CHECK(os_processes(os, procs, &n_procs));

	for(size_t i = 0; i < n_procs; ++i) {
		CHECK(process_name(os, procs[i], name, sizeof name));
		CHECK(process_id(os, procs[i], &pid));

		printf("%ld: %s\n", pid, name);
	}

error:
	if(os != NULL) {
		os_free(os);
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
