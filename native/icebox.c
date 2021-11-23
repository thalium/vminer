#include <stdlib.h>
#include <stdio.h>
#include "icebox.h"

#define CHECK(expr) do { err = expr; if (err) goto error; } while(0)

int main() {
	Error *err = NULL;
	Backend *dump = NULL;
	Os *os = NULL;
	Process procs[200];
	char name[30];
	unsigned pid;
	size_t n_procs = (sizeof procs)/(sizeof *procs);

	CHECK(read_dump("kvm.dump", &dump));
	CHECK(os_new(dump, &os));
	CHECK(os_processes(os, procs, &n_procs));

	for(size_t i = 0; i < n_procs; ++i) {
		CHECK(process_name(os, procs[i], name, sizeof name));
		CHECK(process_pid(os, procs[i], &pid));

		printf("%d: %s\n", pid, name);
	}

error:
	if(os != NULL) {
		os_free(os);
	} else if(dump != NULL) {
		backend_free(dump);
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
