// SPDX-License-Identifier: GPL-2.0
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/bpf.h>
#include <sys/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_rlimit.h"
#include "bpf_util.h"
#include "cgroup_helpers.h"

#include "test_tcpbpf.h"

// for trace printk
#include <fcntl.h>
#include <sys/stat.h>


// copied from samples/bpf/bpf_load.c
#define DEBUGFS "/sys/kernel/debug/tracing/"
void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf));
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

#define EXPECT_EQ(expected, actual, fmt)			\
	do {							\
		if ((expected) != (actual)) {			\
			printf("  Value of: " #actual "\n"	\
			       "    Actual: %" fmt "\n"		\
			       "  Expected: %" fmt "\n",	\
			       (actual), (expected));		\
			goto err;				\
		}						\
	} while (0)


int verify_option_result(int map_fd)
{
	__u32 key = 0;
	int res;
	int rv;

	rv = bpf_map_lookup_elem(map_fd, &key, &res);
	EXPECT_EQ(0, rv, "d");
	EXPECT_EQ(0, res, "d");
	key = 1;
	rv = bpf_map_lookup_elem(map_fd, &key, &res);
	EXPECT_EQ(0, rv, "d");
	EXPECT_EQ(5, res, "d");
	return 0;
err:
	return -1;
}

static int bpf_find_map(const char *test, struct bpf_object *obj,
			const char *name)
{
	struct bpf_map *map;

	map = bpf_object__find_map_by_name(obj, name);
	if (!map) {
		printf("%s:FAIL:map '%s' not found\n", test, name);
		return -1;
	}
	return bpf_map__fd(map);
}

int main(int argc, char **argv)
{
	const char *file = "test_tcp_option_kern.o";
	int prog_fd, map_fd, cg_fd = -1;
	const char *cg_path = "/foo";
	int error = EXIT_FAILURE;
	struct bpf_object *obj;
	int rv;

	if (setup_cgroup_environment())
		goto err;

	cg_fd = create_and_get_cgroup(cg_path);
	if (cg_fd < 0)
		goto err;

	if (join_cgroup(cg_path))
		goto err;

	if (bpf_prog_load(file, BPF_PROG_TYPE_SOCK_OPS, &obj, &prog_fd)) {
		printf("FAILED: load_bpf_file failed for: %s\n", file);
		goto err;
	}

	rv = bpf_prog_attach(prog_fd, cg_fd, BPF_CGROUP_SOCK_OPS, 0);
	if (rv) {
		printf("FAILED: bpf_prog_attach: %d (%s)\n",
		       error, strerror(errno));
		goto err;
	}

	if (system("./tcp_server.py")) {
		printf("FAILED: TCP server\n");
		goto err;
	}

	map_fd = bpf_find_map(__func__, obj, "option_count");
	if (map_fd < 0)
		goto err;

	if (verify_option_result(map_fd)) {
		printf("FAILED: Wrong option value\n");
		goto err;
	}
	read_trace_pipe();

	printf("PASSED!\n");
	error = 0;
err:
	bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
	close(cg_fd);
	cleanup_cgroup_environment();
	return error;
}
