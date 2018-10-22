// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

static inline unsigned int swap(unsigned int num) {
	return __builtin_bswap32(num);
}

int _version SEC("version") = 1;

#define debug 1

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int op;
	int option_buffer;
	unsigned int kind, delay, segs;

	op = (int) skops->op;

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
	{
		char fmt0[] = "client: connect\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));
		break;
	}
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	{
		char fmt2[] = "client: active established\n";
		bpf_trace_printk(fmt2, sizeof(fmt2));

		if (!debug)
			break;
		bpf_getsockopt(skops, IPPROTO_TCP, TCP_DELACK_MIN, &delay, sizeof(delay));
		bpf_getsockopt(skops, IPPROTO_TCP, TCP_DELACK_SEGS, &segs, sizeof(segs));
		char fmt111[] = "client: delay: %u	segs: %u rv: %d\n";
		bpf_trace_printk(fmt111, sizeof(fmt111), delay, segs, rv);

		delay = 80; // ms
		segs = 10;
		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_DELACK_MIN, &delay, sizeof(delay));
		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_DELACK_MAX, &delay, sizeof(delay));
		rv+= bpf_setsockopt(skops, IPPROTO_TCP, TCP_DELACK_SEGS, &segs, sizeof(segs));

		/* get new vals */
		bpf_getsockopt(skops, IPPROTO_TCP, TCP_DELACK_MIN, &delay, sizeof(delay));
		bpf_getsockopt(skops, IPPROTO_TCP, TCP_DELACK_SEGS, &segs, sizeof(segs));
		bpf_trace_printk(fmt111, sizeof(fmt111), delay, segs, rv);
		break;
	}
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		if (debug) {
			char fmt3[] = "server: passive established\n";
			bpf_trace_printk(fmt3, sizeof(fmt3));
		}
		break;
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
