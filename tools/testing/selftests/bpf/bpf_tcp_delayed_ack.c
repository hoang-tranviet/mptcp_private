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

int _version SEC("version") = 1;

#define OPTION_KIND 67	// reserved option number

struct tcp_option {
	__u8 kind;
	__u8 len;
	__u8 rel_delay;
	__u8 segs;
};

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int op;
	int option_buffer;
	unsigned int kind, delay, segs;

	op = (int) skops->op;

	switch (op) {
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);
		break;
	case BPF_TCP_OPTIONS_SIZE_CALC: {
		int option_len = sizeof(struct tcp_option);
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
		} else rv = 0;
		break;
	}
	case BPF_TCP_OPTIONS_WRITE:
	{
		struct tcp_option opt = {
			.kind = OPTION_KIND,
			.len  = 4,	// of this option struct
			.rel_delay = 2,	// inverted, delay ACK timeout as fraction of RTT
			.segs = 100,	// (# mss) amount of unacked data that triggers immediate ACK
		};
		memcpy(&option_buffer, &opt, sizeof(int));
		rv = option_buffer;
		break;
	}
	case BPF_TCP_PARSE_OPTIONS: {
		unsigned int option = swap(skops->args[2]);
		unsigned int rel_delay;

		kind      = (option & 0xFF000000) >> 24;
		rel_delay = (option & 0x0000FF00) >> 8;
		segs      = (option & 0x000000FF);

		if (kind != OPTION_KIND)
			break;
		delay = (skops->rtt_min >> 3) / (rel_delay);
		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_DELACK_MIN, &delay, sizeof(delay));
		rv+= bpf_setsockopt(skops, IPPROTO_TCP, TCP_DELACK_SEGS, &segs, sizeof(segs));
		break;
	}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
