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

#define debug 0
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
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		if (!debug)
			break;
		char fmt0[] = "client: connect\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));

		bpf_getsockopt(skops, IPPROTO_TCP, TCP_DELACK_MIN, &delay, sizeof(delay));
		bpf_getsockopt(skops, IPPROTO_TCP, TCP_DELACK_SEGS, &segs, sizeof(segs));
		char fmt111[] = "client: delay: %u	segs: %u\n";
		bpf_trace_printk(fmt111, sizeof(fmt111), delay, segs);

		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		if (!debug)
			break;
		char fmt2[] = "client: active established\n";
		bpf_trace_printk(fmt2, sizeof(fmt2));

		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		if (debug) {
			char fmt3[] = "server: passive established\n";
			bpf_trace_printk(fmt3, sizeof(fmt3));
		}
		/* Server will send option */
		rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);

		break;
	case BPF_TCP_OPTIONS_SIZE_CALC: {
		int option_len = sizeof(struct tcp_option);
		/* args[1] is the second argument */
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
			//char fmt4[] = "OPTIONS_SIZE_CALC  \t original:%d extend:%d B\n";
			//bpf_trace_printk(fmt4, sizeof(fmt4), skops->args[1], option_len);
		}
		else rv = 0;
		break;
	}
	case BPF_TCP_OPTIONS_WRITE:
	{
		struct tcp_option opt = {
			.kind = OPTION_KIND,
			.len  = 4,	// of this option struct
			.rel_delay = 4,	// inverted, delay ACK timeout as fraction of RTT
			.segs = 10,	// (# mss) amount of unacked data that triggers immediate ACK
		};
		/* Server sends option */
		memcpy(&option_buffer, &opt, sizeof(int));
		rv = option_buffer;

		if (debug) {
			char fmt5[] = "OPTIONS_WRITE: %x \n\n";
			bpf_trace_printk(fmt5, sizeof(fmt5), rv);
		}
		break;

                // disable option insertion after sending first data packet
                if (skops->data_segs_in > 1)
                        bpf_sock_ops_cb_flags_set(skops, 0);

	}
	case BPF_TCP_PARSE_OPTIONS: {
		/* client */
		/* get the parsed option, swap to little-endian */
		unsigned int option = swap(skops->args[2]);
		unsigned int rel_delay;

		kind      = (option & 0xFF000000) >> 24;
		rel_delay = (option & 0x0000FF00) >> 8;
		segs      = (option & 0x000000FF);

		if (debug) {
			char fmt10[] = "PARSE_OPTIONS: %x, delacks per rtt: %u, segs: %u\n";
			bpf_trace_printk(fmt10, sizeof(fmt10), option, rel_delay, segs);
		}

		if (kind != OPTION_KIND) {
			break;
		}
		delay = (skops->rtt_min >> 3) / (rel_delay);
		if (debug) {
			char fmt11[] = "rttmin: %u us, delay: %u us\n";
			bpf_trace_printk(fmt11, sizeof(fmt11), skops->rtt_min >> 3, delay);
		}
		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_DELACK_MIN, &delay, sizeof(delay));
		rv+= bpf_setsockopt(skops, IPPROTO_TCP, TCP_DELACK_SEGS, &segs, sizeof(segs));

		if (debug) {
			/* get new vals */
			bpf_getsockopt(skops, IPPROTO_TCP, TCP_DELACK_MIN, &delay, sizeof(delay));
			bpf_getsockopt(skops, IPPROTO_TCP, TCP_DELACK_SEGS, &segs, sizeof(segs));
			char fmt12[] = "receiver new delay: %u 	segs: %u\n";
			bpf_trace_printk(fmt12, sizeof(fmt12), delay, segs);
		}
		break;
	}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
