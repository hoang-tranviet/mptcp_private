/* Copyright (c) 2018 Viet-Hoang Tran */

#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"

static inline unsigned int swap(unsigned int num) {
	return __builtin_bswap32(num);
}

int _version SEC("version") = 1;

struct tcp_option {
	__u8 kind;
	__u8 len;
	__u16 data;
};

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	struct tcp_option opt = {
		.kind = 66, 	// arbitrary
		.len = 4,   	// of this option struct
		.data = 0x3000, // iw in mss
	};
	int bufsize = 1500000;
	int rwnd_init = 40;
	int iw = 40;
	int rv = 0;
	int option_buffer;
	int op;

	op = (int) skops->op;


	/* Usually there would be a check to insure the hosts are far
	 * from each other so it makes sense to increase buffer sizes
	 */
	switch (op) {
	/* client side */
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);
		/* Set sndbuf and rcvbuf of active connections */
		char fmt0[] = "tcp connect callback\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));
		rv += bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF, &bufsize,
				    sizeof(bufsize));
		rv += bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF,
				     &bufsize, sizeof(bufsize));
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		// disable option insertion
		rv = bpf_sock_ops_cb_flags_set(skops, 0);
		break;
	case BPF_TCP_OPTIONS_SIZE_CALC: {
		int option_len = sizeof(opt);
		/* args[1] is the second argument */
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
		}
		else rv = 0;
		break;
	}
	case BPF_TCP_OPTIONS_WRITE:
		/* put the struct option into the reply value */
		memcpy(&option_buffer, &opt, sizeof(int));
		rv = option_buffer;
		char fmt3[] = "OPTIONS_WRITE: %x \n";
		bpf_trace_printk(fmt3, sizeof(fmt3), rv);
		break;

	/* server side */
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		/* Set sndbuf and rcvbuf of passive connections */
		rv = bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF, &bufsize,
				    sizeof(bufsize));
		rv +=  bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF,
				      &bufsize, sizeof(bufsize));
		break;
	case BPF_TCP_PARSE_OPTIONS:
		{
		unsigned int iw_opt, iw;
		iw_opt = swap(skops->args[2]);
		/* Keep the last 16 bits */
		iw = iw_opt & 0x0000FFFF;
		char fmt11[] = "rv:%d new iw: %u\n";
		bpf_trace_printk(fmt11, sizeof(fmt11), rv, iw);

		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_BPF_IW, &iw,
				    sizeof(iw));
		rv += bpf_getsockopt(skops, IPPROTO_TCP, TCP_BPF_IW, &iw,
				    sizeof(iw));
		bpf_trace_printk(fmt11, sizeof(fmt11), rv, iw);
		break;
		}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
