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

#define IW 40 	/* #MSS */
#define DEBUG 0

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	struct tcp_option opt = {
		.kind = 66, 	// arbitrary
		.len = 4,   	// of this option struct
		.data = IW << 8,// iw in little-endian
	};
	//int bufsize = 1500000;
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
		char fmt0[] = "tcp connect callback\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));
		/* Set sndbuf and rcvbuf of active connections
		rv += bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF, &bufsize,
				    sizeof(bufsize));
		rv += bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF,
				     &bufsize, sizeof(bufsize));
		 */
		break;
	case BPF_SOCK_OPS_RWND_INIT:
		// enable proper sending of new unsent data during fast recovery
		// see  tcp_default_init_rwnd() and RFC 3517, Section 4
		rv = IW*5;
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
		if (DEBUG) {
			char fmt3[] = "OPTIONS_WRITE: %x \n";
			bpf_trace_printk(fmt3, sizeof(fmt3), rv);
		}
		// disable option insertion from now
		if (skops->data_segs_in > 1)
			bpf_sock_ops_cb_flags_set(skops, 0);
		break;

	/* server side */
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		/* Set sndbuf and rcvbuf of passive connections
		rv = bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF, &bufsize,
				    sizeof(bufsize));
		rv +=  bpf_setsockopt(skops, SOL_SOCKET, SO_RCVBUF,
				      &bufsize, sizeof(bufsize));
		 */
		break;
	case BPF_TCP_PARSE_OPTIONS:
		if (DEBUG) {
			char fmt90[] = "sk state:%d full:%d segs_in:%u\n";
			char fmt91[] = "segs_out:%u data_segs_out:%u rcv_nxt:%u \n";
			bpf_trace_printk(fmt90, sizeof(fmt90), skops->state, skops->is_fullsock, skops->segs_in);
			bpf_trace_printk(fmt91, sizeof(fmt91), skops->segs_out, skops->data_segs_out, skops->rcv_nxt);
		}

		unsigned int iw_opt, iw;
		iw_opt = swap(skops->args[2]);
		/* Keep the last 16 bits */
		iw = iw_opt & 0x0000FFFF;

		if (DEBUG) {
			char fmt11[] = "got iw: %u\n";
			bpf_trace_printk(fmt11, sizeof(fmt11), iw);

			char fmt13[] = "current cwnd: %u\n";
			bpf_trace_printk(fmt13, sizeof(fmt13), skops->snd_cwnd);
		}

		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_BPF_IW, &iw, sizeof(iw));

		if (DEBUG) {
			char fmt12[] = "setsockopt ret: %d\n";
			bpf_trace_printk(fmt12, sizeof(fmt12), rv);

			/* note: TCP_BPF_IW has no getsockopt brother! */
			char fmt13[] = "new cwnd: %u\n";
			bpf_trace_printk(fmt13, sizeof(fmt13), skops->snd_cwnd);
		}
		break;
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
