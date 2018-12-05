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

int _version SEC("version") = 1;

struct tcp_option {
	__u8 kind;
	__u8 len;
	__u16 data;
};

#define IW 40 	/* #MSS */

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	struct tcp_option opt = {
		.kind = 66, 	// arbitrary
		.len = 4,   	// of this option struct
		.data = IW << 8,// iw in little-endian
	};
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
		break;
	case BPF_SOCK_OPS_RWND_INIT:
		rv = IW*5;
		break;
	case BPF_TCP_OPTIONS_SIZE_CALC: {
		int option_len = sizeof(opt);
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
		}
		else rv = 0;
		break;
	}
	case BPF_TCP_OPTIONS_WRITE:
		memcpy(&option_buffer, &opt, sizeof(int));
		rv = option_buffer;
		if (skops->data_segs_in > 1)
			bpf_sock_ops_cb_flags_set(skops, 0);
		break;
	/* server side */
	case BPF_TCP_PARSE_OPTIONS:{
		unsigned int iw_opt, iw;
		iw_opt = swap(skops->args[2]);
		iw = iw_opt & 0x0000FFFF;
		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_BPF_IW, &iw, sizeof(iw));
		break;
		}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
