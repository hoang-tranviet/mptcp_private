// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/tcp.h>
//#include <netinet/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

int _version SEC("version") = 1;

struct tcp_option {
	__u8 kind;
	__u8 len;
	__u16 data;
};

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	// Use well-known option to avoid trigger BPF PARSE_OPTION callback
	struct tcp_option opt = {
		.kind = 2, // MSS option
		.len = 4,   // of this option struct
		.data = 0xA805, // = 05A8 (little endian) = 1480 (dec)
	};

	int rv = -1;

	int op = (int) skops->op;

	switch (op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);
		break;
	case BPF_TCP_OPTIONS_SIZE_CALC:
	{
		int option_len = sizeof(struct tcp_option);
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
		}
		else
			rv = 0;
		break;
	}
	case BPF_TCP_OPTIONS_WRITE:{
		int option_buffer;
		memcpy(&option_buffer, &opt, sizeof(int));
		rv = option_buffer;
		break;
	}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
