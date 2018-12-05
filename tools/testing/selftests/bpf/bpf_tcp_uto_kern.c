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
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

int _version SEC("version") = 1;

#define G_FLAG 0x0080

struct tcp_option {
	__u8 kind;
	__u8 len;
	__u16 data;
};

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	struct tcp_option opt = {
		.kind = 28, // TCP user option
		.len = 4,   // of this option struct
		.data = 0x0100, // 1 second
	};
	int rv = -1;
	int granularity = 0;
	int option_buffer;
	unsigned int uto, UserTimeout;

	int op = (int) skops->op;

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);
		UserTimeout = 1000;
		bpf_setsockopt(skops, IPPROTO_TCP, TCP_BPF_USER_TIMEOUT, &UserTimeout, sizeof(UserTimeout));
		break;
	case BPF_TCP_OPTIONS_SIZE_CALC:
	{
		int option_len = sizeof(struct tcp_option);
		if (skops->args[1] + option_len <= 40)
			rv = option_len;
		else rv = 0;
		break;
	}
	case BPF_TCP_OPTIONS_WRITE:
		if (granularity != 0) {
			struct tcp_option *p = (&opt);
			p->data |= G_FLAG;
		}
		memcpy(&option_buffer, &opt, sizeof(int));
		rv = option_buffer;
		break;
	case BPF_TCP_PARSE_OPTIONS:
		uto = __builtin_bswap32(skops->args[2]);
		UserTimeout = (uto & 0x00007FFF)*1000;
		granularity = (uto & 0x00008000) >> 15;
		if (granularity != 0)
			UserTimeout *= 60;
		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_BPF_USER_TIMEOUT, &UserTimeout, sizeof(UserTimeout));
		break;
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
