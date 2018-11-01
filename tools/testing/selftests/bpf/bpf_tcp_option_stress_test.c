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
	struct tcp_option opt = {
		.kind = 28, // TCP user option
		.len = 4,   // of this option struct
		.data = 0x0100, // 1 second
	};

	int rv = -1;

	int op = (int) skops->op;

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
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
	case BPF_TCP_PARSE_OPTIONS:
	{
		unsigned int uto, UserTimeout;

		uto = __builtin_bswap32(skops->args[2]);
		UserTimeout = (uto & 0x00007FFF)*1000;

/*
		// each trace_printk() on fast path reduces about 3% of goodput
		// still much better than printk() which reduces goodput by 25 times!
		char fmt11[] = "real Timeout: %d\n";
		bpf_trace_printk(fmt11, sizeof(fmt11), UserTimeout);
*/
		break;
	}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
