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

struct bpf_map_def SEC("maps") global_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct tcpbpf_globals),
	.max_entries = 2,
};

static inline void update_event_map(int event)
{
	__u32 key = 0;
	struct tcpbpf_globals g, *gp;

	gp = bpf_map_lookup_elem(&global_map, &key);
	if (gp == NULL) {
		struct tcpbpf_globals g = {0};

		g.event_map |= (1 << event);
		bpf_map_update_elem(&global_map, &key, &g,
			    BPF_ANY);
	} else {
		g = *gp;
		g.event_map |= (1 << event);
		bpf_map_update_elem(&global_map, &key, &g,
			    BPF_ANY);
	}
}

/* From: stackoverflow.com/questions/2182002/convert-big-endian-to-little-endian-in-c-without-using-provided-func */
static inline unsigned int swap(unsigned int num) {
	return ((num>>24)&0xff) | // move byte 3 to byte 0
		((num<<8)&0xff0000) | // move byte 1 to byte 2
		((num>>8)&0xff00) | // move byte 2 to byte 1
		((num<<24)&0xff000000); // byte 0 to byte 3

}

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
		.data = 0x0200, // will be swapped for big-endian
	};

	int rv = -1;
	int granularity = 0;
	int op;
	int v = 0;
	int option_buffer;
	unsigned int uto, UserTimeout;

	op = (int) skops->op;

	update_event_map(op);
	char fmt11[] = "real Timeout: %d\n";

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		/* Set specific callback */
		rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);

		char fmt0[] = "tcp connect callback\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	{
		char fmt2[] = "active established callback\n";
		bpf_trace_printk(fmt2, sizeof(fmt2));
		break;
	}
	case BPF_TCP_OPTIONS_SIZE_CALC:
	{
		int option_len = sizeof(struct tcp_option);
		/* args[1] is the second argument */
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
			char fmt4[] = "OPTIONS_SIZE_CALC  \t original:%d extend:%d B\n";
			bpf_trace_printk(fmt4, sizeof(fmt4), skops->args[1], option_len);
		}
		else rv = 0;
		break;
	}
	case BPF_TCP_OPTIONS_WRITE:
		/* put the struct option into the reply value */
		if (granularity != 0) {
			/* set granularity flag */
			struct tcp_option *p = (&opt);
			p->data |= G_FLAG;
		}

		memcpy(&option_buffer, &opt, sizeof(int));
		// skops->reply_long = opt;
		rv = option_buffer;

		char fmt5[] = "OPTIONS_WRITE: %x \n";
		bpf_trace_printk(fmt5, sizeof(fmt5), rv);
		break;

	case BPF_TCP_PARSE_OPTIONS:
		/* get original value */
		rv = bpf_getsockopt(skops, IPPROTO_TCP, TCP_BPF_USER_TIMEOUT, &UserTimeout, sizeof(UserTimeout));
		char fmt10[] = "PARSE_OPTIONS: %x, %x, %d\n";
		bpf_trace_printk(fmt11, sizeof(fmt11), UserTimeout);

		/* get the parsed option, swap to little-endian */
		uto = swap(skops->args[2]);
		/* Keep the last 15 bits */
		UserTimeout = uto & 0x00007FFF;
		granularity = uto & 0x00008000;
		bpf_trace_printk(fmt10, sizeof(fmt10), uto, granularity, UserTimeout);
		if (granularity != 0)
			/* convert from minutes to seconds */
			UserTimeout *= 60;
		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_BPF_USER_TIMEOUT, &UserTimeout, sizeof(UserTimeout));

		/* get new UTO */
		rv = bpf_getsockopt(skops, IPPROTO_TCP, TCP_BPF_USER_TIMEOUT, &UserTimeout, sizeof(UserTimeout));
		bpf_trace_printk(fmt11, sizeof(fmt11), UserTimeout);
		break;
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
