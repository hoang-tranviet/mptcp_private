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

int _version SEC("version") = 1;

struct mptcp_option {
	__u8 kind;
	__u8 len;
	__u8 rsv:4, subtype:4;
	__u8 data;
};

struct mptcp_option mp_opt = {
	.kind = 30, // MPTCP code
	.len = 4,
	.subtype = 15,
	.rsv = 0,
	.data = 0xFF,
};

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int bad_call_rv = 0;
	int good_call_rv = 0;
	int op;
	int v = 0;
	int option_len = sizeof(mp_opt);
	int option_buffer;
	int header_len;

	op = (int) skops->op;

	update_event_map(op);
	char fmt0[] = "tcp connect callback\n";
	char fmt1[] = "active established callback\n";
	char fmt4[] = "BPF_TCP_OPTIONS_SIZE_CALC  \t original:%d extend:%d bytes more\n";
	char fmt3[] = "BPF_MPTCP_OPTIONS_WRITE \n";

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		bpf_trace_printk(fmt0, sizeof(fmt0));
		break;
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		/* Set specific callback */
		good_call_rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);
		/* This activates all conditional call back: RTO, Retrans, State changed, and option write */
		// good_call_rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_ALL_CB_FLAGS);
		bpf_trace_printk(fmt1, sizeof(fmt1));
		break;
	case BPF_TCP_OPTIONS_SIZE_CALC:
		/* args[1] is the second argument */
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
			bpf_trace_printk(fmt4, sizeof(fmt4), skops->args[1], option_len);
		}
		else rv = 0;
		break;
	case BPF_MPTCP_OPTIONS_WRITE:
		/* put the struct option into the reply value */
		bpf_trace_printk(fmt3, sizeof(fmt3));
		// skops->reply_long = mp_opt;
		memcpy(&option_buffer, &mp_opt, sizeof(int));
		rv = option_buffer;
		break;
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
