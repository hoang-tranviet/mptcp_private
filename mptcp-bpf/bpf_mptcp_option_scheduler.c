/* Copyright (c) 2019 Viet-Hoang Tran */

#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

// cannot be larger than 6: "invalid indirect read from stack off -44+5 size 6"
#define SCHED_LENGTH 6

#define DEBUG 0

struct bpf_map_def SEC("maps") sched_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = SCHED_LENGTH,
	.max_entries = 5,
};

static inline void init_map()
{
	__u32 key0 = 0;
	__u32 key1 = 1;
	__u32 key2 = 2;
	__u32 key3 = 3;
	char a[]="def";
	char b[]="redun";
	char c[]="blest";
	char d[]="desync";
//	char e[]="roundrobin";

	bpf_map_update_elem(&sched_map, &key0, a, BPF_ANY);
	bpf_map_update_elem(&sched_map, &key1, b, BPF_ANY);
	bpf_map_update_elem(&sched_map, &key2, c, BPF_ANY);
	bpf_map_update_elem(&sched_map, &key3, d, BPF_ANY);
}

int _version SEC("version") = 1;

struct tcp_option {
	__u8 kind;
	__u8 len;
	__u16 data;
};

struct tcp_option opt = {
	.kind = 66, 	// arbitrary
	.len = sizeof(opt),   	// of this option struct
	.data = bpf_htons(0x0003), // convert to NBO
};

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int op;
	int option_len = sizeof(opt);
	int option_buffer;
	char sched_name[20];

	op = (int) skops->op;

	char fmt20[] = "not found element a[0]\n";

	init_map();

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		/* Send new option from client side*/
		rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);
		char fmt0[] = "SYN sent\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));
		break;
	case BPF_TCP_OPTIONS_SIZE_CALC:
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
			if (!DEBUG)
				break;
			char fmt4[] = "OPTIONS_SIZE_CALC original:%d extend:%d B\n";
			bpf_trace_printk(fmt4, sizeof(fmt4), skops->args[1], option_len);
		}
		else rv = 0;
		break;
	case BPF_MPTCP_OPTIONS_WRITE:
		/* put the struct option into the reply value */
		memcpy(&option_buffer, &opt, sizeof(int));
		rv = option_buffer;

		char fmt3[] = "OPTIONS_WRITE: %x \n";
		bpf_trace_printk(fmt3, sizeof(fmt3), rv);

		if (skops->state == BPF_TCP_ESTABLISHED && skops->data_segs_out > 5)
			/* Disable option write callback */
		//	bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags
		//					 & ~BPF_SOCK_OPS_OPTION_WRITE_FLAG);
			bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG &
				       			~BPF_SOCK_OPS_OPTION_WRITE_FLAG);
		break;
	case BPF_MPTCP_PARSE_OPTIONS:
		/* get current Scheduler */
		rv = bpf_getsockopt(skops, IPPROTO_TCP, MPTCP_SCHEDULER, sched_name, 20);

		char fmt11[] = "SCHED: %s\n";
		bpf_trace_printk(fmt11, sizeof(fmt11), sched_name);

		unsigned int sch_opt, sch_id;
		sch_opt = bpf_ntohl(skops->args[2]);
		/* Keep the last 16 bits */
		sch_id = sch_opt & 0x0000FFFF;

		char fmt10[] = "PARSE_OPTIONS: raw %x swapped %x sch_id %x\n";
		bpf_trace_printk(fmt10, sizeof(fmt10), skops->args[2], sch_opt, sch_id);

		if (sch_id > 4)
			break;
		char *con_str = bpf_map_lookup_elem(&sched_map, &sch_id);

		if (con_str != NULL) {
			rv = bpf_setsockopt(skops, IPPROTO_TCP, MPTCP_SCHEDULER, con_str, SCHED_LENGTH);
			char fmt12[] = "setsockopt ret:%d Sched in map: %s\n";
			bpf_trace_printk(fmt12, sizeof(fmt12), rv, con_str);
		}
		/* get new Sched */
		rv = bpf_getsockopt(skops, IPPROTO_TCP, MPTCP_SCHEDULER, sched_name, 20);
		bpf_trace_printk(fmt11, sizeof(fmt11), sched_name);
		break;
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
