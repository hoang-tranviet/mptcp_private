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

#define DEBUG 1

struct bpf_map_def SEC("maps") sched_map = {
	.type = BPF_MAP_TYPE_HASH,
	//.type = BPF_MAP_TYPE_PERCPU_HASH,	/* there will be race! */
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
	char b[]="red";
	char c[]="blest";
	char d[]="rr\0";

	bpf_map_update_elem(&sched_map, &key0, a, BPF_NOEXIST);
	bpf_map_update_elem(&sched_map, &key1, b, BPF_NOEXIST);
	bpf_map_update_elem(&sched_map, &key2, c, BPF_NOEXIST);
	bpf_map_update_elem(&sched_map, &key3, d, BPF_NOEXIST);
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
        .subtype = 14,
        .rsv = 0,
        .data = 0x03, // id
};


SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int op;
	int option_len = sizeof(mp_opt);
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
		memcpy(&option_buffer, &mp_opt, sizeof(int));
		rv = option_buffer;

		if (DEBUG) {
			char fmt3[] = "OPTIONS_WRITE: %x \n";
			bpf_trace_printk(fmt3, sizeof(fmt3), rv);
		}

		/* Disable option write callback */
		/*
		if (skops->state == BPF_TCP_ESTABLISHED)
			bpf_sock_ops_cb_flags_set(skops, skops->bpf_sock_ops_cb_flags
							 & ~BPF_SOCK_OPS_OPTION_WRITE_FLAG);
							 */
		break;
	case BPF_MPTCP_PARSE_OPTIONS:
		/* on receiving 3rd ack, this hook is called on meta_sk (TCP_SYN_RCV state)
		 * after mptcp_alloc_mpcb() and mptcp_init_scheduler() have been called.
		 */

		/* get current Scheduler */
		rv = bpf_getsockopt(skops, IPPROTO_TCP, MPTCP_SCHEDULER, sched_name, 20);

		char fmt11[] = "PARSE: tcp state:%u current SCHED: %s\n";
		bpf_trace_printk(fmt11, sizeof(fmt11), skops->state, sched_name);

		unsigned int sch_opt, sch_id;
		sch_opt = bpf_ntohl(skops->args[2]);
		/* Keep the last 8 bits */
		sch_id = sch_opt & 0x000000FF;

		//char fmt10[] = "PARSE_OPTIONS: raw %x swapped %x sch_id %x\n";
		//bpf_trace_printk(fmt10, sizeof(fmt10), skops->args[2], sch_opt, sch_id);

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
		bpf_trace_printk(fmt11, sizeof(fmt11), skops->state, sched_name, rv);
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		rv = bpf_getsockopt(skops, IPPROTO_TCP, MPTCP_SCHEDULER, sched_name, 20);

		char fmt22[] = "TCP_ESTABLISHED: current SCHED: %s\n";
		bpf_trace_printk(fmt22, sizeof(fmt22), sched_name);
		break;
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
