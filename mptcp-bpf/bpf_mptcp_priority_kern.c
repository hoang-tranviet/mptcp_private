// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/tcp.h>
//#include <netinet/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

struct bpf_map_def SEC("maps") flag_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = 4,
	.max_entries = 2,
};

static inline void update_flag_map(int flag)
{
	__u32 key = 0;
	int g = flag, *gp;

	bpf_map_update_elem(&flag_map, &key, &g,
		    BPF_ANY);
}

static inline int should_write()
{
	__u32 key = 0;
	int *should_write = bpf_map_lookup_elem(&flag_map, &key);
	if ((should_write) && (*should_write == 1))
		return 1;
	else
		return 0;
}

#define bswap_32(x) ((unsigned int)__builtin_bswap32(x))

#define MP_NEW_PRIO 11

#define DELAY_REQUEST 1
#define BW_REQUEST    2
//int should_write;	//global variable not valid

int _version SEC("version") = 1;

struct mptcp_option {
	__u8 kind;
	__u8 len;
	__u8 flag:4, subtype:4;
	__u8 data;
};


SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int op;
	int v = 0;
	int option_buffer;
	int header_len;

	op = (int) skops->op;

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		update_flag_map(0);
		char fmt0[] = "tcp connect callback\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));
		break;
	//case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	case BPF_MPTCP_ADD_SOCK:
	{
		unsigned int id = skops->args[0];
		unsigned int dev_type = skops->args[1];
		char fmt1[] = "subflow id: %u \t dev->type: %u\n";
		bpf_trace_printk(fmt1, sizeof(fmt1), id, dev_type);

		/* master subflow has id = 1 */
		if (id == 1) {
			int value = 1;
			/* other subflows will be in back up mode */
			rv = bpf_setsockopt(skops, IPPROTO_TCP,
					    MPTCP_BACKUP_SFS_MODE, &value, sizeof(value));
			/* Enable option write callback on this subflow */
			bpf_sock_ops_cb_flags_set( skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);
			rv = 1;
		}
		else {
			update_flag_map(1);
			rv = 10;
		}
		break;
	}
	case BPF_TCP_OPTIONS_SIZE_CALC:
		{
		int option_len = sizeof(struct mptcp_option);

		/* args[1] is the second argument */
		if (should_write() &&
		   (skops->args[1] + option_len <= 40)) {
			rv = option_len;
			char fmt4[] = "BPF_TCP_OPTIONS_SIZE_CALC \
					\t original:%d extend:%d bytes more\n";
			bpf_trace_printk(fmt4, sizeof(fmt4), skops->args[1], option_len);
			break;
		}
		char fmt00[] = "ignore write\n";
		bpf_trace_printk(fmt00, sizeof(fmt00));
		rv = 0;
		break;
		}
	case BPF_MPTCP_OPTIONS_WRITE:
		{
		if (should_write()) {
			/* put the struct option into the reply value */
			struct mptcp_option mp_opt = {
				.kind = 30, // MPTCP code
				.len = 4,
				.subtype = MP_NEW_PRIO,
				.flag = DELAY_REQUEST,
				.data = 0x05,	// in ms
			};
			char fmt3[] = "BPF_MPTCP_OPTIONS_WRITE \n";
			bpf_trace_printk(fmt3, sizeof(fmt3));
			// skops->reply_long = mp_opt;
			memcpy(&option_buffer, &mp_opt, sizeof(int));
			rv = option_buffer;
			break;
		}
		rv = 0;
		break;
		}
	case BPF_MPTCP_PARSE_OPTIONS:
		{
		unsigned int op;
		unsigned int value;

		/* This is on subflow or meta socket? */
		rv = bpf_getsockopt(skops, IPPROTO_TCP,
					    MPTCP_RTT_THRESHOLD,
					    &value, sizeof(value));
		char fmt11[] = "RTT threshold = %d \n";
		bpf_trace_printk(fmt11, sizeof(fmt11), value);

		/* get the parsed option, swap to little-endian */
		unsigned int option = bswap_32(skops->args[2]);
		char fmt10[] = "BPF_MPTCP_PARSE_OPTIONS: %d, %d, %x\n";
		bpf_trace_printk(fmt10, sizeof(fmt10),  skops->args[0], skops->args[1],
							option);
		unsigned int op_code = (option & 0x0000F000) >> 12;
		unsigned int flags   = (option & 0x00000F00) >> 8;

		/* Keep the last 8 bits */
		value = option & 0x000000FF;
		char fmt12[] = "op_code: %u flags: %x, \t value: %d \n";
		bpf_trace_printk(fmt12, sizeof(fmt12), op_code, flags, value);

		if (op_code != MP_NEW_PRIO)
			break;

		if (flags == DELAY_REQUEST)
			op = MPTCP_RTT_THRESHOLD;
		else
			break;

		rv = bpf_setsockopt(skops, IPPROTO_TCP,
					    op, &value, sizeof(value));

		rv = bpf_getsockopt(skops, IPPROTO_TCP,
					    op, &value, sizeof(value));
		bpf_trace_printk(fmt11, sizeof(fmt11), value);
		break;
		}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
