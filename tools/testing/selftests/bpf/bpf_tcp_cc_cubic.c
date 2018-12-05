/* Copyright (c) 2017 Viet-Hoang Tran */

#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"

#define CC_LENGTH 5

struct bpf_map_def SEC("maps") cong_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = CC_LENGTH,
	.max_entries = 10,
};

static inline void init_map()
{
	__u32 key0 = 0;
	__u32 key1 = 1;
	__u32 key2 = 2;
	__u32 key3 = 3;
	char a[]="vegas";
	char b[]="reno";
	char c[]="bbr";
	char d[]="cubic";

	bpf_map_update_elem(&cong_map, &key0, a, BPF_ANY);
	bpf_map_update_elem(&cong_map, &key1, b, BPF_ANY);
	bpf_map_update_elem(&cong_map, &key2, c, BPF_EXIST);
	bpf_map_update_elem(&cong_map, &key3, d, BPF_EXIST);
}

int _version SEC("version") = 1;

struct tcp_option {
	__u8 kind;
	__u8 len;
	__u16 data;
};

struct tcp_option opt = {
	.kind = 66, 	// arbitrary
	.len = 4,   	// of this option struct
	.data = 0x0300, // Cubic
};

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int option_len = sizeof(opt);
	int option_buffer;

	int op = (int) skops->op;

	init_map();

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);
		break;
	case BPF_TCP_OPTIONS_SIZE_CALC:
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
		} else rv = 0;
		break;
	case BPF_TCP_OPTIONS_WRITE:
		memcpy(&option_buffer, &opt, sizeof(int));
		rv = option_buffer;
		break;
	case BPF_TCP_PARSE_OPTIONS:{
		unsigned int cc_opt, cc_id;
		cc_opt = __builtin_bswap32(skops->args[2]);
		cc_id = cc_opt & 0x0000FFFF;

		char *con_str = bpf_map_lookup_elem(&cong_map, &cc_id);

		if (con_str != NULL)
			rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_CONGESTION, con_str, CC_LENGTH);
		break;
	}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
