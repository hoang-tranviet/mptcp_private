/* Copyright (c) 2019 Viet-Hoang Tran */
#include <string.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

int _version SEC("version") = 1;

struct bpf_map_def SEC("maps") option_count = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(int),
	.max_entries = 2,
};

struct tcp_option {
	__u8 kind;
	__u8 len;
	__u16 data;
};

#define bpf_printk(fmt, ...)					\
({								\
	       char ____fmt[] = fmt;				\
	       bpf_trace_printk(____fmt, sizeof(____fmt),	\
				##__VA_ARGS__);			\
})

#define IW 5

SEC("sockops")
int test_tcp_option(struct bpf_sock_ops *skops)
{
	struct tcp_option opt = {
		.kind = 66, 	// arbitrary
		.len  = 4,   	// of this option struct
		.data = bpf_htons(IW),
	};

	__u32 option_buffer, tcp_options_size;
	__u32 rcv_opt, opt_val, key;
	int rv = 0;

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		rv = bpf_sock_ops_cb_flags_set(skops,
					BPF_SOCK_OPS_OPTION_WRITE_FLAG);
		break;
	case BPF_TCP_OPTIONS_SIZE_CALC:
		tcp_options_size = skops->args[1];
		if (tcp_options_size + sizeof(opt) <= 40)
			rv = sizeof(opt);
		else
			rv = 0;
		break;
	case BPF_TCP_OPTIONS_WRITE:
		/* put the struct option into the reply value */
		memcpy(&option_buffer, &opt, sizeof(int));
		rv = option_buffer;
		break;

	case BPF_SOCK_OPS_TCP_LISTEN_CB:
		rv = bpf_sock_ops_cb_flags_set(skops,
					BPF_SOCK_OPS_OPTION_PARSE_FLAG);
		break;
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		key = 0;
		opt_val = 0;
		bpf_map_update_elem(&option_count, &key, &opt_val, BPF_ANY);
		break;
	case BPF_TCP_PARSE_OPTIONS:
		rcv_opt = bpf_ntohl(skops->args[2]);

		/* Keep the first two bytes */
		opt_val = rcv_opt >> 16;
		bpf_printk("Parse option value: %x\n", opt_val);
		key = 1;
		bpf_map_update_elem(&option_count, &key, &opt_val, BPF_ANY);
		break;
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
