// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

int _version SEC("version") = 1;

struct bpf_map_def SEC("maps") server_addr_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct sockaddr_in),
	.max_entries = 10,
};


SEC("sockops")
int bpf_addaddr_server(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int v = 0;

	int op = (int) skops->op;
	unsigned int token = skops->mptcp_loc_token;

	char dbg[] = "server: call op: %d \n";
	bpf_trace_printk(dbg, sizeof(dbg), op);

	/* run on server only */
	if (skops->local_port != 80)
		return 0;

	switch (op) {
	case BPF_MPTCP_FULLY_ESTABLISHED:
		/* skip master sk */
		if (!skops->args[1])
			break;

		char fully[] = "server: mpp conn is fully established, is_master:%d\n";
		bpf_trace_printk(fully, sizeof(fully),  skops->args[1]);
		break;
	case BPF_MPTCP_ADDR_SIGNAL:
	{
		unsigned int size = skops->args[1];
		struct sockaddr_in *local_addr;

		char deb[] = "server: ADDR_SIGNAL: size: %u \n";
		bpf_trace_printk(deb, sizeof(deb), size);

		int id = 2;
		local_addr = bpf_map_lookup_elem(&server_addr_map, &id);
		if (!local_addr)
			return 0;
		char fmt1[] = "server: to send add_addr: %x, id: %d \n";
		bpf_trace_printk(fmt1, sizeof(fmt1),
				 bpf_ntohl(local_addr->sin_addr.s_addr), id);

		rv = bpf_mptcp_addr_signal(skops, id,
					(struct sockaddr *)local_addr,
					sizeof(struct sockaddr_in),
					1);
		break;
	}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
