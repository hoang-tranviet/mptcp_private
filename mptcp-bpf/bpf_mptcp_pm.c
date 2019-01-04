// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

int _version SEC("version") = 1;

#define SRC_IP4		0xC0A8210AU	// 192.168.33.10
#define DST_IP4		0x8268E62DU	// 130.104.230.45
#define DST_IP4		0x8268E48CU	// 130.104.228.140

struct bpf_map_def SEC("maps") sockaddr_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct sockaddr_in),
	.max_entries = 100,
};


SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int op;
	int v = 0;

	op = (int) skops->op;

	switch (op) {
	case BPF_MPTCP_NEW_SESSION:
	{
		char snew[] = "%x: new mptcp connection\n";
		bpf_trace_printk(snew, sizeof(snew), skops->mptcp_loc_token);
		break;
	}
	case BPF_MPTCP_FULLY_ESTABLISHED:
	{
		char fully[] = "%x: mptcp conn is fully established, is_master:%d\n";
		bpf_trace_printk(fully, sizeof(fully),  skops->args[0],
							skops->args[1]);
		// this is not master sk, then skip it
		if (!skops->args[1])
			break;

		struct sockaddr_in *local_addr;
		struct sockaddr_in rem_addr = { };

		int key = 2;
		local_addr = bpf_map_lookup_elem(&sockaddr_map, &key);
		if (!local_addr)
			// without this check, verifier will reject
			return 0;
		char lookup[] = "local address: %u %x \n";
		bpf_trace_printk(lookup, sizeof(lookup),
				 bpf_ntohs(local_addr->sin_port),
				 bpf_ntohl(local_addr->sin_addr.s_addr));

		rem_addr.sin_addr.s_addr = bpf_htonl(DST_IP4);
		rem_addr.sin_family = AF_INET;
		rem_addr.sin_port = bpf_htons(80);

		/* when passing (NULL, 0):
		 * existing local and remote addresses will be used
		 * to set up new subflow, useful to set up ndiffports
		 */
		rv = bpf_open_subflow( skops,  NULL, 0,  NULL, 0);

		/* open new subflow on desired local and remote addresses
		 * set one end as (NULL, 0) if want to use existing address
		 */
		rv = bpf_open_subflow( skops,
				(struct sockaddr *)local_addr, sizeof(struct sockaddr_in),
				(struct sockaddr *)&rem_addr, sizeof(rem_addr));
		char opensf[] = "open new subflow: ret: %d\n";
		bpf_trace_printk(opensf, sizeof(opensf), rv);
		break;
	}
	case BPF_MPTCP_ADD_SOCK:
	{
		unsigned int id = skops->args[0];
		char fmt1[] = "%x: SYN-ACK arrived: subflow id: %u \n";
		bpf_trace_printk(fmt1, sizeof(fmt1), skops->mptcp_loc_token, id);
		break;
	}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
