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
	.max_entries = 10,
};

struct add_addrs {
	/* remote address IDs per connection... */
	__u32 id1;
	__u32 id2;
	__u32 id3;
	__u32 id4;
	/* ... and their corresponding IP addresses */
	__u32 ip1;
	__u32 ip2;
	__u32 ip3;
	__u32 ip4;
};

struct bpf_map_def SEC("maps") add_addr_map = {
	/* BPF_MAP_TYPE_ARRAY doesn't work, don't know why */
	.type = BPF_MAP_TYPE_HASH,
	.key_size   = sizeof(__u32),
	.value_size = sizeof(struct add_addrs),
	.max_entries = 100,
};

SEC("sockops")
int bpf_fullmesh(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int op;
	int v = 0;

	if (skops->local_port == 80)
		return 0;

	__u32 token = skops->mptcp_loc_token;

	op = (int) skops->op;

	switch (op) {
	case BPF_MPTCP_NEW_SESSION:
	{
		char snew[] = "client: new mptcp connection: %x\n";
		bpf_trace_printk(snew, sizeof(snew), token);

		struct add_addrs addrs;
		/* Zero initialize the list */
		memset(&addrs, 0, sizeof(struct add_addrs));

		rv = bpf_map_update_elem(&add_addr_map, &token, &addrs, BPF_ANY);

		break;
	}
	case BPF_MPTCP_FULLY_ESTABLISHED:
	{
		char fully[] = "client: fully established, is_master:%d\n";
		bpf_trace_printk(fully, sizeof(fully), skops->args[1]);

		// this is not master sk, then skip it
		if (!skops->args[1])
			break;

		struct sockaddr_in *local_addr;

		int key = 2;
		local_addr = bpf_map_lookup_elem(&sockaddr_map, &key);
		if (!local_addr)
			// without this check, verifier will reject
			return 0;
		char lookup[] = "client: get local address: %x %u \n";
		bpf_trace_printk(lookup, sizeof(lookup),
				 bpf_ntohl(local_addr->sin_addr.s_addr),
				 bpf_ntohs(local_addr->sin_port));
		/* ARRAY_MAP: elements are initialized with empty values by default
		 * ignore them */
		if (local_addr->sin_addr.s_addr == 0)
			return 0;

		/* when passing (NULL, 0):
		 * existing local or remote addresses will be used
		 * to set up new subflow, useful to set up ndiffports
		 */
		rv = bpf_open_subflow( skops,
				(struct sockaddr *)local_addr, sizeof(struct sockaddr_in),
				NULL, 0);
		char opensf[] = "client: open new subflow: ret: %d\n";
		bpf_trace_printk(opensf, sizeof(opensf), rv);
		break;
	}
	case BPF_MPTCP_SYNACK_ARRIVED:
	{
		unsigned int id = skops->args[0];
		char fmt1[] = "client: SYN-ACK arrived: subflow id: %u \n";
		bpf_trace_printk(fmt1, sizeof(fmt1), id);
		break;
	}
	case BPF_MPTCP_ADD_RADDR:
	{
		char add[] = "client: received new addaddr: %x port %d id %d\n";
		bpf_trace_printk(add, sizeof(add),
				bpf_htonl(skops->args[0]),
				bpf_htonl(skops->args[1]),
				skops->args[2]);

		__u32 ip = skops->args[0];
		__u32 id = skops->args[2];
		__u32 key = token;

		/* open subflows towards new remote address */
		struct sockaddr_in rem_addr = {
			.sin_addr.s_addr = ip,
			.sin_family = AF_INET,
			.sin_port = bpf_htons(80),
		};
		rv = bpf_open_subflow( skops,
				NULL, 0,
				(struct sockaddr *)&rem_addr, sizeof(rem_addr));
		char opensf[] = "client: open subflow ret: %d\n";
		bpf_trace_printk(opensf, sizeof(opensf), rv);

		/* open subflow on second local IP */
		struct sockaddr_in *local_addr;

		key = 2;
		local_addr = bpf_map_lookup_elem(&sockaddr_map, &key);
		if (!local_addr)
			return 0;
		rv = bpf_open_subflow( skops,
				(struct sockaddr *)local_addr, sizeof(struct sockaddr_in),
				(struct sockaddr *)&rem_addr, sizeof(rem_addr));

		/* add to current add_addrs list */
		struct add_addrs *addrs = bpf_map_lookup_elem(&add_addr_map, &key);

		if (!addrs) {
			char emp[] = "client: add_addr list not found\n";
			bpf_trace_printk(emp, sizeof(emp));
			break;
		}

		/* if received IP already in the list, skip it */
		if (addrs->ip1 == ip || addrs->ip2 == ip
		 || addrs->ip3 == ip || addrs->ip4 == ip) {
			char inlist[] = "IP already in the list, skip it";
			bpf_trace_printk(inlist, sizeof(inlist));
			break;
		}
		else if (addrs->ip1 == 0) {
			addrs->id1 = id;
			addrs->ip1 = ip;
		}
		else if (addrs->ip2 == 0) {
			addrs->id2 = id;
			addrs->ip2 = ip;
		}
		else if (addrs->ip3 == 0) {
			addrs->id3 = id;
			addrs->ip3 = ip;
		}
		else if (addrs->ip4 == 0) {
			addrs->id4 = id;
			addrs->ip4 = ip;
		}
		else {
			char full[] = "add_addr list is full!\n";
			bpf_trace_printk(full, sizeof(full));}

		break;
	}
	case BPF_MPTCP_REM_RADDR:
	{
		__u32 id = skops->args[1];

		char rem[] = "client: remove raddr id: %d\n";
		bpf_trace_printk(rem, sizeof(rem), id);

		struct add_addrs *addrs = bpf_map_lookup_elem(&add_addr_map, &token);

		if (!addrs)
			break;

		char addrlist[] = " \t raddr list: %pr\n";
		bpf_trace_printk(addrlist, sizeof(addrlist), addrs);

		/* remove addr from list,
		 * not 'else' here since id = 0 is both a valid value and the emptiness */
		if (addrs->id1 == id)
			addrs->id1 = addrs->ip1 = 0;
		if (addrs->id2 == id)
			addrs->id2 = addrs->ip2 = 0;
		if (addrs->id3 == id)
			addrs->id3 = addrs->ip3 = 0;
		if (addrs->id4 == id)
			addrs->id4 = addrs->ip4 = 0;


		bpf_trace_printk(addrlist, sizeof(addrlist), addrs);
		break;
	}

	case BPF_MPTCP_CLOSE_SESSION:
	{
		struct add_addrs *addrs = bpf_map_lookup_elem(&add_addr_map, &token);

		char close[] = "client: close mp conn, removing add_addrs list\n";
		bpf_trace_printk(close, sizeof(close), token);

		rv = bpf_map_delete_elem(&add_addr_map, &token);

		break;
	}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
