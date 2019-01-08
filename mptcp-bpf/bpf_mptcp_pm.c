// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
//#include <linux/if_ether.h>
//#include <linux/if_arp.h>
//#include <linux/if_packet.h>
//#include <linux/ip.h>
//#include <linux/types.h>
//#include <linux/socket.h>
//#include <linux/tcp.h>
#include <arpa/inet.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

int _version SEC("version") = 1;

//BPF_TABLE("extern", u32, u32, addresses, 1);

#define SRC_IP4		0xC0A8210AU	// 192.168.33.10
#define DST_IP4		0x8268E62DU	// 130.104.230.45


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
		char fully[] = "mptcp conn is fully established: token:%x is_master:%d\n";
		bpf_trace_printk(fully, sizeof(fully),  skops->args[0],
							skops->args[1]);
		struct sockaddr_in loc_addr = { };
		struct sockaddr_in rem_addr = { };
/*
		inet_pton(AF_INET, "192.168.10.10", &loc_addr.sin_addr);
		inet_pton(AF_INET, "192.168.10.11", &rem_addr.sin_addr);
*/
		loc_addr.sin_addr.s_addr = bpf_htonl(SRC_IP4);
		rem_addr.sin_addr.s_addr = bpf_htonl(DST_IP4);
		loc_addr.sin_family = rem_addr.sin_family = AF_INET;
		loc_addr.sin_port = bpf_htons(0);
		rem_addr.sin_port = bpf_htons(80);
		rv = bpf_open_subflow(  skops,
					(struct sockaddr *)&loc_addr, sizeof(loc_addr),
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
