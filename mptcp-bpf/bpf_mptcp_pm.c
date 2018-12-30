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
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

int _version SEC("version") = 1;

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
