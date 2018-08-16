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


#define DELAY_REQUEST 1
#define BW_REQUEST    2

int _version SEC("version") = 1;


SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int op;
	int v = 0;

	op = (int) skops->op;

	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
	{
		char fmt0[] = "tcp connect\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));
		break;
	}
	case BPF_MPTCP_ADD_SOCK:
	{
		unsigned int id = skops->args[0];
		char fmt1[] = "subflow id: %u \n";
		bpf_trace_printk(fmt1, sizeof(fmt1), id);

		/* master subflow has id = 1 */
		if (id == 1) {
			int value;
			bpf_getsockopt(skops, IPPROTO_TCP,
				MPTCP_ACK_BYTES_THRESHOLD, &value, sizeof(value));
			char fmt2[] = "ack_bytes threshold: %u \n";
			bpf_trace_printk(fmt2, sizeof(fmt2), value);

			/* set threshold in bytes, if a data-ack does ack for new data
			 * more than this value, it will be reinjected on other subflows */
			value = 4000;
			rv = bpf_setsockopt(skops, IPPROTO_TCP,
				MPTCP_ACK_BYTES_THRESHOLD, &value, sizeof(value));

			bpf_getsockopt(skops, IPPROTO_TCP,
				MPTCP_ACK_BYTES_THRESHOLD, &value, sizeof(value));
			bpf_trace_printk(fmt2, sizeof(fmt2), value);

		}
		break;
	}
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
