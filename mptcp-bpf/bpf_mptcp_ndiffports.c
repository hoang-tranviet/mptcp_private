// SPDX-License-Identifier: GPL-2.0

/* Note that ndiffports program doesn't need to store local addrs and remote adds,
 * so should be called by regular user daemon:
 * sudo ./test_mptcp_user bpf_mptcp_ndiffports.o
 */

#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

int _version SEC("version") = 1;

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int v = 0;
	skops->reply = rv;

	/* Do not create subflows on server side */
	if (skops->local_port == 80)
		return 0;

	if (skops->op ==  BPF_MPTCP_FULLY_ESTABLISHED) {
		char fully[] = "mptcp conn is fully established: token:%x is_master:%d\n";
		bpf_trace_printk(fully, sizeof(fully),  skops->args[0],
							skops->args[1]);
		/* if this is not master sk, skip it */
		if (!skops->args[1])
			return 0;

		/* when passing (NULL, 0): existing local and remote addresses
		 * will be used to set up new subflow
		 */
		rv = bpf_open_subflow( skops,  NULL, 0,  NULL, 0);

		char opensf[] = "open new subflow: ret: %d\n";
		bpf_trace_printk(opensf, sizeof(opensf), rv);
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
