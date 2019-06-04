// SPDX-License-Identifier: GPL-2.0

/* BPF PM to recreate subflow when it is closed due to TCP RST or timeout
 * This helps to deal with CGNAT timeout that reset the TCP subflow,
 * or to deal with middlebox's throttling on elephant connection,
 * or to avoid the sniffers by swiching the subflow...
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

	switch (skops->op) {
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
		break;
	case BPF_MPTCP_FULLY_ESTABLISHED:
		/* if this is not master sk, skip it */
		if (!skops->args[1])
			return 0;

		char fully[] = "mptcp conn is fully established: token:%x is_master:%d\n";
		bpf_trace_printk(fully, sizeof(fully),  skops->mptcp_loc_token,
							skops->args[1]);
		/* when passing (NULL, 0): existing local and remote addresses
		 * will be used to set up new subflow
		rv = bpf_open_subflow( skops,  NULL, 0,  NULL, 0);

		char opensf[] = "open new subflow: ret: %d\n";
		bpf_trace_printk(opensf, sizeof(opensf), rv);
		 */
		break;
	case BPF_SOCK_OPS_STATE_CB:
	{
		/* skops->args[0] is negated (1 -> -1) in BPF context.
		 * The state is correct in main kernel, before and after passing args.  Why? */
		char state[] = "TCP state from: %d to %d\n";
		bpf_trace_printk(state, sizeof(state), skops->args[0], skops->args[1]);
		if (skops->args[1] == BPF_TCP_CLOSE) {
			rv = bpf_open_subflow( skops,  NULL, 0,  NULL, 0);
			char opensf[] = "recreate subflow: ret: %d\n";
			bpf_trace_printk(opensf, sizeof(opensf), rv);
		}

		break;
	}
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
