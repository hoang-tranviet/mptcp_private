// SPDX-License-Identifier: GPL-2.0

/* ndiffports-style program doesn't need to store local addrs and remote adds,
 * so should be called by regular user daemon:
 * sudo ./test_mptcp_user bpf_mptcp_delayed_pm.o
 */

#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <arpa/inet.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

#define THIN_CONN_SIZE 50000	 /* bytes */

struct bpf_map_def SEC("maps") done_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u32),
	.value_size = 4,
	.max_entries = 2,
};

static inline void update_map(__u32 key)
{
	int g = 1;

	bpf_map_update_elem(&done_map, &key, &g, BPF_ANY);
}

static inline int should_open(__u32 key)
{
	int *done = bpf_map_lookup_elem(&done_map, &key);
	if ((done) && (*done == 1))
		return 0;
	else
		return 1;
}

int _version SEC("version") = 1;

SEC("sockops")
int bpf_delayed_pm(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int v = 0;
	skops->reply = rv;

	/* Do not create subflows on server side */
	if (skops->local_port == 80)
		return 0;

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_USER_RECV_CB_FLAG);
		char fmt0[] = "SYN sent\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));
		break;
	case BPF_MPTCP_FULLY_ESTABLISHED:
		/* if this is not master sk, skip it */
		if (!skops->args[1])
			return 0;

		char fully[] = "%x: mptcp conn is fully established, is_master:%d\n";
		bpf_trace_printk(fully, sizeof(fully),  skops->mptcp_loc_token,
							skops->args[1]);
		break;
	case BPF_SOCK_OPS_USER_RECV:
		/* do not create new subflow for thin connection */
		/* For meta-sk: {data_}segs_in, {data_}segs_out are zeros */
		if (skops->bytes_received < THIN_CONN_SIZE)
			return 0;
		char dbg[] = "segs_out:%u  bytes_received:%lu bytes_acked:%lu \n\n";
		bpf_trace_printk(dbg, sizeof(dbg), skops->segs_out, skops->bytes_received, skops->bytes_acked);

		if (should_open(skops->mptcp_loc_token)) {
			/* when passing (NULL, 0): existing local and remote addresses
			 * will be used to set up new subflow
			 */
			rv = bpf_open_subflow( skops,  NULL, 0,  NULL, 0);

			char opensf[] = "open new subflow: ret: %d\n";
			bpf_trace_printk(opensf, sizeof(opensf), rv);

			/* mark the job done, clear the flag */
			update_map(skops->mptcp_loc_token);
			bpf_sock_ops_cb_flags_set(skops, 0);
		}
		break;
	default:
		rv = 0;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
