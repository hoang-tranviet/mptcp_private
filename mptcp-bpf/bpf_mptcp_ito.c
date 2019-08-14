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
//#include <netinet/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"

/* This bpf program lets a host (via an MPTCP option)
 * to request/announce a MPTCP-level Inactivity Timeout 
 */

int _version SEC("version") = 1;

// in seconds
#define ITO 240
#define DEBUG 0

struct mptcp_option {
	__u8 kind;
	__u8 len;
	__u8 rsv:4, subtype:4;
	__u8 data;
};

struct mptcp_option mp_opt = {
	.kind = 30, // MPTCP code
	.len = 4,
	.subtype = 15,
	.rsv = 0,
	.data = ITO,
};

SEC("sockops")
int mptcp_ito(struct bpf_sock_ops *skops)
{
	int rv = -1;
	int op;
	int v = 0;
	int option_len = sizeof(mp_opt);
	unsigned int ito;
	int ka = 1;


	op = (int) skops->op;

	switch (op) {
	/* server side */
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	{
		char fmt0[] = "server established\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));

		/*
		ito = ITO;
		rv = bpf_setsockopt(skops, IPPROTO_MPTCP, MPTCP_KILL_ON_IDLE, &ka, sizeof(ka));
		rv = bpf_setsockopt(skops, IPPROTO_MPTCP, SO_KEEPALIVE, &ka, sizeof(ka));
		rv = bpf_setsockopt(skops, IPPROTO_MPTCP, TCP_KEEPIDLE, &ito, sizeof(ito));
		*/

		rv = bpf_getsockopt(skops, IPPROTO_MPTCP, TCP_KEEPIDLE, &ito, sizeof(ito));
		char fmt00[] = "server: meta ito %d  token %x\n";
		bpf_trace_printk(fmt00, sizeof(fmt00), ito, skops->mptcp_loc_token);
		break;
	}
	case BPF_MPTCP_SYNACK_ARRIVED:
	{
		unsigned int id = skops->args[0];
		unsigned int dev_type = skops->args[1];
		char fmt1[] = "Client: rcv SYN-ACK on sf %u \t dev->type %u  token %x\n";
		bpf_trace_printk(fmt1, sizeof(fmt1), id, dev_type, skops->mptcp_loc_token);

		/* Enable option write callback on this subflow */
		bpf_sock_ops_cb_flags_set( skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);

		ito = ITO;
		rv = bpf_setsockopt(skops, IPPROTO_MPTCP, MPTCP_KILL_ON_IDLE, &ka, sizeof(ka));
		rv = bpf_setsockopt(skops, IPPROTO_MPTCP, SO_KEEPALIVE, &ka, sizeof(ka));
		rv = bpf_setsockopt(skops, IPPROTO_MPTCP, TCP_KEEPIDLE, &ito, sizeof(ito));
		rv = bpf_getsockopt(skops, IPPROTO_MPTCP, TCP_KEEPIDLE, &ito, sizeof(ito));
		char fmt00[] = "client: ito %d \n";
		bpf_trace_printk(fmt00, sizeof(fmt00), ito);
		break;
	}
        case BPF_MPTCP_NEW_SESSION:
		/* meta sk level, not interfere with option write flags */
		bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
		break;

	case BPF_TCP_OPTIONS_SIZE_CALC:
		/* args[1] is the second argument */
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
			char fmt4[] = "OPTIONS_SIZE   original:%d add:%d bytes\n";
			bpf_trace_printk(fmt4, sizeof(fmt4), skops->args[1], option_len);
		}
		else rv = 0;
		break;
	case BPF_MPTCP_OPTIONS_WRITE:
	{
		char fmt3[] = "OPTIONS_WRITE on sf %u\n\n";
		bpf_trace_printk(fmt3, sizeof(fmt3), skops->args[1]);

		int option_buffer;
		memcpy(&option_buffer, &mp_opt, sizeof(int));
		rv = option_buffer;

		bpf_sock_ops_cb_flags_set( skops, 0);
		break;
	}
	case BPF_MPTCP_PARSE_OPTIONS:
	{
		char fmt00[] = "server: ito %d \n";
		rv = bpf_getsockopt(skops, IPPROTO_MPTCP, TCP_KEEPIDLE, &ito, sizeof(ito));
		bpf_trace_printk(fmt00, sizeof(fmt00), ito);

		unsigned int option = bpf_ntohl(skops->args[2]);
		/* Keep the last 8 bits */
		ito = (option & 0x000000FF);

		char fmt10[] = "parse options: %x,     ito: %d s\n";
		bpf_trace_printk(fmt10, sizeof(fmt10), option, ito);

		rv = bpf_setsockopt(skops, IPPROTO_MPTCP, MPTCP_KILL_ON_IDLE, &ka, sizeof(ka));
		rv = bpf_setsockopt(skops, IPPROTO_MPTCP, SO_KEEPALIVE, &ka, sizeof(ka));
		rv = bpf_setsockopt(skops, IPPROTO_MPTCP, TCP_KEEPIDLE, &ito, sizeof(ito));

		rv = bpf_getsockopt(skops, IPPROTO_MPTCP, TCP_KEEPIDLE, &ito, sizeof(ito));
		bpf_trace_printk(fmt00, sizeof(fmt00), ito);

		break;
	}
        case BPF_SOCK_OPS_STATE_CB:
		if (DEBUG) {
			char state[] = "token %x: TCP state from: %u to %u\n";
			bpf_trace_printk(state, sizeof(state), skops->mptcp_loc_token,
				       skops->args[0], skops->args[1]);
		}
                break;

	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
