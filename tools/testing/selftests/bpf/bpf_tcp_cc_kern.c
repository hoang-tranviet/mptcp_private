// SPDX-License-Identifier: GPL-2.0
#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/tcp.h>
//#include <netinet/in.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "test_tcpbpf.h"


// cannot be larger than 5, weird
// error if it is 6: "invalid indirect read from stack off -44+5 size 6"
#define CC_LENGTH 5

struct bpf_map_def SEC("maps") cong_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = CC_LENGTH,
	.max_entries = 10,
};

static inline void init_map()
{
	__u32 key = 0;
	__u32 key2 = 1;
	__u32 key3 = 2;
	char *gp;
	char a[]="vegas";
	char b[]="reno";
	char c[]="bbr";

	/*
	gp = bpf_map_lookup_elem(&cong_map, &key);
	if (gp != NULL)
		bpf_map_update_elem(&cong_map, &key, a, BPF_ANY);
	else
	*/
		bpf_map_update_elem(&cong_map, &key, a, BPF_ANY);

	bpf_map_update_elem(&cong_map, &key2, b, BPF_EXIST);

	bpf_map_update_elem(&cong_map, &key3, c, BPF_EXIST);
}


/* From: stackoverflow.com/questions/2182002/\
         convert-big-endian-to-little-endian-in-c-without-using-provided-func */
static inline unsigned int swap(unsigned int num) {
	return __builtin_bswap32(num);
}

int _version SEC("version") = 1;


struct tcp_option {
	__u8 kind;
	__u8 len;
	__u16 data;
};

struct tcp_option opt = {
	.kind = 66, // random, just looks like CC
	.len = 4,   // of this option struct
	.data = 0x0200, // will be swapped for big-endian
};

SEC("sockops")
int bpf_testcb(struct bpf_sock_ops *skops)
{
	/*char cc[10][10]= {0};
	cc[0] = "reno";
	cc[1] = "cubic";
	cc[2] = "vegas";
	cc[3] = "bbr";
	cc[4] = "olia";*/
	//const char *cc[10] = {"reno","vegas", "bbr"};
	char cong[] = "reno\0";
	int rv = -1;
	int op;
	int option_len = sizeof(opt);
	int option_buffer;
	int header_len;
	char cc_name[20];

	op = (int) skops->op;

	char fmt20[] = "not found element a[0]\n";
	char fmt12[] = "CC in map: %s\n";

	init_map();


	switch (op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
		rv = bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_OPTION_WRITE_FLAG);
		char fmt0[] = "SYN sent\n";
		bpf_trace_printk(fmt0, sizeof(fmt0));
		break;
		/* Send new option from client side*/
	case BPF_TCP_OPTIONS_SIZE_CALC:
		/* args[1] is the second argument */
		if (skops->args[1] + option_len <= 40) {
			rv = option_len;
			//char fmt4[] = "OPTIONS_SIZE_CALC original:%d extend:%d B\n";
			//bpf_trace_printk(fmt4, sizeof(fmt4), skops->args[1], option_len);
		}
		else rv = 0;
		break;
	case BPF_TCP_OPTIONS_WRITE:
		/* put the struct option into the reply value */
		// skops->reply_long = opt;
		memcpy(&option_buffer, &opt, sizeof(int));
		rv = option_buffer;
		char fmt3[] = "OPTIONS_WRITE: %x \n";
		bpf_trace_printk(fmt3, sizeof(fmt3), rv);
		break;
	case BPF_TCP_PARSE_OPTIONS:
		/* get current CC */
		rv = bpf_getsockopt(skops, IPPROTO_TCP, TCP_CONGESTION, cc_name, 20);
		char fmt11[] = "CC: %s\n";
		bpf_trace_printk(fmt11, sizeof(fmt11), cc_name);

		/* get the parsed option, swap to little-endian */
		//__u32 cc_opt, cc_id;
		unsigned int cc_opt, cc_id;
		cc_opt = swap(skops->args[2]);
		/* Keep the last 16 bits */
		cc_id = cc_opt & 0x0000FFFF;

		char fmt10[] = "PARSE_OPTIONS: raw %x swapped %x cc_id %x\n";
		bpf_trace_printk(fmt10, sizeof(fmt10), skops->args[2], cc_opt, cc_id);


		char *con_str = bpf_map_lookup_elem(&cong_map, &cc_id);
		//memcpy(cong , cc[cc_id], 5);	// does not work :(
		/* bpf_setsockopt work with string
		 * but not with an element in a string array :(
		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_CONGESTION, cc[cc_id], sizeof(cc[cc_id]));
		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_CONGESTION, cc[cc_id], 5); */

		if (con_str != NULL) {
		//rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_CONGESTION, con_str, sizeof(con_str));
		rv = bpf_setsockopt(skops, IPPROTO_TCP, TCP_CONGESTION, con_str, CC_LENGTH);
		bpf_trace_printk(fmt12, sizeof(fmt12), con_str);
		}

		/* get new CC */
		rv = bpf_getsockopt(skops, IPPROTO_TCP, TCP_CONGESTION, cc_name, 20);
		bpf_trace_printk(fmt11, sizeof(fmt11), cc_name);
		break;
	default:
		rv = -1;
	}
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
