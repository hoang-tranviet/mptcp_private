#!/bin/bash

for cc in reno cubic vegas bbr; do
	rm dump* &> /dev/null
	echo "bpf_tcp_cc_${cc}.o"
	./test_tcp_user bpf_tcp_cc_${cc}.o -q
	mkdir -p trace-cc/$cc
	mv dump* trace-cc/$cc
done
cp my_net_cc.sh trace-cc/
