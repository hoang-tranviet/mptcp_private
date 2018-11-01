#!/bin/bash
set -x
mkdir -p stress_test
killall iperf3 		&> /dev/null

prefix=''
if [ "$#" -eq 0 ]; then
	echo "No argument: Base test"
elif [ "$#" -eq 1 ]; then
	echo "1 argument: Option insertion test"
	prefix='insert-'
elif [ "$#" -eq 2 ]; then
	echo "2 argument: Option insertion/parsing test"
	prefix='insert-parse'
elif [ "$#" -eq 3 ]; then
	echo "3 argument: Option insertion/parsing + bpf_{get/set}sockopt test"
	prefix='insert-parse-sockopt-'
fi

for i in {0..9}; do
	iperf3 -s -1  -J		> stress_test/${prefix}server-${i}.json &
	iperf3 -c localhost -t 10 -J 	> stress_test/${prefix}client-${i}.json
done
