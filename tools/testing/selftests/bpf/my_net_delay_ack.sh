#!/bin/bash

set -x

sysctl -w net.mptcp.mptcp_enabled=0

serverIP="inlab"
serverPort=80
time=`date +%s`
dump_server=$time+"-server.pcap"
dump_client=$time+"-client.pcap"

$NS2  tcpdump -s 120 -i eth1 -w dump-client-$time &


sleep 1

netstat -s > netstat.before
# client will self-terminate in m seconds
curl $serverIP:$serverPort/32MB.rpm  -m 5  -o /dev/null
netstat -s > netstat.after

sleep 1

colordiff --unified netstat.before netstat.after

colordiff --unified netstat.before netstat.after > netstat-$time.diff

pkill tcpdump
