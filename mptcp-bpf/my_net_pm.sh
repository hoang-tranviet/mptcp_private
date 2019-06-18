#!/bin/bash

# set up netns + routing + traffic control
# _________________
# |                |
# |    server     ns1
# | .1.1     .3.3  |
# |_veth1___veth3__|
#    |        |
#  __|________|____
# | ethRt1  ethRt3 |
# | .1.11   .3.33  |
# |   \     /      |
# |    Router    nsRt
# |   /     \      |
# | .2.22   .4.44  |
# | ethRt2  ethRt4 |
# |__|________|____|
#  __|________|____
# | veth2   veth4  |
# | .2.2     .4.4  |
# |    client     ns2
# |________________|
#

NS1="ip netns exec ns1 "
NS2="ip netns exec ns2 "
NS_RT="ip netns exec nsRt "

#set -x

sysctl -w net.mptcp.mptcp_debug=0
sysctl -w net.mptcp.mptcp_path_manager=default

clean() {
$NS_RT ip link del ethRt1
$NS_RT ip link del ethRt2
$NS_RT ip link del ethRt3
$NS_RT ip link del ethRt4
$NS1 ip link del veth1
$NS2 ip link del veth2
$NS1 ip link del veth3
$NS2 ip link del veth4

ip netns del ns1
ip netns del ns2
ip netns del nsRt
}

clean &> /dev/null


# Add namespaces
ip netns add ns1
ip netns add ns2
ip netns add nsRt

# Add veths interfaces
ip link add veth1 type veth peer name ethRt1
ip link add veth2 type veth peer name ethRt2
ip link add veth3 type veth peer name ethRt3
ip link add veth4 type veth peer name ethRt4

#link veths
ip link set netns ns1 veth1
ip link set netns ns2 veth2
ip link set netns ns1 veth3
ip link set netns ns2 veth4
ip link set netns nsRt ethRt1
ip link set netns nsRt ethRt2
ip link set netns nsRt ethRt3
ip link set netns nsRt ethRt4

#assign mac's
$NS1  ifconfig veth1 hw ether 02:03:01:04:05:01
$NS2  ifconfig veth2 hw ether 02:03:01:04:05:02
$NS1  ifconfig veth3 hw ether 02:03:01:04:05:03
$NS2  ifconfig veth4 hw ether 02:03:01:04:05:04
$NS_RT ifconfig ethRt1 hw ether 02:03:06:05:07:01
$NS_RT ifconfig ethRt2 hw ether 02:03:06:05:07:02
$NS_RT ifconfig ethRt3 hw ether 02:03:06:05:07:03
$NS_RT ifconfig ethRt4 hw ether 02:03:06:05:07:04

#assign ip's
$NS1 ifconfig veth1 10.1.1.1/24 up
$NS2 ifconfig veth2 10.1.2.2/24 up
$NS1 ifconfig veth3 10.1.3.3/24 up
$NS2 ifconfig veth4 10.1.4.4/24 up

$NS_RT ip address add 127.0.0.1/8 dev lo
$NS_RT ip link set dev lo up

$NS_RT ifconfig ethRt1 10.1.1.11/24 up
$NS_RT ifconfig ethRt2 10.1.2.22/24 up
$NS_RT ifconfig ethRt3 10.1.3.33/24 up
$NS_RT ifconfig ethRt4 10.1.4.44/24 up

$NS_RT sysctl -w net.ipv4.ip_forward=1


#config source routing
#---------------------

# Server side
# creates two routing tables
$NS1  ip rule add from 10.1.1.1 table 1
$NS1  ip rule add from 10.1.3.3 table 3
# add per-table routes
$NS1 ip route add 10.1.1.0/24 dev veth1 scope link table 1
$NS1 ip route add default via 10.1.1.11 dev veth1 table 1
$NS1 ip route add 10.1.3.0/24 dev veth3 scope link table 3
$NS1 ip route add default via 10.1.3.33 dev veth3 table 3
# default route for normal traffic
$NS1 ip route add default scope global nexthop via 10.1.1.11 dev veth1
#$NS1 ip route add default scope global nexthop via 10.1.3.33 dev veth3

# Client side
# creates two routing tables
$NS2  ip rule add from 10.1.2.2 table 2
$NS2  ip rule add from 10.1.4.4 table 4
# add per-table routes
$NS2 ip route add 10.1.2.0/24 dev veth2 scope link table 2
$NS2 ip route add default via 10.1.2.22 dev veth2 table 2
$NS2 ip route add 10.1.4.0/24 dev veth4 scope link table 4
$NS2 ip route add default via 10.1.4.44 dev veth4 table 4
# default route for normal traffic
$NS2 ip route add default scope global nexthop via 10.1.2.22 dev veth2

#-------------------
#config routing done


#setup router
$NS_RT ip link set up dev ethRt1
$NS_RT ip link set up dev ethRt2
$NS_RT ip link set up dev ethRt3
$NS_RT ip link set up dev ethRt4

#add delay and bw
# for client-to-server traffic
$NS_RT tc qdisc add dev ethRt1   root handle 1:0    netem delay 5ms # loss 0.5%
$NS_RT tc qdisc add dev ethRt1   parent 1:1 handle 10:    tbf rate 40Mbit latency 1ms burst 80000

$NS_RT tc qdisc add dev ethRt3   root handle 1:0    netem delay 5ms # loss 0.5%
$NS_RT tc qdisc add dev ethRt3   parent 1:1 handle 10:    tbf rate 40Mbit latency 1ms burst 80000

# for server-to-client traffic
$NS_RT tc qdisc add dev ethRt2   root handle 1:0    netem delay 5ms # loss 0.5%
$NS_RT tc qdisc add dev ethRt2   parent 1:1 handle 10:    tbf rate 40Mbit latency 1ms burst 80000

$NS_RT tc qdisc add dev ethRt4   root handle 1:0    netem delay 5ms # loss 0.5%
$NS_RT tc qdisc add dev ethRt4   parent 1:1 handle 10:    tbf rate 40Mbit latency 1ms burst 80000


serverIP="10.1.1.1"
serverPort=80
time=`date +%s`
dump_server=$time+"-server.pcap"
dump_client=$time+"-client.pcap"

#$NS1  python3 -m http.server 80 &
$NS1 ./load_pm_user  bpf_mptcp_pm_server.o ./python-http-server.sh -q &

$NS1  tcpdump -i veth1 -w dump_1_server &
$NS2  tcpdump -i veth2 -w dump_2_client &
$NS1  tcpdump -i veth3 -w dump_3_server &
sleep 0.5


#$NS2 ./curl-2s-10KB.sh
$NS2 ./load_pm_user  bpf_mptcp_fullmesh.o ./curl-2s-10KB.sh &

sleep 1
$NS2 bpftool prog show
$NS2 bpftool map show
$NS2 bpftool cgroup tree
sleep 2
bpftool prog tracelog &

pkill tcpdump
#pkill tcpdump
#pkill tcpdump

pkill load_pm_user
pkill python3
pkill bpftool
