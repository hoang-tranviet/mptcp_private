#!/bin/bash

# set up netns + bridge to use traffic control
# _________________
# |                |
# |    server     ns1
# | .1.1     .3.3  |
# |_veth1___veth3__|
#    |        |
#  __|________|____
# | ethBr1  ethBr3 |
# |   \     /      |
# |    Bridge    nsBr
# |   /     \      |
# | ethBr2  ethBr4 |
# |__|________|____|
#  __|________|____
# | veth2   veth4  |
# | .1.2     .3.4  |
# |    client     ns2
# |________________|
#

NS1="ip netns exec ns1 "
NS2="ip netns exec ns2 "
NS_BR="ip netns exec nsBr "

#set -x

sysctl -w net.mptcp.mptcp_enabled=1
sysctl -w net.mptcp.mptcp_debug=1

# temp disable additional sf to debug
sysctl -w net.mptcp.mptcp_path_manager=fullmesh

# Clean
function clean() {
	$NS_BR ip link del ethBr1
	$NS_BR ip link del ethBr2
	$NS_BR ip link del ethBr3
	$NS_BR ip link del ethBr4
	$NS_BR ip link del dev br
	$NS1 ip link del veth1
	$NS2 ip link del veth2
	$NS1 ip link del veth3
	$NS2 ip link del veth4

	ip netns del ns1
	ip netns del ns2
	ip netns del nsBr
}

clean &> /dev/null

# Add namespaces
ip netns add ns1
ip netns add ns2
ip netns add nsBr

# Add veths interfaces
ip link add veth1 type veth peer name ethBr1
ip link add veth2 type veth peer name ethBr2
ip link add veth3 type veth peer name ethBr3
ip link add veth4 type veth peer name ethBr4

#link veths
ip link set netns ns1 veth1
ip link set netns ns2 veth2
ip link set netns ns1 veth3
ip link set netns ns2 veth4
ip link set netns nsBr ethBr1
ip link set netns nsBr ethBr2
ip link set netns nsBr ethBr3
ip link set netns nsBr ethBr4

#assign mac's
$NS1  ifconfig veth1 hw ether 02:03:01:04:05:01
$NS2  ifconfig veth2 hw ether 02:03:01:04:05:02
$NS1  ifconfig veth3 hw ether 02:03:01:04:05:03
$NS2  ifconfig veth4 hw ether 02:03:01:04:05:04
$NS_BR ifconfig ethBr1 hw ether 02:03:06:05:07:01
$NS_BR ifconfig ethBr2 hw ether 02:03:06:05:07:02
$NS_BR ifconfig ethBr3 hw ether 02:03:06:05:07:03
$NS_BR ifconfig ethBr4 hw ether 02:03:06:05:07:04

#assign ip's
$NS1 ifconfig veth1 10.1.1.1/24 up
$NS2 ifconfig veth2 10.1.1.2/24 up
$NS1 ifconfig veth3 10.1.3.3/24 up
$NS2 ifconfig veth4 10.1.3.4/24 up

#config source routing
#---------------------

# Server side
# creates two routing tables
$NS1  ip rule add from 10.1.1.1 table 1
$NS1  ip rule add from 10.1.3.3 table 3
# add per-table routes
$NS1 ip route add 10.1.1.0/24 dev veth1 scope link table 1
$NS1 ip route add default via 10.1.1.2 dev veth1 table 1
$NS1 ip route add 10.1.3.0/24 dev veth3 scope link table 3
$NS1 ip route add default via 10.1.3.4 dev veth3 table 3
# default route for normal traffic
$NS1 ip route add default scope global nexthop via 10.1.1.2 dev veth1
#$NS1 ip route add default scope global nexthop via 10.1.3.4 dev veth3

# Client side
# creates two routing tables
$NS2  ip rule add from 10.1.1.2 table 1
$NS2  ip rule add from 10.1.3.4 table 3
# add per-table routes
$NS2 ip route add 10.1.1.0/24 dev veth2 scope link table 1
$NS2 ip route add default via 10.1.1.1 dev veth2 table 1
$NS2 ip route add 10.1.3.0/24 dev veth4 scope link table 3
$NS2 ip route add default via 10.1.3.3 dev veth4 table 3
# default route for normal traffic
$NS2 ip route add default scope global nexthop via 10.1.1.1 dev veth2

#-------------------
#config routing done


#setup bridge
brctl addbr br
ip link del dev br
$NS_BR brctl addbr br
$NS_BR brctl addif br ethBr1
$NS_BR ip link set up dev ethBr1
$NS_BR brctl addif br ethBr2
$NS_BR ip link set up dev ethBr2
$NS_BR brctl addif br ethBr3
$NS_BR ip link set up dev ethBr3
$NS_BR brctl addif br ethBr4
$NS_BR ip link set up dev ethBr4

$NS_BR ip link set up dev br

# path 1-2, client-to-server
$NS1 tc qdisc add dev veth1   root tbf rate 2Mbit latency 1ms burst 4000
$NS_BR tc qdisc add dev ethBr2   root handle 1:0    netem delay 5ms  #loss 0.5%


# path 3-4, client-to-server
$NS1 tc qdisc add dev veth3   root tbf rate 2Mbit latency 1ms burst 4000
$NS_BR tc qdisc add dev ethBr4   root handle 1:0    netem delay 5ms  #loss 0.5%


# path 2-1, server-to-client
$NS2 tc qdisc add dev veth2  root  tbf rate 2Mbit latency 1ms burst 4000
$NS_BR tc qdisc add dev ethBr1   root handle 1:0    netem delay 5ms  #loss 0.5%


# path 4-3, server-to-client
$NS2 tc qdisc add dev veth4   root tbf rate 2Mbit latency 1ms burst 4000
$NS_BR tc qdisc add dev ethBr3   root handle 1:0    netem delay 5ms  #loss 0.5%


serverIP="10.1.1.1"
serverPort=80

#$NS1  tcpdump -i veth1 -w dump_1_server &
#$NS2  tcpdump -i veth2 -w dump_2_client tcp &
#$NS1  tcpdump -i veth3 -w dump_3_server &
#$NS2  tcpdump -i veth4 -w dump_4_client tcp &
$NS1   tcpdump -i any   -w dump_server   tcp &
$NS2   tcpdump -i any   -w dump_client   tcp &


# make sure that we set limit-rate to 50K in nginx
sudo nginx -s stop
$NS1  sudo nginx

$NS2 ip route get $serverIP
$NS2 traceroute $serverIP

sleep 1

# client will self-terminate in (-m) seconds
# do NOT use --limit-rate on the receiver!
# curl will delay the ACK --> increase RTT
$NS2  curl $serverIP:$serverPort/file.txt  -m 21  -o /dev/null &

sleep 10
# increase the delay to 100 ms
$NS_BR tc qdisc del dev ethBr2   root handle 1:0    netem delay 5ms
$NS_BR tc qdisc add dev ethBr2   root handle 1:0    netem delay 50ms
$NS_BR tc qdisc del dev ethBr1   root handle 1:0    netem delay 5ms
$NS_BR tc qdisc add dev ethBr1   root handle 1:0    netem delay 50ms


sleep 11

$NS_BR tc -s qdisc show dev ethBr1
$NS_BR tc -s qdisc show dev ethBr3
pkill tcpdump
pkill tcpdump
pkill tcpdump
pkill tcpdump

pkill python3
