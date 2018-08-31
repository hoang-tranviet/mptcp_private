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

set -x

sysctl -w net.mptcp.mptcp_debug=1
#sysctl -w net.mptcp.mptcp_path_manager=ndiffports
sysctl -w net.mptcp.mptcp_path_manager=fullmesh

# Clean
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

#add delay and bw
# for client-to-server traffic
#$NS_BR tc qdisc add dev ethBr1 root handle 5:  tbf rate 5mbit  burst 10000 latency 200ms
#$NS_BR tc qdisc add dev ethBr3 root handle 5:  tbf rate 5mbit  burst 10000 latency 200ms
$NS_BR tc qdisc add dev ethBr1 handle 1: root   htb default 11
$NS_BR tc class add dev ethBr1 parent 1:    classid 1:11 htb rate 5mbps
$NS_BR tc qdisc add dev ethBr1 parent 1:11 handle 12:0 netem delay 40ms

$NS_BR tc qdisc add dev ethBr3 handle 1: root   htb default 11
$NS_BR tc class add dev ethBr3 parent 1:    classid 1:11 htb rate 5mbps
$NS_BR tc qdisc add dev ethBr3 parent 1:11 handle 12:0 netem delay 40ms
# will crash
#$NS_BR tc qdisc add dev ethBr1 parent 5:0  fq_codel limit 1000  target 3ms  interval 40ms

# for server-to-client traffic
#$NS_BR tc qdisc add dev ethBr2 root handle 6:  tbf rate 2mbit  burst 10000 latency 100ms
#$NS_BR tc qdisc add dev ethBr4 root handle 6:  tbf rate 2mbit  burst 10000 latency 100ms
$NS_BR tc qdisc add dev ethBr2 handle 1: root   htb default 11
$NS_BR tc class add dev ethBr2 parent 1:    classid 1:11 htb rate 5mbps
$NS_BR tc qdisc add dev ethBr2 parent 1:11 handle 12:0 netem delay 20ms

$NS_BR tc qdisc add dev ethBr4 handle 1: root   htb default 11
$NS_BR tc class add dev ethBr4 parent 1:    classid 1:11 htb rate 5mbps
$NS_BR tc qdisc add dev ethBr4 parent 1:11 handle 12:0 netem delay 20ms
# has no effect
#$NS_BR tc qdisc add dev ethBr2 parent 6:0  fq_codel limit 1000  target 3ms  interval 40ms

# has no effect
#$NS_BR tc qdisc add dev br root  fq_codel limit 1000  target 3ms  interval 40ms


$NS1 ethtool -K veth1 tso off gso off gro off  2> /dev/null
$NS2 ethtool -K veth2 tso off gso off gro off  2> /dev/null
$NS1 ethtool -K veth3 tso off gso off gro off  2> /dev/null
$NS2 ethtool -K veth4 tso off gso off gro off  2> /dev/null

serverIP="10.1.1.1"
serverPort=80
time=`date +%s`
dump_server=$time+"-server.pcap"
dump_client=$time+"-client.pcap"

$NS1  tcpdump -i veth1 -w dump_1_server &
$NS2  tcpdump -i veth2 -w dump_2_client &
$NS1  tcpdump -i veth3 -w dump_3_server &
$NS2  tcpdump -i veth4 -w dump_4_client &
#$NS_BR  tcpdump -i ethBr1 -w dump_server_br &
#$NS_BR  tcpdump -i ethBr2 -w dump_client_br &
#$NS_BR  tcpdump -i br -w dump_br &


$NS1  python3 -m http.server 80 &

sleep 1

# client will self-terminate in (-m) seconds
$NS2  curl $serverIP:$serverPort/vmlinux.o  -m 5  -o /dev/null

pkill tcpdump
pkill tcpdump
pkill tcpdump
pkill tcpdump

pkill python3
