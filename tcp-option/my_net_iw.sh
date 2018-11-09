#!/bin/bash

# set up netns + bridge to use traffic control
#
# server is in ns1
# |_veth1________|
#    |
#  __|___________
# | ethBr1       |
# |   \          |
# |   Bridge    nsBr
# |   /          |
# | ethBr2       |
# |__|___________|
#  __|___________
# | veth2        |
# client is in ns2

NS1="ip netns exec ns1 "
NS2="ip netns exec ns2 "
NS_BR="ip netns exec nsBr "

#set -x

sysctl -w net.mptcp.mptcp_enabled=0
sysctl -w net.ipv4.tcp_congestion_control=reno
#sysctl -w net.ipv4.tcp_congestion_control=cubic

# Clean
$NS_BR ip link del ethBr1
$NS_BR ip link del ethBr2
$NS_BR ip link del dev br
$NS1 ip link del veth1
$NS2 ip link del veth2

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

#link veths
ip link set netns ns1 veth1
ip link set netns ns2 veth2
ip link set netns nsBr ethBr1
ip link set netns nsBr ethBr2

#assign mac's
$NS1  ifconfig veth1 hw ether 02:03:01:04:06:07
$NS2  ifconfig veth2 hw ether 02:03:01:04:05:06
$NS_BR ifconfig ethBr1 hw ether 02:03:06:05:07:04
$NS_BR ifconfig ethBr2 hw ether 02:03:06:05:07:05

#assign ip's
$NS1 ifconfig veth1 10.1.1.1/24 up
$NS2 ifconfig veth2 10.1.1.2/24 up

#setup bridge
brctl addbr br
ip link del dev br
$NS_BR brctl addbr br
$NS_BR brctl addif br ethBr1
$NS_BR ip link set up dev ethBr1
$NS_BR brctl addif br ethBr2
$NS_BR ip link set up dev ethBr2

$NS_BR ip link set up dev br

#add delay and bw
# for client-to-server traffic
$NS_BR tc qdisc add dev ethBr1 handle 1: root   htb default 11
# mbps = MegaByte/s !
$NS_BR tc class add dev ethBr1 parent 1:    classid 1:11 htb rate 5mbps  quantum 1514
$NS_BR tc qdisc add dev ethBr1 parent 1:11 handle 12:0 netem delay 40ms
# will crash
#$NS_BR tc qdisc add dev ethBr1 parent 12:0  fq_codel limit 1000  target 3ms  interval 40ms

# for server-to-client traffic
$NS_BR tc qdisc add dev ethBr2 handle 1: root   htb default 11
$NS_BR tc class add dev ethBr2 parent 1:    classid 1:11 htb rate 5mbps  quantum 1514
$NS_BR tc qdisc add dev ethBr2 parent 1:11 handle 12:0 netem delay 40ms

# has no effect
#$NS_BR tc qdisc add dev br root  fq_codel limit 1000  target 3ms  interval 40ms

$NS_BR tc -s -d class show dev ethBr2
$NS_BR tc qdisc show

read -p "Pause"

$NS1 ethtool -K veth1 tso off gso off gro off 2> /dev/null
$NS2 ethtool -K veth2 tso off gso off gro off 2> /dev/null

serverIP="10.1.1.1"
serverPort=80
time=`date +%s`
dump_server=$time+"-server.pcap"
dump_client=$time+"-client.pcap"

$NS1  tcpdump -s 128 -i veth1 -w dump-$time-server &
$NS2  tcpdump -s 128 -i veth2 -w dump-$time-client &
#$NS_BR  tcpdump -i ethBr1 -w dump_server_br &
#$NS_BR  tcpdump -i ethBr2 -w dump_client_br &


# remember to copy server objects to /usr/share/nginx/html
fuser -k 80/tcp
$NS1 nginx

sleep 1
$NS1  netstat -s > netstat-$time-before

#$NS2  wget $serverIP/missing/gs1.wac.edgecastcdn.net/8019B6/data.tumblr.com/2d8674fb4cb5ade09dba02dbebd5e05f/tumblr_ms82wimFSG1rlz4gso1_1280.jpg
# client downloads all files of the website recursively
cd epload
#$NS2  node emulator/run.js http dependency_graphs/www.rakuten.co.jp_/
$NS2  node emulator/run.js http dependency_graphs/www.tumblr.com_/
#$NS2  node emulator/run.js http dependency_graphs/twitter.com_/
cd -

sleep 1
$NS1  netstat -s > netstat-$time-after
colordiff netstat-$time-*

pkill tcpdump
pkill tcpdump

$NS1 nginx -s quit
