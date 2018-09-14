#!/bin/bash

# set up netns + router to use traffic control
#  _______  ________
# | ns1   ||  ns3   |
# |       ||        |
# |server1||server3 |
# | .1.1  ||  .3.3  |
# |_veth1_||_veth3__|
#    |        |
#  __|________|____
# | ethRt1  ethRt3 |
# | .1.11   .3.33  |
# |   \    /       |
# |   Router      nsRt
# |   /            |
# | .2.22          |
# | ethRt2         |
# |__|_____________|
#  __|_____________
# | veth2          |
# | .2.2           |
# client is in ns2 |

NS1="ip netns exec ns1 "
NS2="ip netns exec ns2 "
NS3="ip netns exec ns3 "
NS_RT="ip netns exec nsRt "

terminate_all() {
	pkill rsync
	pkill rsync
	pkill -f "PidFile=/run/sshd-ns1.pid"
	pkill -f "PidFile=/run/sshd-ns3.pid"
	pkill tcpdump
	pkill tcpdump
	pkill tcpdump
}

clean_up() {
	# this will also auto remove ethRt{X}
	$NS1 ip link del veth1
	$NS2 ip link del veth2
	$NS3 ip link del veth3

	ip netns del ns1
	ip netns del ns2
	ip netns del ns3
	ip netns del nsRt
}

finish() {
	terminate_all
	clean_up  2> /dev/null
}

# trap Ctrl-C
trap finish SIGINT

sysctl_config() {
	sysctl -w net.mptcp.mptcp_enabled=0

	# to activate pr_debug() but no effect?
	sysctl -w kernel.printk="7 7 7 7"
	#cat /proc/sys/kernel/printk
	$NS2 echo "7 7 7 7" > /proc/sys/kernel/printk
	#cat /proc/sys/kernel/printk
	#$NS2 cat /proc/sys/kernel/printk
}

clean_up 2> /dev/null

if [ "$#" -ne 3 ]; then
    echo "Need 3 params: delay(ms) iteration uto_enable/disable"
    exit 1
fi

delay=$1
iter=$2

# Add namespaces
ip netns add ns1
ip netns add ns2
ip netns add ns3
ip netns add nsRt

# Add veths interfaces
ip link add veth1 type veth peer name ethRt1
ip link add veth2 type veth peer name ethRt2
ip link add veth3 type veth peer name ethRt3

#link veths
ip link set netns ns1 veth1
ip link set netns ns2 veth2
ip link set netns ns3 veth3
ip link set netns nsRt ethRt1
ip link set netns nsRt ethRt2
ip link set netns nsRt ethRt3

#assign mac's
$NS1  ifconfig veth1 hw ether 02:03:01:04:06:07
$NS3  ifconfig veth3 hw ether 02:03:01:04:05:05
$NS2  ifconfig veth2 hw ether 02:03:01:04:05:06
$NS_RT ifconfig ethRt1 hw ether 02:03:06:05:07:04
$NS_RT ifconfig ethRt2 hw ether 02:03:06:05:07:05
$NS_RT ifconfig ethRt3 hw ether 02:03:06:05:07:06

#assign ip's
$NS_RT ip address add 127.0.0.1/8 dev lo
$NS_RT ip link set dev lo up

$NS1   ifconfig  veth1 10.1.1.1/24 up
$NS_RT ifconfig ethRt1 10.1.1.11/24 up

$NS3   ifconfig  veth3 10.1.3.3/24 up
$NS_RT ifconfig ethRt3 10.1.3.33/24 up

$NS2   ifconfig  veth2 10.1.2.2/24 up
$NS_RT ifconfig ethRt2 10.1.2.22/24 up

$NS1 ip route add 10.1.0.0/16 via 10.1.1.11
$NS2 ip route add 10.1.0.0/16 via 10.1.2.22
$NS3 ip route add 10.1.0.0/16 via 10.1.3.33

$NS_RT sysctl -w net.ipv4.ip_forward=1

#setup router
$NS_RT ip link set up dev ethRt1
$NS_RT ip link set up dev ethRt2
$NS_RT ip link set up dev ethRt3

#add delay and bw
# for client-to-server traffic
$NS_RT tc qdisc add dev ethRt1 handle 1: root   htb default 11
$NS_RT tc class add dev ethRt1 parent 1:    classid 1:11 htb rate 1mbps
$NS_RT tc qdisc add dev ethRt1 parent 1:11 handle 12:0 netem delay ${delay}ms

$NS_RT tc qdisc add dev ethRt3 handle 1: root   htb default 11
$NS_RT tc class add dev ethRt3 parent 1:    classid 1:11 htb rate 1mbps
$NS_RT tc qdisc add dev ethRt3 parent 1:11 handle 12:0 netem delay 5ms

# for server-to-client traffic
$NS_RT tc qdisc add dev ethRt2 handle 1: root   htb default 11
$NS_RT tc class add dev ethRt2 parent 1:    classid 1:11 htb rate 1mbps
$NS_RT tc qdisc add dev ethRt2 parent 1:11 handle 12:0 netem delay 5ms


$NS1 ethtool -K veth1 tso off gso off gro off 2> /dev/null
$NS3 ethtool -K veth3 tso off gso off gro off 2> /dev/null
$NS2 ethtool -K veth2 tso off gso off gro off 2> /dev/null

sysctl_config

server1_IP="10.1.1.1"
server3_IP="10.1.3.3"

set -x
if [ $3 -eq 1 ]; then
	parent_dir="trace-uto"
else
	parent_dir="trace-uto-disabled"
fi

outdir=${parent_dir}/delay-${delay}
mkdir -p $outdir
echo "testdir: $outdir	id: $iter"


$NS1  tcpdump -s 150 -i veth1  -w $outdir/dump_${iter}_server     &> /dev/null &
$NS3  tcpdump -s 150 -i veth3  -w $outdir/dump_${iter}_server_alt &> /dev/null &
$NS2  tcpdump -s 150 -i veth2  -w $outdir/dump_${iter}_client     &> /dev/null &
sleep 0.2


# start sshd in the server's netns
$NS1 /usr/sbin/sshd -o PidFile=/run/sshd-ns1.pid
$NS3 /usr/sbin/sshd -o PidFile=/run/sshd-ns3.pid

$NS2 ./rsync_uto.sh $server1_IP  $server3_IP &

sleep 4

$NS_RT ip link set down dev ethRt1
wait `pgrep  rsync_uto.sh`
echo "wait done"
#sleep 10

finish
