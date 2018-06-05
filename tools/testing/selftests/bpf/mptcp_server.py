#!/usr/bin/env python3
#
# Author: Viet-Hoang Tran (UClouvain)

import sys, os, getopt
import time
import subprocess


# get my non-loopback IP address
import socket
def get_local_ip():
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s.connect(("8.8.8.8", 80))
	ip = s.getsockname()[0]
	s.close()
	return ip

subprocess.Popen(["sysctl", "-w", "net.mptcp.mptcp_path_manager=ndiffports"])
subprocess.Popen(["sysctl", "-w", "net.mptcp.mptcp_debug=1"])
subprocess.Popen(["sysctl", "net.mptcp"])
subprocess.Popen(["ethtool", "-K", "eth1", "gro", "off"])

serverPort = 80

millis = str(round(time.time() * 1000))
dump_file='dump-'+ millis +'.pcap'
tcpdump = subprocess.Popen(["time","tcpdump", "-i", "lo", '-w', dump_file]);

time.sleep(0.3)

# Remember to set python HTTP server's
# protocol_version to HTTP/1.1 to enable TCP KeepAlive
server = subprocess.Popen(["python3", "-m", "http.server", str(serverPort)])

time.sleep(0.1)
ip = get_local_ip()

# blocking call to curl client
client = subprocess.call("curl "+ str(ip) +':'+ str(serverPort) + "/vmlinux.o --limit-rate 1K -o /dev/null", shell=True)

server.kill()
tcpdump.kill()

