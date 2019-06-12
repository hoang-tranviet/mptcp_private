ip_map_id=`bpftool map show |grep sockaddr_map|cut -d ':' -f1`

cmd=`ifconfig | grep 'inet ' | awk {' if ($2 != "127.0.0.1") print $2'}`

i=0
for addr in $cmd; do
	echo $addr $ip_map_id
	bpftool map update id $ip_map_id  key 0 0 0 $i value 1 2 3 4
	i=$i+1
done

