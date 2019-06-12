#NS2="ip netns exec ns2 "

# client will self-terminate in (-m) seconds
curl 10.1.1.1:80/vmlinux.o  -m 2  --limit-rate 10K  -o /dev/null


