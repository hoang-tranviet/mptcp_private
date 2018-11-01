make
sudo ./tcp_stress_test.sh
sudo ./test_tcp_user bpf_tcp_option_insert.o -q
sudo ./test_tcp_user bpf_tcp_option_stress_test.o -q
sudo ./test_tcp_user bpf_tcp_option_sockopt_stress_test.o -q
