tc filter del dev eth0 egress
tc filter del dev eth0 ingress
tc qdisc del dev eth0 clsact
rm /sys/fs/bpf/tc/brc_rx_filter
rm /sys/fs/bpf/tc/brc_tx_filter

cd ..
make 
cd .bin 
./brc