tc qdisc add dev eth0 clsact 
tc filter add dev eth0 ingress bpf object-pinned /sys/fs/bpf/tc/brc_rx_filter
tc filter add dev eth0 egress bpf object-pinned /sys/fs/bpf/tc/brc_tx_filter
cat /sys/kernel/debug/tracing/trace_pipe