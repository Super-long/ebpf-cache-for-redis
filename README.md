# ebpf-cache-for-redis

1. git submodule update --init --recursive  
2. cd brc 
3. make


---
或者手动编译

1. clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../vmlinux/x86/ -idirafter /usr/local/include -idirafter /usr/lib64/clang/11.0.0/include -idirafter /usr/include  -c trace.bpf.c -o trace.bpf.o 
2. /root/exercise/libbpf-bootstrap/tools/bpftool gen skeleton trace.bpf.o > trace.skel.h 
3. clang -g -O2 -Wall -I . -c trace.c -o trace.o 
4. clang -Wall -O2 -g trace.o /root/exercise/libbpf-bootstrap/examples/c/.output/libbpf.a  -lelf -lz -o trace  


---
现在在用户态挂载的时候有一个大问题，就是bpf_tc_hook_create不太成熟，资料较少，所以使用object pin先把TC bpf挂载，然后再手动挂载TC程序,我倾向于使用更低级别的接口,但是捣鼓了一周没搞出来,后续看下libbpf源码
1. cd .bin
2. ./brc
3. tc qdisc add dev eth0 clsact 
4. tc filter add dev eth0 egress bpf object-pinned /sys/fs/bpf/tc/brc_tx_filter
5. cat /sys/kernel/debug/tracing/trace_pipe

卸载bpf程序和qdisc
1. tc filter del dev eth0 egress 
2. tc qdisc del dev eth0 clsact
3. rm /sys/fs/bpf/tc/brc_tx_filter
