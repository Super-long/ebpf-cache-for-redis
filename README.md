# ebpf-cache-for-redis

1. git submodule update --init --recursive  
2. cd brc 
3. make


---
# 手动编译

1. clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../vmlinux/x86/ -idirafter /usr/local/include -idirafter /usr/lib64/clang/11.0.0/include -idirafter /usr/include  -c trace.bpf.c -o trace.bpf.o 
2. /root/exercise/libbpf-bootstrap/tools/bpftool gen skeleton trace.bpf.o > trace.skel.h 
3. clang -g -O2 -Wall -I . -c trace.c -o trace.o 
4. clang -Wall -O2 -g trace.o /root/exercise/libbpf-bootstrap/examples/c/.output/libbpf.a  -lelf -lz -o trace  

# 执行
现在在用户态挂载的时候有一个大问题，就是bpf_tc_hook_create不太成熟，资料较少，所以使用object pin先把TC bpf挂载，然后再手动挂载TC程序,我倾向于使用更低级别的接口,但是捣鼓了两天没搞出来,后续看下libbpf源码
1. cd .bin
2. ./brc
3. tc qdisc add dev eth0 clsact 
4. tc filter add dev eth0 egress bpf object-pinned /sys/fs/bpf/tc/brc_tx_filter
5. cat /sys/kernel/debug/tracing/trace_pipe

# 卸载
卸载bpf程序和qdisc
1. tc filter del dev eth0 egress 
2. tc qdisc del dev eth0 clsact
3. rm /sys/fs/bpf/tc/brc_tx_filter

# Redis协议
https://redis.io/topics/protocol
## 批量回复
支持二进制安全字符串
> "*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n"

> "$6\r\nfoobar\r\n"

> "$-1\r\n"

## 整数回复
`:` 之后就是整数
> :0\r\n

> :1000\r\n


## 状态回复
客户端返回`+`之后的消息
> +OK\r\n

## 错误回复
`-`之后代表错误类型，ERR 是一个通用错误，而 WRONGTYPE 则是一个更特定的错误，之后为内容
> -Error message\r\n

> -WRONGTYPE Operation against a key holding the wrong kind of value\r\n

## 数组回复