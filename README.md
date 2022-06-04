# ebpf-cache-for-redis

1. git submodule update --init --recursive  
2. cd brc 
3. make

需要修改libbpf/src/libbpf.c 中`SEC_DEF("tc",			SCHED_CLS, 0, SEC_NONE),`为`SEC_DEF("tc",			SCHED_CLS, 0, SEC_NONE | SEC_SLOPPY_PFX),`

- ./redis-server 启动一个redis服务器
- ./redis-cli CONFIG SET protected-mode no 使得其可被外网访问
- 在brc/.bin 中执行`sh ../restart.sh`
- 在任意路径执行`sh mount.sh`
- 另一台机器上启动./redis-cli 执行set get
- 执行`./tools/bpftool map dump name map_cache` 查看实际cache中的数据
- 在`/tmp/brc_stats.txt`和`/tmp/brc_stats_interval.txt`中可以查看map_stats中的实时数据



---
# 手动编译

1. clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I../vmlinux/x86/ -idirafter /usr/local/include -idirafter /usr/lib64/clang/11.0.0/include -idirafter /usr/include  -c trace.bpf.c -o trace.bpf.o 
2. /root/exercise/libbpf-bootstrap/tools/bpftool gen skeleton trace.bpf.o > trace.skel.h 
3. clang -g -O2 -Wall -I . -c trace.c -o trace.o 
4. clang -Wall -O2 -g trace.o /root/exercise/libbpf-bootstrap/examples/c/.output/libbpf.a  -lelf -lz -o trace  

# 执行
现在在用户态挂载的时候有一个大问题，就是bpf_tc_hook_create不太成熟，资料较少，所以使用object pin先把TC bpf挂载，然后再手动挂载TC程序,我倾向于使用更低级别的接口,但是捣鼓了两天没搞出来,后续看下libbpf源码
1. make && cd .bin && ./brc
2. tc qdisc add dev eth0 clsact 
3. tc filter add dev eth0 ingress bpf object-pinned /sys/fs/bpf/tc/brc_rx_filter
4. tc filter add dev eth0 egress bpf object-pinned /sys/fs/bpf/tc/brc_tx_filter
5. cat /sys/kernel/debug/tracing/trace_pipe

上述三四步不能颠倒，否则map_keys中的数据可能会出现错乱

如果bpf文件系统还没挂载就执行：
1. mount -t bpf none /sys/fs/bpf/

# 卸载
卸载bpf程序和qdisc
1. tc filter del dev eth0 egress
2. tc filter del dev eth0 ingress
3. tc qdisc del dev eth0 clsact
4. rm /sys/fs/bpf/tc/brc_rx_filter
5. rm /sys/fs/bpf/tc/brc_tx_filter

# 对于BPF程序的解释
## brc_rx_filter
1. 将6379端口TCP协议的get请求执行解析，解析结果放在pctx中，然后执行尾调用brc_hash_keys
2. 对于非get数据执行brc_invalidate_cache

## brc_hash_keys
1. 找到这个get请求中key的hash_index
2. 对应的entry如果是有效的话调用brc_prepare_packet
3. 对应的entry是无效的话把key放入到invaild_key_data中，在egress中需要用到这个key的数据(queue如何把栈上数据放入其中)
## brc_invalidate_cache
1. 使得set操作中key对应的hash entry为invaild
## brc_tx_filter
1. 对于6379端口且是批量回复的数据执行解析，解析结果放在pctx中，如果发现是"$-1\r\n"的话需要从invaild_key_data中pop一个数据项，然后执行brc_update_cache
## brc_update_cache
1. 从invaild_key_data中拿到此次get实际key到数据
2. 计算key对应的hash_index
3. 如果此entry是invaild的，替换其中所有的值;如果是vaild有效，意味着此次get的这个


# Redis协议
https://redis.io/topics/protocol
## 批量回复
支持二进制安全字符串
> "*3\r\n$3\r\nSET\r\n$5\r\nmykey\r\n$7\r\nmyvalue\r\n"

> "*2\r\n$3\r\nget\r\n$13\r\nusername:1234\r\n"

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


# 关于用户态/内核态一致性
希望cache不会对用户态本身对数据有任何影响，所以set操作是一定会pass到用户态处理的，然后在get的时候再执行cache update的

但是这样的话仅仅凭借get返回值的数据没法更新cache（返回值中不存在key，无法自解释），所以现在是否需要再get操作执行的时候做一些数据的保存呢

一个方法是在get操作是在ingress中插入key，然后在egress中把这个key拿出来，现在看起来只要get了，除非redis崩了，egree中一定是可以拿到这个消息的，但是用户态可能出现阻塞，也就是说cache中key可能出现堆积，但是一定是先进先出的一个过程，搞一个循环队列？

在用户态宕机的时候清空内核cache，然后在get可能使得循环队列超限的时候也清空内核cache

# pragma clang loop unroll(disable)
指示编译器不允许展开循环，但是clang官网说展开的话可以增加ILP(指令级别并行)的机会 
https://cseweb.ucsd.edu//classes/wi05/cse240a/ilp1.pdf
https://clang.llvm.org/docs/LanguageExtensions.html#loop-unrolling

# debug
1. https://stackoverflow.com/questions/53136145/how-to-solve-the-r0-invalid-mem-access-inv-error-when-loading-an-ebpf-file-o
2. https://mechpen.github.io/posts/2019-08-29-bpf-verifier/index.html
3. 貌似bpf_printk的中文不能显示？
4. spin_lock的范围内不允许使用bpf_printk
5. 目前queue的push操作需要栈上的对象，导致key的上限比较小