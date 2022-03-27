#include "vmlinux.h"	// 必须放在首位

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
//#include "../libbpf/include/uapi/linux/pkt_cls.h"

#include "bpf_helpers.h"
#include "brc_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define tcp_hdrlen(tcp) (tcp->doff * 4)
// https://zhangbinalan.gitbooks.io/protocol/content/ipxie_yi_tou_bu.html
#define ipv4_hdrlen(ip) (ip->ihl * 4)

// https://mechpen.github.io/posts/2019-08-29-bpf-verifier/index.html
#define ensure_header(skb, var_off, const_off, hdr) do{	\
	u32 len = const_off + sizeof(*hdr);			\
	void *data = (void *)(long)skb->data + var_off;		\
	void *data_end = (void *)(long)skb->data_end;		\
								\
	if (data + len > data_end)				\
		bpf_skb_pull_data(skb, var_off + len);		\
								\
	data = (void *)(long)skb->data + var_off;		\
	data_end = (void *)(long)skb->data_end;			\
	if (data + len > data_end)				\
		return 0;				\
								\
	hdr = (void *)(data + const_off);			\
} while(0)

/*
 * @brief: 用于尾调用
 * @notes: 尾调用上限目前为33
 **/ 
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, RECURSION_UPPER_LIMIT);
	__type(key, u32);
	__type(value, u32);
} tc_progs SEC(".maps");

/*
 * @brief: 实际的hash表{hash->brc_cache_entry}
 **/ 
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct brc_cache_entry);
	__uint(max_entries, BRC_CACHE_ENTRY_COUNT);
} map_cache SEC(".maps");

/*
 * @brief: 用于在ingress中把get的key保存，在egress中
 **/
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, unsigned int);
	__type(value, struct redis_key);
	__uint(max_entries, BRC_MAX_KEY_IN_PACKET);
} map_keys SEC(".maps");

/*
 * @brief: 用于和用户态之间传递数据
 **/ 
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, unsigned int);
	__type(value, struct brc_stats);
	__uint(max_entries, MAP_STATS_MAX);
} map_stats SEC(".maps");

struct parsing_context;
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, unsigned int);
	__type(value, struct parsing_context);
	__uint(max_entries, PARSING_MAX);
} map_parsing_context SEC(".maps");

struct brc_cache_key;
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	//__type(key, 0); queue这里设置这个在load的时候会报错
	__type(value, struct brc_cache_key);
	__uint(max_entries, BRC_CACHE_QUEUE_SIZE);
} map_invaild_key SEC(".maps");

struct redis_key {
	u32 hash;
	char key_data[BRC_MAX_KEY_LENGTH + 1];
	unsigned int len;
};

// 因为redis协议的返回值无法自解释，但是我们又希望维护内核态和用户态的一致性，所以设置一个BPF_MAP_TYPE_QUEUE
struct brc_cache_key {
	struct bpf_spin_lock lock;
	unsigned int len;
	char key[BRC_MAX_KEY_LENGTH + 1];	// 为了在hash相同的时候判断是否是同一个key
};

struct parsing_context {
	unsigned int value_size;	// 在brc_rx_filter也可以代表key的大小
	unsigned short read_pkt_offset;
};

struct brc_cache_entry {
	struct bpf_spin_lock lock;
	unsigned int key_len;
	unsigned int data_len;
	char valid;
	int hash;
	char key[BRC_MAX_KEY_LENGTH];	// 为了在hash相同的时候判断是否是同一个key
	char data[BRC_MAX_CACHE_DATA_SIZE];
};

SEC("tc/brc_rx_filter")
int brc_rx_filter_main(struct __sk_buff *skb) {
	// static struct bpf_sock *(*bpf_skc_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *) 99;
	// libbpf/src/bpf_helper_defs.h xdp/tc 支持 bpf_skc_lookup_tcp
	// https://elixir.bootlin.com/linux/v5.17/source/tools/testing/selftests/bpf/progs/test_btf_skc_cls_ingress.c#L94 调用bpf_skc_lookup_tcp的例子
	// vmlinux/x86/vmlinux.h cls支持 bpf_skc_lookup_tcp

	// static struct bpf_tcp_sock *(*bpf_tcp_sock)(struct bpf_sock *sk) = (void *) 96;
	// libbpf/src/bpf_helper_defs.h 支持 bpf_tcp_sock,这里返回的结构体才是需要修改的,但是只支持tc,所以看起来这里也需要使用tc

	// https://elixir.bootlin.com/linux/v5.10.13/source/tools/testing/selftests/bpf/bpf_tcp_helpers.h#L53 bpf_sock定义

	// btf_bpf_tcp_sock
	// =============================================
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	void *transp = data + sizeof(*eth) + sizeof(*ip);
	// 这里的解析应该是不规范的，参考ensure_header上面的链接
	struct udphdr *udp;
	struct tcphdr *tcp;
	char *payload;
	__be16 dport;

	if (ip + 1 > data_end)
		return 0;

	switch (ip->protocol) {
		case IPPROTO_UDP:
			return 0;
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) transp;
			if (tcp + 1 > data_end)
				return 0;
			dport = tcp->dest;
			payload = transp + sizeof(*tcp);
			break;
		default:
			return 0;
	}

	// 经过上面的循环拿到目的端口和payload相关，payload是真实数据包的其实地址
	if (dport == bpf_htons(6379) && payload+13 <= data_end) {
		bpf_printk("recive request from port 6379 %s\n", payload);
		// 目前只支持get
		// "*2\r\n$3\r\nget\r\n$4\r\nkey1\r\n"
		// 前八个字节亘古不变
		if (payload[8] == 'g' && payload[9] == 'e' && 
			payload[10] == 't' && payload[11] == '\r' && payload[12] == '\n') { // is this a GET request
			bpf_printk("this is a get request\n");
			unsigned int map_stats_index = MAP_STATS;
			unsigned int parsing_egress = PARSING_INGRESS;
			// 如果一个目标端口的TCP包来了，而且是get请求，就会更新map_stats表中的数据
			struct brc_stats *stats = bpf_map_lookup_elem(&map_stats, &map_stats_index);
			if (!stats) {
				bpf_printk("stats invaild\n");
				return 0;
			}
			stats->get_recv_count++;

			// 解析上下文
			struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &parsing_egress);
			if (!pctx) {
				bpf_printk("pctx invaild\n");
				return 0;
			}
			// 14这个下标上应该是'$'
			pctx->read_pkt_offset = 13;
			pctx->value_size = 0;

			// "*2\r\n$3\r\nget\r\n$13\r\nusername:1234\r\n"
			// 这里不加 pctx->read_pkt_offset < BRC_MAX_PACKET_LENGTH 就会载入失败
			// ebpf如何处理无限循环？
			if (pctx->read_pkt_offset < BRC_MAX_PACKET_LENGTH && payload+pctx->read_pkt_offset+1 <= data_end && payload[pctx->read_pkt_offset] == '$') {
				pctx->read_pkt_offset++;	// 现在pctx->read_pkt_offset是数字的第一个字符的下标
#pragma clang loop unroll(disable)
				while (pctx->read_pkt_offset < BRC_MAX_PACKET_LENGTH && payload+pctx->read_pkt_offset+1 <= data_end && payload[pctx->read_pkt_offset] != '\r' && 
					payload[pctx->read_pkt_offset] >= '0' && payload[pctx->read_pkt_offset] <= '9') {
					pctx->value_size *= 10;
					pctx->value_size += payload[pctx->read_pkt_offset] - '0';
					pctx->read_pkt_offset++;
				}
			} else {
				bpf_printk("common check\n");
				return 0;
			}

			if (payload+pctx->read_pkt_offset+1 > data_end || pctx->value_size > BRC_MAX_KEY_LENGTH) {
				stats->big_key_pass_to_user++;
				bpf_printk("out of bounds\n");
				return 0;
			}
			bpf_printk("value size is %d\n", pctx->value_size);
			// 目前value_size是key的大小,read_pkt_offset是key的第一个字节
			bpf_tail_call(skb, &tc_progs, BRC_PROG_TC_HASH_KEYS);
		} else {
			// *3\r\n$3\r\nset\r\n$4\r\nkey1\r\n$6\r\nvalue1\r\n
			bpf_printk("this is a set request\n");
			// 非get请求就会来这里,set会把标记设置为invaild
			bpf_tail_call(skb, &tc_progs, BRC_PROG_TC_INVALIDATE_CACHE);
		}
	}

	return 0;
}

// 这里主要做的事情是通过get中的key计算hash值
// cache中是vaild就返回，如果是invaild就放入全局cache，等到get返回的时候获取key的值
// 在egress可能接收到set的返回值和get的返回值，前者我们忽略，那后者一定都是invaild以后去用户态拿数据的请求了
// 因为redis的单线程模型，所以这里使用一个队列来解决redis协议无法自解释的问题看起来是OK的
SEC("tc/brc_hash_keys")
int brc_hash_keys_main(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	void *transp = data + sizeof(*eth) + sizeof(*ip);
	// 这里的解析应该是不规范的，参考ensure_header上面的链接
	struct tcphdr *tcp;
	char *payload;
	bpf_printk("this is brc_hash_keys_main\n");

	// 这里必须要先验证ip + 1 > data_end，才能执行后面
	if (ip + 1 > data_end || ip->protocol != IPPROTO_TCP)
		return 0;

	tcp = (struct tcphdr *) transp;
	if (tcp + 1 > data_end)
		return 0;
	payload = transp + sizeof(*tcp);
	int off;

	unsigned int map_stats_index = MAP_STATS;
	unsigned int parsing_egress = PARSING_INGRESS;
	
	struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &parsing_egress);
	if (!pctx) {
		return 0;
	}

	// *3\r\n$3\r\nset\r\n$4\r\nkey1\r\n$6\r\nvalue1\r\n
	bpf_printk("pctx->read_pkt_offset [%d], pctx->value_size [%d]\n", pctx->read_pkt_offset, pctx->value_size);
	// pctx->read_pkt_offset > BRC_MAX_PACKET_LENGTH 非常重要，没这个load不了
	if (pctx->value_size > BRC_MAX_KEY_LENGTH || pctx->read_pkt_offset > BRC_MAX_PACKET_LENGTH) {
		return 1;
	}
	u32 hash = FNV_OFFSET_BASIS_32;
	// 目前payload的第一个字节就是key实际值的第一个字节
	// value_size是key的大小
	// 循环中一定要显式的限定为有限循环,且需要给payload判断是否有效
	if (payload + pctx->read_pkt_offset <= data_end) {
		payload = payload + pctx->read_pkt_offset;
	}

	// 这个printf一加就load失败
	//bpf_printk("this is brc_hash_keys, payload is %s\n", payload);
	// "*2\r\n$3\r\nget\r\n$4\r\nkey1\r\n"
	if (payload + 2 <= data_end && payload[0] == '\r' && payload[1] == '\n') {
#pragma clang loop unroll(disable)
		for (off = 2; payload+off+1 <= data_end && off < pctx->value_size+2; ++off) {
			hash ^= payload[off];
			hash *= FNV_PRIME_32;
		}
	} else {
		bpf_printk("payload not begin 'CRLF'\n");
		return 0;
	}

	u32 cache_idx = hash % BRC_CACHE_ENTRY_COUNT;
	bpf_printk("brc_hash_keys: hash is [%d], cache_idx is[%d] \n", hash, cache_idx);

	struct brc_cache_entry *entry = bpf_map_lookup_elem(&map_cache, &cache_idx);
	if (!entry) {
		return 0;
	}
	// 到了这里证明是个get操作，如果发现是invaild的，就把数据放入queue;如果是vaild的话就直接继续执行尾调用
	bpf_spin_lock(&entry->lock);
	// hash相同且字符串也一样证明找对了;vaild准备返回相关的事务;invaild pass 到用户态处理
	if (entry->valid) {
		// 这个标识代表在hash相同是判断key是否相同
		bool diff = true;
		if (pctx->value_size != entry->key_len) {
			diff = false;
		}
// math between pkt pointer and register with unbounded min value is not allowed
 		if (diff) {
			for (off = 2; off < BRC_MAX_KEY_LENGTH && payload+off+1 <= data_end && off < pctx->value_size; ++off) {
				if (payload[off] != entry->key[off - 2]) {
					diff = false;
					break;
				}
			}
		}
		u32 tmp_hash = entry->hash;
		bpf_spin_unlock(&entry->lock);
		// spin_lock的范围内不允许使用bpf_printk
		bpf_printk("this entry idx[%d] is vaild\n", cache_idx);
		if (tmp_hash == hash && diff) {
			bpf_tail_call(skb, &tc_progs, BRC_PROG_TC_PREPARE_PACKET);
		}
		// 能到这里证明对应entry有效，但是于get中的key不匹配
	} else {
		// entry是无效的，pass到用户态处理
		bpf_spin_unlock(&entry->lock);
		bpf_printk("this entry idx[%d] is invaild\n", cache_idx);
		// 这里是一个栈变量，限制了key的大小
		struct redis_key key_entry = {
			.hash = hash,
			.len = pctx->value_size
		};
// #pragma clang loop unroll(disable)
		for (off = 2; off < BRC_MAX_KEY_LENGTH && payload+off+1 <= data_end && off < pctx->value_size; ++off) {
			key_entry.key_data[off - 2] = payload[off];
		}
		//bpf_printk("key_entry.key_data is [%s]\n", key_entry.key_data);
		
		if (off >= BRC_MAX_KEY_LENGTH || payload+off+1 > data_end) {
			return 1;
		}
		// if (pctx->value_size >= BRC_MAX_KEY_LENGTH){
		// 	return 1;
		// }
		// 用于debug
		//key_entry.key_data[pctx->value_size] = '\n';

		bpf_map_push_elem(&map_invaild_key, &key_entry, BPF_ANY);
	}

	struct brc_stats *stats = bpf_map_lookup_elem(&map_stats, &map_stats_index);
	if (!stats) {
		return 0;
	}
	stats->miss_count++;

	return 0;
}

SEC("tc/brc_prepare_packet")
int brc_prepare_packet_main(struct __sk_buff *skb) {

	return XDP_PASS;
}

SEC("tc/brc_write_reply")
int brc_write_reply_main(struct __sk_buff *skb) {

	return XDP_PASS;
}

SEC("tc/brc_maintain_tcp")
int brc_maintain_tcp_main(struct __sk_buff *skb) {

	return XDP_PASS;
}

// 只做一件事，就是在get的时候让这个hash index上的entry invaild
SEC("tc/brc_invalidate_cache")
int brc_invalidate_cache_main(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	void *transp = data + sizeof(*eth) + sizeof(*ip);
	// 这里的解析应该是不规范的，参考ensure_header上面的链接
	struct tcphdr *tcp;
	char *payload;

	// 这里必须要先验证ip + 1 > data_end，才能执行后面
	if (ip + 1 > data_end || ip->protocol != IPPROTO_TCP)
		return 0;

	tcp = (struct tcphdr *) transp;
	if (tcp + 1 > data_end)
		return 0;
	payload = transp + sizeof(*tcp);

	unsigned int map_stats_index = MAP_STATS;
	struct brc_stats *stats = bpf_map_lookup_elem(&map_stats, &map_stats_index);
	if (!stats) {
		return 0;
	}

	u32 hash;
	int set_found = 0, interval = 0, key_found = 0;
	// 下面是一个状态机
	// *3\r\n$3\r\nset\r\n |(13) $4\r\nkey1\r\n$6\r\nvalue1\r\n
	bpf_printk("come on! payload is %s\n", payload);
	// if (payload + 11 <= data_end) {
	// 	bpf_printk("[5]%c [8]%c [9]%c [10]%c\n",payload[5],payload[8], payload[9], payload[10]);
	// }
	for (unsigned int off = 8; off < BRC_MAX_PACKET_LENGTH && payload+off+1 <= data_end;) {
		if (set_found == 0 && payload+off+5 <= data_end && 
			payload[off] == 's' && payload[off+1] == 'e' && payload[off+2] == 't') {
			set_found = 1;
			bpf_printk("find set!!!\n");
			// 把off移动搭配key的长度字段的第一个字符,除了set还跳过了’\r\n‘
			off += 5;
			stats->set_recv_count++;
		}	// 这里的+4指“$5\r\n”,目前暂且不解析长度，直接认为是一位数，并使用'/r'判断结尾
		else if (interval == 0 && set_found == 1 && payload+off+4 <= data_end && payload[off] == '$' 
			&& payload[off+2] == '\r' && payload[off+3] == '\n') {
			bpf_printk("find interval!!!\n");
			interval = 1;
			// 把off移动搭配key的长度字段的第一个字符
			off += 4;
		}
		else if (key_found == 0 && interval == 1 && payload+off+1 <= data_end && payload[off] != '\r') {
			bpf_printk("find key start!!!\n");
			hash = FNV_OFFSET_BASIS_32;
			hash ^= payload[off];
			hash *= FNV_PRIME_32;
			key_found = 1;
			off += 1;
		}	// 目前解析也不用长度，直接用'\n'判断
		else if (key_found == 1 && payload+off+1 <= data_end ) {
			if (payload[off] == '\r') { // 找到key的末尾了
				u32 cache_idx = hash % BRC_CACHE_ENTRY_COUNT;
				bpf_printk("find key end!!! hash[%d] cache_idx[%d]\n", hash, cache_idx);
				struct brc_cache_entry *entry = bpf_map_lookup_elem(&map_cache, &cache_idx);
				if (!entry) {
					bpf_printk("entry invaild when key hash end\n");
					return 0;
				}
				bpf_spin_lock(&entry->lock);
				if (entry->valid) {
					stats->invalidation_count++;
				}
				entry->valid = 0;
				bpf_spin_unlock(&entry->lock);
				break;
			}
			else { // still processing the key
				hash ^= payload[off];
				hash *= FNV_PRIME_32;
				off += 1;
			}
		} else {
			// 这个条件必须得有,要么就load不进去
			break;
		}
	}
	bpf_printk("brc_invalidate_cache finish!!!\n");
	return 0;
}

SEC("tc/brc_tx_filter")
int brc_tx_filter_main(struct __sk_buff *skb) {
	// 大于cache中允许的最大长度，直接返回错误
	if (skb->len > BRC_MAX_CACHE_DATA_SIZE + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
		return 0;
	}

	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	if (ip + 1 > data_end)
		return 0;
	void *transp = data + sizeof(*eth) + sizeof(*ip);
	// 这里的解析应该是不规范的，参考ensure_header上面的链接
	struct udphdr *udp;
	struct tcphdr *tcp;
	char *payload;
	__be16 dport;

	int payload_size = skb->len - sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
	struct redis_key key_entry;
	unsigned int map_stats_index = MAP_STATS;
	unsigned int parsing_egress = PARSING_EGRESS;

	switch (ip->protocol) {
		case IPPROTO_UDP:
			return 0;
			break;
		case IPPROTO_TCP:
			tcp = (struct tcphdr *) transp;
			if (tcp + 1 > data_end)
				return 0;
			dport = tcp->source;
			payload = transp + sizeof(*tcp);
			break;
		default:
			return 0;
	}
	
	// 因为下面先用到了[0]，所以需要检查此下标(payload + 1 <= data_end )是否是有效的,这是必要的步骤
	// 目前只处理批量回复，只监听6379，先支持set/get操作，后续再说
	// redis这部分的解析逻辑在 processBulkItem,我们需要的就是string2ll
	// 这个版本不能把尾调用和bpf to bpf结合使用就只能把解析也放在这个尾调用里面了
	// "$6\r\nfoobar\r\n"
	if (dport == bpf_htons(6379) && payload + 1 <= data_end && payload[0] == '$') {
		//bpf_printk("this is brc_tx_filter. payload is [%s]\n", payload);
		bpf_printk("this is brc_tx_filter.\n");
		// step1:先解析出数字，然后向后推一个/r/n，然后再执行尾调用
		struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &parsing_egress);
		if (!pctx) {
			bpf_map_pop_elem(&map_invaild_key, &key_entry);
			return 0;
		}
		pctx->value_size = 0;
		pctx->read_pkt_offset = 1;	// '$'
		
		// "$-1\r\n"
		// 一个get请求从客户端没读到自己希望的数据，那在全局cache中也需要一次delete操作 
		if (payload+pctx->read_pkt_offset+1 <= data_end && payload[pctx->read_pkt_offset] == '-') {
			bpf_map_pop_elem(&map_invaild_key, &key_entry);
			return 0;
		}
		// 那剩下的就是invaild的get操作，且确实从用户态获取到值了，这就需要尝试更新内核cache了
#pragma clang loop unroll(disable)
		while (pctx->read_pkt_offset < BRC_MAX_CACHE_DATA_SIZE && payload+pctx->read_pkt_offset+1 <= data_end && payload[pctx->read_pkt_offset] != '\r' && 
			payload[pctx->read_pkt_offset] >= '0' && payload[pctx->read_pkt_offset] <= '9') {
			pctx->value_size *= 10;
			pctx->value_size += payload[pctx->read_pkt_offset] - '0';
			pctx->read_pkt_offset++;
		}

		//bpf_printk("brc_tx_filter: pctx->value_size is [%d]\n", pctx->value_size);

		if (payload+pctx->read_pkt_offset+1 > data_end || pctx->value_size > BRC_MAX_CACHE_DATA_SIZE) {
			bpf_map_pop_elem(&map_invaild_key, &key_entry);
			return 0;
		}

		if (payload+pctx->read_pkt_offset+2 <= data_end &&
			payload[pctx->read_pkt_offset] == '\r' && payload[pctx->read_pkt_offset + 1] == '\n') {
			pctx->read_pkt_offset+=2;
		}
		// 现在 pctx->read_pkt_offset 的位置就是数据的第一个字节,且value_size是数据的实际大小

		// step2:更新map_stats状态
		struct brc_stats *stats = bpf_map_lookup_elem(&map_stats, &map_stats_index);
		if (!stats) {
			bpf_map_pop_elem(&map_invaild_key, &key_entry);
			return 0;
		}
		stats->try_update++;
		
		// step3: 尾调用,开始把数据写入hash表
		bpf_tail_call(skb, &tc_progs, BRC_PROG_TC_UPDATE_CACHE);
	}

	return 0;
	//return TC_ACT_OK;
}

SEC("tc/brc_update_cache")
int brc_update_cache_main(struct __sk_buff *skb) {
	bpf_printk("this is brc_update_cache_main\n");
	struct redis_key key_entry;
	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);
	void *transp = data + sizeof(*eth) + sizeof(*ip);
	// 这里的解析应该是不规范的，参考ensure_header上面的链接
	struct tcphdr *tcp;
	char *payload;

	// 这里必须要先验证ip + 1 > data_end，才能执行后面
	if (ip + 1 > data_end || ip->protocol != IPPROTO_TCP)
		return 0;

	tcp = (struct tcphdr *) transp;
	if (tcp + 1 > data_end)
		return 0;
	payload = transp + sizeof(*tcp);
	int off;

	unsigned int map_stats_index = MAP_STATS;
	unsigned int parsing_egress = PARSING_EGRESS;
	
	struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &parsing_egress);
	if (!pctx) {
		return 0;
	}
	
	// pctx->read_pkt_offset > BRC_MAX_PACKET_LENGTH 非常重要，没这个load不了
	if (pctx->value_size > BRC_MAX_CACHE_DATA_SIZE || pctx->read_pkt_offset > BRC_MAX_PACKET_LENGTH) {
		return 1;
	}
	u32 hash = FNV_OFFSET_BASIS_32;
	// 目前payload的第一个字节就是key实际值的第一个字节
	// value_size是key的大小
	// 循环中一定要显式的限定为有限循环,且需要给payload判断是否有效
	if (payload + pctx->read_pkt_offset <= data_end) {
		payload = payload + pctx->read_pkt_offset;
	}

	bpf_printk("redis get reply(read_offset=%d)\n", pctx->read_pkt_offset);

	// ==========================================

	// 获取此get返回值对应的key
	bpf_map_pop_elem(&map_invaild_key, &key_entry);
	// compute the key hash
#pragma clang loop unroll(disable)
	// hash算法为FNV-1a 
	// "$6\r\nfoobar\r\n"
	// step1:找到此key对应的hash_index
	// off < BRC_MAX_KEY_LENGTH 必须放在循环里，不能放在上面用key_entry.len和BRC_MAX_KEY_LENGTH做
	for (unsigned int off = 0; off < BRC_MAX_KEY_LENGTH && off < key_entry.len ; off++) {
		hash ^= key_entry.key_data[off];
		hash *= FNV_PRIME_32;
	}
	u32 cache_idx = hash % BRC_CACHE_ENTRY_COUNT;

	bpf_printk("hash is [%d], cache_idx is [%d]\n", hash, cache_idx);

	struct brc_cache_entry *entry = bpf_map_lookup_elem(&map_cache, &cache_idx);
	if (!entry) {
		return 0;
	}

	// 加锁，因为可能出现并发处理；我们认为最新的数据更可能被访问
//	bpf_spin_lock(&entry->lock);

// 	int diff = 0;
// #pragma clang loop unroll(disable)
// 	// 比较cache中的老数据和现在的数据是否相同
// 	for (int i = 0; i < key_entry.len; ++i) {
// 		if (key_entry.key_data[i] != entry->key[i]) {
// 			diff = 1;
// 			break;
// 		}
// 	}

// 	if (diff == 1) {
// 		// hash虽然相同，但是key不相同
// 		bpf_spin_unlock(&entry->lock);
// 		return 0;
// 	}
//	bpf_spin_unlock(&entry->lock);
// 上面比较数据实际是否一致在这里不重要，在get要在内核被提前处理时比较重要

	bpf_spin_lock(&entry->lock);
	// step2: 只要vaild是0，我们就会全量的替换
	if (!entry->valid) { 
		entry->valid = 1;
		entry->hash = hash;

		entry->key_len = key_entry.len;
		for(int i = 0; i < BRC_MAX_KEY_LENGTH && i < key_entry.len; ++i) {
			entry->key[i] = key_entry.key_data[i];
		}

		entry->data_len = pctx->value_size;
		for(int i = 0; payload+i+1 <= data_end && i < pctx->value_size && i < BRC_CACHE_ENTRY_COUNT; ++i) {
			entry->data[i] = payload[i];
		}

		bpf_spin_unlock(&entry->lock);
		bpf_printk("brc_update_cache entry->key: %s, entry->key_len\n", entry->key, entry->key_len);
		bpf_printk("brc_update_cache entry->data: %s, entry->data_len\n", entry->data, entry->data_len);
		
		struct brc_stats *stats = bpf_map_lookup_elem(&map_stats, &map_stats_index);
		if (!stats) {
			return 0;
		}
		stats->update_count++;
	} else {
		bpf_spin_unlock(&entry->lock);
	}

	return 0;
}