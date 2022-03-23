#include "vmlinux.h"	// 必须放在首位

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
//#include "../libbpf/include/uapi/linux/pkt_cls.h"

#include "bpf_helpers.h"
#include "brc_common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/*
 * @brief: 用于尾调用
 * @notes: 尾调用上限目前为33
 **/ 
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 33);
	__type(key, u32);
	__type(value, u32);
} xdp_progs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 33);
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
} map_kcache SEC(".maps");

/*
 * @brief: 因为使用的是尾调用，所以需要在解析多个key时维护以解析的数据
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
	__uint(max_entries, 1);
} map_stats SEC(".maps");

struct parsing_context;
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, unsigned int);
	__type(value, struct parsing_context);
	__uint(max_entries, 1);
} map_parsing_context SEC(".maps") ;

struct redis_key {
	u32 hash;
	char key_data[BRC_MAX_KEY_LENGTH];
	unsigned int len;
};

struct parsing_context {
	unsigned int value_size;
	unsigned short read_pkt_offset;
	unsigned short write_pkt_offset;
};

struct brc_cache_entry {
	struct bpf_spin_lock lock;
	unsigned int len;
	char valid;
	int hash;
	char data[BRC_MAX_CACHE_DATA_SIZE];
};

SEC("xdp/brc_rx_filter")
int brc_rx_filter_main(struct xdp_md *ctx) {
	// static struct bpf_sock *(*bpf_skc_lookup_tcp)(void *ctx, struct bpf_sock_tuple *tuple, __u32 tuple_size, __u64 netns, __u64 flags) = (void *) 99;
	// libbpf/src/bpf_helper_defs.h xdp/tc 支持 bpf_skc_lookup_tcp
	// https://elixir.bootlin.com/linux/v5.17/source/tools/testing/selftests/bpf/progs/test_btf_skc_cls_ingress.c#L94 调用bpf_skc_lookup_tcp的例子
	// vmlinux/x86/vmlinux.h cls支持 bpf_skc_lookup_tcp

	// static struct bpf_tcp_sock *(*bpf_tcp_sock)(struct bpf_sock *sk) = (void *) 96;
	// libbpf/src/bpf_helper_defs.h 支持 bpf_tcp_sock,这里返回的结构体才是需要修改的,但是只支持tc,所以看起来这里也需要使用tc

	// btf_bpf_tcp_sock
	char fmt[] = "---------brc_rx_filter_main--------\n";
	bpf_trace_printk(fmt, sizeof(fmt));
	return XDP_PASS;
}

SEC("xdp/brc_hash_keys")
int brc_hash_keys_main(struct xdp_md *ctx) {

	return XDP_PASS;
}

SEC("xdp/brc_prepare_packet")
int brc_prepare_packet_main(struct xdp_md *ctx) {

	return XDP_PASS;
}

SEC("xdp/brc_write_reply")
int brc_write_reply_main(struct xdp_md *ctx) {

	return XDP_PASS;
}

SEC("xdp/brc_maintain_tcp")
int brc_maintain_tcp_main(struct xdp_md *ctx) {

	return XDP_PASS;
}

SEC("xdp/brc_invalidate_cache")
int brc_invalidate_cache_main(struct xdp_md *ctx) {
	return XDP_PASS;
}

SEC("tc/brc_tx_filter")
int brc_tx_filter_main(struct __sk_buff *skb) {
	// 大于cache中允许的最大长度，直接返回错误
	if (skb->len > BRC_MAX_CACHE_DATA_SIZE + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
		return 0;
	}

	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	struct ethhdr *eth = data;

	struct iphdr *ip = data + sizeof(*eth);
	// 协议不正确,且数据包封装出现问题，虽然基本不太可能，直接返回
	if (ip->protocol != IPPROTO_TCP || ip + 1 > data_end) {
		return 0;
	}

	struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);
	// TCP的包头可能不止20字节，但是tcphdr中看起来是定长的
	char *payload = data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp);
	int payload_size = skb->len - sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);
	unsigned int zero = 0;

	// 数据包太小，也直接返回
	if (tcp + 1 > data_end)
		return 0;

	__be16 sport = tcp->source;

	// 目前只处理批量回复，只监听6379，先支持set/get操作，后续再说
	// redis这部分的解析逻辑在 processBulkItem,我们需要的就是string2ll
	// 这个版本不能把尾调用和bpf to bpf结合使用就只能把解析也放在这个尾调用里面了
	// "$6\r\nfoobar\r\n"
	if (sport == htons(6379) && payload[0] == '$') {
		// step1:先解析出数字，然后向后推一个/r/n，然后在执行尾调用
		struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &zero);
		pctx->value_size = 0;
		pctx->read_pkt_offset = 0;
		if (!pctx) {
			return 0;
		}
		pctx->read_pkt_offset = 1;	// '$'
		// "$-1\r\n"
		if (payload[pctx->read_pkt_offset] == '-') {
			return 0;
		}
		
		while (pctx->read_pkt_offset < payload_size && payload[pctx->read_pkt_offset] != '\r' && 
			payload[pctx->read_pkt_offset] >= '0' && payload[pctx->read_pkt_offset] <= '9') {
			pctx->value_size *= 10;
			pctx->value_size += payload[pctx->read_pkt_offset] - '0';
			pctx->read_pkt_offset++;
		}
		if(payload[pctx->read_pkt_offset] < '0' && payload[pctx->read_pkt_offset] > '9') {
			return 0;
		}

		if (pctx->read_pkt_offset < payload_size && pctx->read_pkt_offset + 1 < payload_size &&
			payload[pctx->read_pkt_offset] == '\r' && payload[pctx->read_pkt_offset + 1] == '\n') {
			pctx->read_pkt_offset+=2;
		}
		// 现在 pctx->read_pkt_offset 的位置就是数据的第一个字节,且value_size是数据的实际大小

		// step2:更新map_stats状态
		struct brc_stats *stats = bpf_map_lookup_elem(&map_stats, &zero);
		if (!stats) {
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

	return 0;
	//return TC_ACT_OK;
}