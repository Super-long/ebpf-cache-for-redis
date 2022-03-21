#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "vmlinux.h"
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
	unsigned int key_count;
	unsigned int current_key;
	unsigned short read_pkt_offset;
	unsigned short write_pkt_offset;
};

SEC("brc_rx_filter")
int brc_rx_filter_main(struct xdp_md *ctx) {

}

SEC("brc_hash_keys")
int brc_hash_keys_main(struct xdp_md *ctx) {

}

SEC("brc_prepare_packet")
int brc_prepare_packet_main(struct xdp_md *ctx) {

}

SEC("brc_write_reply")
int brc_write_reply_main(struct xdp_md *ctx) {

}

SEC("brc_maintain_tcp")
int brc_maintain_tcp(struct xdp_md *ctx) {

}

SEC("brc_invalidate_cache")
int brc_invalidate_cache_main(struct xdp_md *ctx) {

}

SEC("brc_tx_filter")
int brc_tx_filter_main(struct __sk_buff *skb) {

}

SEC("brc_update_cache")
int brc_update_cache_main(struct __sk_buff *skb) {

}