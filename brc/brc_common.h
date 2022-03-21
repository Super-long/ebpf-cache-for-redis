#ifndef _BRC_COMMON_H
#define _BRC_COMMON_H

#define BRC_MAX_CACHE_DATA_SIZE (1024)
#define BRC_CACHE_ENTRY_COUNT   (1024)
#define BRC_MAX_KEY_LENGTH      (1024)
#define BRC_MAX_KEY_IN_PACKET   (10)
#define FNV_PRIME_32            (16777619)

enum {
	BRC_PROG_XDP_HASH_KEYS = 0,
	BRC_PROG_XDP_PREPARE_PACKET,
	BRC_PROG_XDP_WRITE_REPLY,
    BRC_PORG_XDP_MAINTAIN_TCP,
	BRC_PROG_XDP_INVALIDATE_CACHE,

	BRC_PROG_XDP_MAX,
};

enum {
	BRC_PROG_TC_UPDATE_CACHE = 0,

	BRC_PROG_TC_MAX,
};

// 用于与客户端交互，所以需要放到common中来

struct brc_cache_entry {
	struct bpf_spin_lock lock;
	unsigned int len;
	char valid;
	int hash;
	char data[BRC_MAX_CACHE_DATA_SIZE];
};

struct brc_stats {
	unsigned int get_recv_count;			// 接收的get数
	unsigned int set_recv_count;			// 接收的set数
	unsigned int hit_misprediction;			// 预期命中但未命中（由于哈希冲突或 invalidation/update 的竞争）
	unsigned int hit_count;				    // hit的次数
	unsigned int miss_count;			    // miss的次数
    unsigned int try_update;    			// 尝试更新缓存的次数
	unsigned int update_count;			    // cache被更新的次数
	unsigned int invalidation_count;		// cache被设置为invaild的次数
};

#endif