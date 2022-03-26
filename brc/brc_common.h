#ifndef _BRC_COMMON_H
#define _BRC_COMMON_H

#define BRC_MAX_CACHE_DATA_SIZE (1024)
#define BRC_CACHE_ENTRY_COUNT   (1024)
#define BRC_MAX_PACKET_LENGTH 	(1500)
#define BRC_MAX_KEY_LENGTH      (256)
#define BRC_MAX_KEY_IN_PACKET   (10)
#define BRC_CACHE_QUEUE_SIZE	(512)
#define RECURSION_UPPER_LIMIT 	(33)
// https://www.vbforums.com/showthread.php?879417-RESOLVED-restore-my-string-from-a-hash
#define FNV_OFFSET_BASIS_32 	(2166136261)
#define FNV_PRIME_32            (16777619)

enum {
	BRC_PROG_TC_UPDATE_CACHE = 0,
	BRC_PROG_TC_HASH_KEYS = 0,
	BRC_PROG_TC_PREPARE_PACKET,
	BRC_PROG_TC_WRITE_REPLY,
    BRC_PORG_TC_MAINTAIN_TCP,
	BRC_PROG_TC_INVALIDATE_CACHE,
	BRC_PROG_TC_MAX,
};

enum {
	PARSING_INGRESS = 0,
	PARSING_EGRESS,
	PARSING_MAX,
};

enum {
	MAP_STATS = 0,
	MAP_STATS_MAX,
};

// 用于与客户端交互，所以需要放到common中来
struct brc_stats {
	unsigned int get_recv_count;			// 接收的get数
	unsigned int set_recv_count;			// 接收的set数
	unsigned int hit_misprediction;			// 预期命中但未命中（由于哈希冲突或 invalidation/update 的竞争）
	unsigned int hit_count;				    // hit的次数
	unsigned int miss_count;			    // miss的次数
    unsigned int try_update;    			// 尝试更新缓存的次数
	unsigned int update_count;			    // cache被更新的次数
	unsigned int invalidation_count;		// cache被设置为invaild的次数
	unsigned int big_key_pass_to_user;		// key的大小超过BRC_MAX_KEY_LENGTH,pass到用户态处理
};

#endif