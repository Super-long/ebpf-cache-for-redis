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
	u32 hdrlen, var_off, const_off;
	__be16 dport = 0;
	struct iphdr *ip;
	// 这里暂且不考虑IPV6
	// https://stackoverflow.com/questions/53136145/how-to-solve-the-r0-invalid-mem-access-inv-error-when-loading-an-ebpf-file-o
	struct tcphdr *tcp;
	char *payload;
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	var_off = 0;
	const_off = sizeof(struct ethhdr);
	ensure_header(skb, var_off, const_off, ip);

	switch (ip->protocol) {
		case IPPROTO_UDP:
			payload = data;
			return 0;
		case IPPROTO_TCP:
			hdrlen = ipv4_hdrlen(ip);
			if (hdrlen < sizeof(struct iphdr))
				return 0;
			var_off += hdrlen;
			ensure_header(skb, var_off, const_off, tcp);

			dport = tcp->dest;
			hdrlen = tcp_hdrlen(tcp);
			if (hdrlen < sizeof(struct tcphdr))
				return 0;
			var_off += hdrlen;
			payload = data + const_off + var_off;
			break;
		default:
			return XDP_PASS;
	}
	// 经过上面的循环拿到目的端口和payload相关，payload是真实数据包的起始地址
	if (dport == bpf_htons(6379) && payload+14 <= data_end) {
		// 目前只支持get
		// "*2\r\n$3\r\nget\r\n$13\r\nusername:1234\r\n"
		// 前八个字节亘古不变
		if (ip->protocol == IPPROTO_TCP && payload[9] == 'g' && payload[10] == 'e' && payload[11] == 't' && payload[12] == '\r' && payload[13] == '\n') { // is this a GET request
			unsigned int map_stats_index = MAP_STATS;
			unsigned int parsing_egress = PARSING_INGRESS;
			// 如果一个目标端口的TCP包来了，而且是get请求，就会更新map_stats表中的数据
			struct brc_stats *stats = bpf_map_lookup_elem(&map_stats, &map_stats_index);
			if (!stats) {
				return 0;
			}
			stats->get_recv_count++;

			// 解析上下文
			struct parsing_context *pctx = bpf_map_lookup_elem(&map_parsing_context, &parsing_egress);
			if (!pctx) {
				return 0;
			}
			// 14这个下标上应该是'$'
			pctx->read_pkt_offset = 14;
			pctx->value_size = 0;

			// "*2\r\n$3\r\nget\r\n$13\r\nusername:1234\r\n"
			if (payload+pctx->read_pkt_offset < data_end && payload[pctx->read_pkt_offset] == '$') {
				pctx->read_pkt_offset++;	// 现在pctx->read_pkt_offset是数字的第一个字符的下标
				while (payload+pctx->read_pkt_offset <= data_end && payload[pctx->read_pkt_offset] != '\r' && 
					payload[pctx->read_pkt_offset] >= '0' && payload[pctx->read_pkt_offset] <= '9') {
					pctx->value_size *= 10;
					pctx->value_size += payload[pctx->read_pkt_offset] - '0';
					pctx->read_pkt_offset++;
				}
			} else {
				return 0;
			}

			if (payload+pctx->read_pkt_offset > data_end || pctx->value_size > BRC_MAX_KEY_LENGTH) {
				stats->big_key_pass_to_user++;
				return 0;
			}
			// 目前value_size是key的大小,read_pkt_offset是key的第一个字节
			bpf_tail_call(skb, &tc_progs, BRC_PROG_XDP_HASH_KEYS);
		} else if (ip->protocol == IPPROTO_TCP) {
			// 非get请求就会来这里,set会把标记设置为invaild
			bpf_tail_call(skb, &tc_progs, BRC_PROG_XDP_INVALIDATE_CACHE);
		}
	}
	return 0;
}