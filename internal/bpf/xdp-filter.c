//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "packet-parsers.h"


/* --- Maps --- */

struct ipv4_lpm_key {
	__u32 prefixlen;
	__u32 addr;
};

struct rule_id {
	__u32 subnet_id;
	int proto;
	__u32 port;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct ipv4_lpm_key);
	__type(value, __u32);
	__uint(max_entries, 10000);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} subnet_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct rule_id);
	__type(value, __u32);
	__uint(max_entries, 65536);
} rule_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} default_action_map SEC(".maps");


/* Handle case for ICMP, TCP and UDP */

static __always_inline int handle_icmp(struct hdr_cursor *nh, void *data_end, __u32 subnet_id, __u32 *default_rc){
	struct icmphdr *icmph;
	bpf_printk("HIT: PROTO ICMP, subnet_id: %u", subnet_id);
	if(parse_icmphdr(nh, data_end, &icmph) == -1 ) return XDP_DROP;
	
	struct rule_id id = {
		.subnet_id = subnet_id,	       
		.proto = IPPROTO_ICMP,
		.port = 0 
	};
	
	__u32 *rc = bpf_map_lookup_elem(&rule_map, &id);

	if(!rc){
		return *default_rc;
	}

	bpf_printk("Action obtained, value= %d", *rc);
	return *rc;

}


static __always_inline int handle_tcp(struct hdr_cursor *nh, void *data_end, __u32 subnet_id, __u32 *default_rc){
	struct tcphdr *tcph;
	if(parse_tcphdr(nh, data_end, &tcph) == -1 ) return XDP_DROP;
	
	__u16 dport = bpf_ntohs(tcph->dest);
	bpf_printk("HIT: PROTOCOL TCP - number: %d, checking port number, subnet_id=%u ", IPPROTO_TCP, subnet_id);


	bpf_printk("PORT NUMBER: %u", dport);
	struct rule_id id = {
		.subnet_id = subnet_id,	       
		.proto = (int)IPPROTO_TCP,
		.port = (__u32)dport
	};
	__u8 *k = (void *)&id;

	bpf_printk("KEY BYTES: %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x",
			k[0], k[1], k[2], k[3],
			k[4], k[5], k[6], k[7],
			k[8], k[9], k[10], k[11]);	
	__u32 *rc = bpf_map_lookup_elem(&rule_map, &id);

	if(!rc){
		bpf_printk("RULE MISS: subnet=%u proto=%d port=%u, pointer val: %p", id.subnet_id, id.proto, id.port, (void *)rc);
		return *default_rc;
	}

	bpf_printk("Action obtained, value= %d", *rc);
	return *rc;
}

static __always_inline int handle_udp(struct hdr_cursor *nh, void *data_end, __u32 subnet_id, __u32 *default_rc){
	struct udphdr *udph;
	if(parse_udphdr(nh, data_end, &udph) == -1 ) return XDP_DROP;
	__u16 dport = bpf_ntohs(udph->dest);
	bpf_printk("HIT: PROTO UDP - number: %d, subnet_id=%u ", IPPROTO_UDP, subnet_id);
	bpf_printk("PORT NUMBER: %u", dport);
	struct rule_id id = {
		.subnet_id = subnet_id,	       
		.proto = IPPROTO_UDP,
		.port = (__u32)dport
	};
	
	__u32 *rc = bpf_map_lookup_elem(&rule_map, &id);

	if(!rc){
		return *default_rc;
	}
	bpf_printk("Action obtained, value= %d", *rc);
	return *rc;
}



SEC("xdp")
int xdp_packet_filter(struct xdp_md *ctx){
	void *data = (void *)(long)ctx->data; 
	void *data_end = (void *)(long)ctx->data_end;

	/* Obtaining the default respond */	
	__u32 key = 0;
	__u32 *default_rc = bpf_map_lookup_elem(&default_action_map, &key);
	if(!default_rc) return XDP_DROP;
	bpf_printk("Default action successfully obtained: %d", *default_rc);

	struct ethhdr *ethh;
	struct iphdr *iph;
	
	/* Header cursor */
	struct hdr_cursor nh;
	nh.pos = data;
	
	/* Parse eth header */
       	if(parse_ethhdr(&nh, data_end, &ethh) == -1){
		bpf_printk("DROP: bad eth header"); 
		return XDP_DROP;
	}

	/* Parse ip header */
	if(ethh->h_proto != bpf_htons(ETH_P_IP)){
		bpf_printk("PASS: non-ip ethertype 0x%x", bpf_ntohs(ethh->h_proto));
	       	return XDP_PASS;
	}
	if(parse_iphdr(&nh, data_end, &iph) == -1){
		bpf_printk("DROP: bad ip header"); 
		return XDP_DROP;
	}
	/* Longest prefix matched */
	__u32 src = bpf_ntohl(iph->saddr);

	struct ipv4_lpm_key subnet_key = {
		.prefixlen = 32,
		.addr = src // convert from network order to host order
	};

	__u32 *subnet_id = bpf_map_lookup_elem(&subnet_map, &subnet_key);
	if(!subnet_id){
		bpf_printk("NO SUBNET: src=%x", src);
		return *default_rc;
	}

	bpf_printk("SUBNET HIT: src=%x subnet_id=%u", src, *subnet_id);
	
	/* Parse L4 headers: ICMP,TCP UDP */
	__u32 sid = *subnet_id;
	
	if (iph->protocol == IPPROTO_TCP){
		return handle_tcp(&nh, data_end, sid, default_rc);
	}
	if (iph->protocol == IPPROTO_UDP){
		return handle_udp(&nh, data_end, sid, default_rc);
	}
	if (iph->protocol == IPPROTO_ICMP){
		return handle_icmp(&nh, data_end, sid, default_rc);
	}
	bpf_printk("DEFAULT (unknown proto %u) action=%u", bpf_ntohs(iph->protocol), *default_rc);

	return XDP_DROP;
}

char __license[] SEC("license") = "GPL";
