//go:build ignore

/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-clause) */
/*
 * This file contains parsing functions that are used in the XDP
 * programs. The functions are marked as __always_inline, and fully defined in
 * this header file to be included in the BPF program.
*/
#ifndef __PARSING_HELPERS_H
#define __PARSING_HELPERS_H

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/* Header cursor to keep track of current parsing position */
struct hdr_cursor
{
	void *pos;
};

/* Ethernet header parser */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
										void *data_end,
										struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return eth->h_proto; /* network-byte-order */
}

/* IP and IP_6 header parser*/
static __always_inline int parse_iphdr(struct hdr_cursor *nh,
									   void *data_end,
									   struct iphdr **iphdr)
{
	struct iphdr *ip = nh->pos;
	int hdrsize = sizeof(*ip);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = ip;

	return ip->protocol;
}

static __always_inline int parse_ipv6hdr(struct hdr_cursor *nh,
										void *data_end,
										struct ipv6hdr **ipv6hdr)
{
	struct ipv6hdr *ipv6 = nh->pos;
	int hdrsize = sizeof(*ipv6);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ipv6hdr = ipv6;

	return ipv6->nexthdr;
}

/* ICMP and ICMP_6 parser */
static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
										 void *data_end,
										 struct icmphdr **icmphdr)
{
	struct icmphdr *icmp = nh->pos;
	int hdrsize = sizeof(*icmp);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmphdr = icmp;

	return icmp->type;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
										  void *data_end,
										  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6 = nh->pos;
	int hdrsize = sizeof(*icmp6);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmp6hdr = icmp6;

	return icmp6->icmp6_type;
}

/* TCP and UDP parser */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
										void *data_end,
										struct tcphdr **tcphdr)
{
	struct tcphdr *tcp = nh->pos;
	int hdrsize = sizeof(*tcp);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;

	*tcphdr = tcp;

	return tcp->dest;
}

static __always_inline int parse_udphdr(struct hdr_cursor *nh,
										void *data_end,
										struct udphdr **udphdr)
{
	struct udphdr *udp = nh->pos;
	int hdrsize = sizeof(*udp);

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;

	*udphdr = udp;

	return udp->dest;
}


#endif /* __PARSING_HELPERS_H */
