// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#include "device.h"
#include "peer.h"
#include "socket.h"
#include "queueing.h"
#include "messages.h"

#include <linux/ctype.h>
#include <linux/jhash.h>
#include <linux/net.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/tcp.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/ip6_checksum.h>
#include <net/ip6_tunnel.h>
#include <net/ip_tunnels.h>
#include <net/net_namespace.h>
#include <net/ipv6.h>
#include <net/udp_tunnel.h>
#include <linux/math64.h>
#include <linux/unaligned.h>

static LIST_HEAD(tcpwg_devices);
static DEFINE_SPINLOCK(tcpwg_devices_lock);

enum {
	TCPWG_SYN = 0x02,
	TCPWG_PSH = 0x08,
	TCPWG_ACK = 0x10
};

#define TCPWG_FAKE_HANDSHAKE_TIMEOUT (3 * HZ)
#define TCPWG_FAKE_KEEPALIVE_INTERVAL (20 * HZ)
#define TCPWG_FAKE_IDLE_TIMEOUT (120 * HZ)
#define TCPWG_FAKE_EPOCH_TIMEOUT (REJECT_AFTER_TIME * HZ)
#define TCPWG_PEERLESS_BUCKET_BITS 8
#define TCPWG_PEERLESS_BUCKETS (1U << TCPWG_PEERLESS_BUCKET_BITS)
#define TCPWG_PEERLESS_MAX 4096
#define TCPWG_FAKE_DSCP_TOS 0xb8 /* EF / DSCP 46, ECN preserved by callers. */
#define TCPWG_FAKE_WINDOW 64240
#define TCPWG_FAKE_WSCALE 14
#define TCPWG_TCP_TS_OPT_LEN 12
#define TCPWG_TCP_SYN_OPT_LEN TCPWG_TCP_MAX_OPT_LEN
#define TCPWG_TCP_MIN_MSS4 536
#define TCPWG_TCP_MIN_MSS6 1220
#define TCPWG_FAKE_DELAYED_ACK_INTERVAL (HZ / 20)
#define TCPWG_FAKE_ACK_PACKETS_MIN 2
#define TCPWG_FAKE_ACK_PACKETS_DEFAULT 16
#define TCPWG_FAKE_ACK_PACKETS_MAX 16
#define TCPWG_FAKE_ACK_RATE_WINDOW HZ
#define TCPWG_FAKE_ACK_RATE_4_BPS (50ULL * 1000 * 1000 / 8)
#define TCPWG_FAKE_ACK_RATE_8_BPS (150ULL * 1000 * 1000 / 8)
#define TCPWG_FAKE_ACK_RATE_16_BPS (350ULL * 1000 * 1000 / 8)
#define TCPWG_FAKE_CONTROL_RETRY_INTERVAL HZ
#define TCPWG_FAKE_CONTROL_MAX_RETRIES 2

struct tcpwg_peerless_flow {
	struct hlist_node hnode;
	struct wg_device *wg;
	struct endpoint endpoint;
	u8 state;
	u32 local_isn;
	u32 peer_isn;
	u32 tx_seq;
	u32 rx_seq;
	u32 ts_recent;
	u8 rx_packets_since_ack;
	u8 rx_ack_target;
	bool ts_enabled;
	u64 rx_ack_bytes;
	unsigned long rx_ack_window_start;
	unsigned long state_since;
	unsigned long last_seen;
	unsigned long last_data;
};

struct tcpwg_ack_reply {
	bool send;
	u32 seq;
	u32 ack_seq;
	bool ts_enabled;
	u32 ts_ecr;
};

static u8 tcpwg_fake_ack_target_for_rate(u64 bytes_per_sec)
{
	if (bytes_per_sec >= TCPWG_FAKE_ACK_RATE_16_BPS)
		return 16;
	if (bytes_per_sec >= TCPWG_FAKE_ACK_RATE_8_BPS)
		return 8;
	if (bytes_per_sec >= TCPWG_FAKE_ACK_RATE_4_BPS)
		return 4;
	return TCPWG_FAKE_ACK_PACKETS_MIN;
}

static u8 tcpwg_fake_note_rx_payload(u8 *ack_target, u64 *ack_bytes,
				     unsigned long *window_start,
				     size_t payload_len, unsigned long now)
{
	unsigned long elapsed;
	u64 bytes_per_sec;

	if (!*ack_target)
		*ack_target = TCPWG_FAKE_ACK_PACKETS_DEFAULT;
	if (!*window_start)
		*window_start = now;

	*ack_bytes += payload_len;
	elapsed = now - *window_start;
	if (time_before(now, *window_start + TCPWG_FAKE_ACK_RATE_WINDOW))
		return *ack_target;

	bytes_per_sec = div64_u64(*ack_bytes * HZ, max_t(unsigned long,
							elapsed, 1));
	*ack_target = min_t(u8, tcpwg_fake_ack_target_for_rate(bytes_per_sec),
			    TCPWG_FAKE_ACK_PACKETS_MAX);
	*ack_bytes = 0;
	*window_start = now;
	return *ack_target;
}

static void tcpwg_fake_reset_rx_ack(u8 *ack_target, u64 *ack_bytes,
				    unsigned long *window_start,
				    unsigned long now)
{
	*ack_target = TCPWG_FAKE_ACK_PACKETS_DEFAULT;
	*ack_bytes = 0;
	*window_start = now;
}

static struct hlist_head tcpwg_peerless_flows[TCPWG_PEERLESS_BUCKETS];
static DEFINE_SPINLOCK(tcpwg_peerless_lock);
static atomic_t tcpwg_peerless_count = ATOMIC_INIT(0);
static void tcpwg_peerless_maintenance_work(struct work_struct *work);
static DECLARE_DELAYED_WORK(tcpwg_peerless_maintenance,
			    tcpwg_peerless_maintenance_work);

static void tcpwg_fake_destructor(struct sk_buff *skb)
{
}

static u8 skb_outer_proto(const struct sk_buff *skb)
{
	if (skb->protocol == htons(ETH_P_IP))
		return ip_hdr(skb)->protocol;
	if (IS_ENABLED(CONFIG_IPV6) && skb->protocol == htons(ETH_P_IPV6))
		return ipv6_hdr(skb)->nexthdr;
	return 0;
}

static size_t tcpwg_tcp_opt_len(u8 flags, bool ts_enabled)
{
	if (flags & TCPWG_SYN)
		return ts_enabled ? TCPWG_TCP_SYN_OPT_LEN : 12;
	return ts_enabled ? TCPWG_TCP_TS_OPT_LEN : 0;
}

static size_t tcpwg_tcp_hdr_len(u8 flags, bool ts_enabled)
{
	return sizeof(struct tcphdr) + tcpwg_tcp_opt_len(flags, ts_enabled);
}

static u32 tcpwg_tcp_tsval(void)
{
	return jiffies_to_msecs(jiffies);
}

static u16 tcpwg_tcp_mss(unsigned int mtu, unsigned int ip_hdr_len,
			 unsigned int min_mss)
{
	unsigned int mss;

	if (mtu <= ip_hdr_len + sizeof(struct tcphdr))
		return min_mss;
	mss = mtu - ip_hdr_len - sizeof(struct tcphdr);
	return min_t(unsigned int, U16_MAX, max(mss, min_mss));
}

static bool tcpwg_tcp_get_timestamp(const struct tcphdr *tcp, u32 *tsval,
				    u32 *tsecr)
{
	const u8 *opt = (const u8 *)(tcp + 1);
	unsigned int opt_len;

	if (tcp->doff < sizeof(*tcp) / 4)
		return false;
	opt_len = tcp->doff * 4 - sizeof(*tcp);

	while (opt_len) {
		u8 kind, len;

		kind = opt[0];
		if (kind == TCPOPT_EOL)
			break;
		if (kind == TCPOPT_NOP) {
			++opt;
			--opt_len;
			continue;
		}
		if (opt_len < 2)
			break;
		len = opt[1];
		if (len < 2 || len > opt_len)
			break;
		if (kind == TCPOPT_TIMESTAMP && len == TCPOLEN_TIMESTAMP) {
			if (tsval)
				*tsval = get_unaligned_be32(opt + 2);
			if (tsecr)
				*tsecr = get_unaligned_be32(opt + 6);
			return true;
		}
		opt += len;
		opt_len -= len;
	}
	return false;
}

static bool tcpwg_tcp_note_timestamp(const struct tcphdr *tcp, u32 *ts_recent)
{
	u32 tsval;

	if (!tcpwg_tcp_get_timestamp(tcp, &tsval, NULL))
		return false;
	*ts_recent = tsval;
	return true;
}

static void tcpwg_fill_header(struct tcphdr *tcp, __be16 source, __be16 dest,
			      u8 flags, u32 seq, u32 ack_seq,
			      bool ts_enabled, u32 ts_ecr, u16 mss)
{
	u8 *opt;
	size_t opt_len = tcpwg_tcp_opt_len(flags, ts_enabled);

	memset(tcp, 0, sizeof(*tcp));
	tcp->source = source;
	tcp->dest = dest;
	tcp->seq = htonl(seq);
	tcp->ack_seq = htonl(ack_seq);
	tcp->doff = (sizeof(*tcp) + opt_len) / 4;
	tcp->window = htons(TCPWG_FAKE_WINDOW);
	tcp->syn = !!(flags & TCPWG_SYN);
	tcp->ack = !!(flags & TCPWG_ACK);
	tcp->psh = !!(flags & TCPWG_PSH);

	opt = (u8 *)(tcp + 1);
	if (flags & TCPWG_SYN) {
		*opt++ = TCPOPT_MSS;
		*opt++ = TCPOLEN_MSS;
		put_unaligned_be16(mss, opt);
		opt += sizeof(__be16);
		*opt++ = TCPOPT_SACK_PERM;
		*opt++ = TCPOLEN_SACK_PERM;
		if (ts_enabled) {
			*opt++ = TCPOPT_TIMESTAMP;
			*opt++ = TCPOLEN_TIMESTAMP;
			put_unaligned_be32(tcpwg_tcp_tsval(), opt);
			opt += sizeof(__be32);
			put_unaligned_be32(ts_ecr, opt);
			opt += sizeof(__be32);
		}
		*opt++ = TCPOPT_NOP;
		*opt++ = TCPOPT_WINDOW;
		*opt++ = TCPOLEN_WINDOW;
		*opt++ = TCPWG_FAKE_WSCALE;
		while ((u8 *)tcp + sizeof(*tcp) + opt_len > opt)
			*opt++ = TCPOPT_EOL;
	} else if (ts_enabled) {
		*opt++ = TCPOPT_NOP;
		*opt++ = TCPOPT_NOP;
		*opt++ = TCPOPT_TIMESTAMP;
		*opt++ = TCPOLEN_TIMESTAMP;
		put_unaligned_be32(tcpwg_tcp_tsval(), opt);
		opt += sizeof(__be32);
		put_unaligned_be32(ts_ecr, opt);
	}
}

static bool tcpwg_dev_can_checksum(const struct net_device *dev, bool ipv6)
{
	if (!dev)
		return false;
	if (dev->features & NETIF_F_HW_CSUM)
		return true;
#ifdef NETIF_F_IP_CSUM
	if (!ipv6 && (dev->features & NETIF_F_IP_CSUM))
		return true;
#endif
#ifdef NETIF_F_V4_CSUM
	if (!ipv6 && (dev->features & NETIF_F_V4_CSUM))
		return true;
#endif
#ifdef NETIF_F_IPV6_CSUM
	if (ipv6 && (dev->features & NETIF_F_IPV6_CSUM))
		return true;
#endif
	return false;
}

static bool tcpwg_try_partial_csum(struct sk_buff *skb,
				   const struct net_device *dev,
				   __sum16 pseudo_header, bool ipv6)
{
	struct tcphdr *tcp = tcp_hdr(skb);
	unsigned int csum_start;

	if (unlikely(skb->ip_summed == CHECKSUM_PARTIAL))
		return false;
	if (!tcpwg_dev_can_checksum(dev, ipv6))
		return false;
	if (skb_is_nonlinear(skb) && !(dev->features & NETIF_F_SG))
		return false;
	if (unlikely(skb_transport_header(skb) < skb->head ||
		     skb_transport_header(skb) + sizeof(*tcp) >
			     skb_tail_pointer(skb)))
		return false;

	csum_start = skb_transport_header(skb) - skb->head;
	if (unlikely(csum_start > U16_MAX))
		return false;

	tcp->check = pseudo_header;
	skb->ip_summed = CHECKSUM_PARTIAL;
	skb->csum_start = csum_start;
	skb->csum_offset = offsetof(struct tcphdr, check);
	return true;
}

static void tcpwg_set_v4_csum(struct sk_buff *skb,
			      const struct net_device *dev, __be32 src,
			      __be32 dst)
{
	struct tcphdr *tcp = tcp_hdr(skb);

	tcp->check = 0;
	if (tcpwg_try_partial_csum(skb, dev,
				   ~csum_tcpudp_magic(src, dst, skb->len,
						      IPPROTO_TCP, 0), false))
		return;

	tcp->check = csum_tcpudp_magic(src, dst, skb->len, IPPROTO_TCP,
				       skb_checksum(skb, 0, skb->len, 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}

#if IS_ENABLED(CONFIG_IPV6)
static void tcpwg_set_v6_csum(struct sk_buff *skb, const struct in6_addr *src,
			      const struct in6_addr *dst,
			      const struct net_device *dev)
{
	struct tcphdr *tcp = tcp_hdr(skb);

	tcp->check = 0;
	if (tcpwg_try_partial_csum(skb, dev,
				   ~csum_ipv6_magic(src, dst, skb->len,
						    IPPROTO_TCP, 0), true))
		return;

	tcp->check = csum_ipv6_magic(src, dst, skb->len, IPPROTO_TCP,
				     skb_checksum(skb, 0, skb->len, 0));
	skb->ip_summed = CHECKSUM_UNNECESSARY;
}
#endif

static void tcpwg_setup_skb_sock(struct sock *sock, struct sk_buff *skb)
{
	if (!skb->sk)
		skb->sk = sock;
	if (!skb->destructor)
		skb->destructor = tcpwg_fake_destructor;
}

static void tcpwg_tunnel_xmit4(struct rtable *rt, struct sock *sock,
			       struct sk_buff *skb, __be32 src, __be32 dst,
			       u8 ds, u8 ttl, __be16 sport, __be16 dport,
			       u8 flags, u32 seq, u32 ack_seq,
			       bool ts_enabled, u32 ts_ecr)
{
	struct tcphdr *tcp;
	size_t tcp_len = tcpwg_tcp_hdr_len(flags, ts_enabled);
	u16 mss = tcpwg_tcp_mss(dst_mtu(&rt->dst), sizeof(struct iphdr),
				TCPWG_TCP_MIN_MSS4);

	__skb_push(skb, tcp_len);
	skb_reset_transport_header(skb);
	tcp = tcp_hdr(skb);
	tcpwg_fill_header(tcp, sport, dport, flags, seq, ack_seq,
			  ts_enabled, ts_ecr, mss);

	memset(&IPCB(skb)->opt, 0, sizeof(IPCB(skb)->opt));
	tcpwg_set_v4_csum(skb, rt->dst.dev, src, dst);
	tcpwg_setup_skb_sock(sock, skb);

	iptunnel_xmit(
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
			   sock,
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0) && LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
			   dev_net(skb->dev),
#endif
			   rt, skb, src, dst, IPPROTO_TCP, ds, ttl, 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0) || LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
			   , false
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
			   , 0
#endif
	     );
}

static int tcpwg_send_empty(struct wg_device *wg, struct endpoint *endpoint,
			    u8 flags, u32 seq, u32 ack_seq,
			    bool ts_enabled, u32 ts_ecr);

#if IS_ENABLED(CONFIG_NETFILTER)
static void tcpwg_list_set(struct wg_device *wg, bool active)
{
	spin_lock_bh(&tcpwg_devices_lock);
	if (active) {
		if (list_empty(&wg->tcpwg_list))
			list_add(&wg->tcpwg_list, &tcpwg_devices);
	} else if (!list_empty(&wg->tcpwg_list)) {
		list_del_init(&wg->tcpwg_list);
	}
	spin_unlock_bh(&tcpwg_devices_lock);
}

static struct wg_device *tcpwg_lookup_device(struct net *net, __be16 port)
{
	struct wg_device *wg, *ret = NULL;
	u16 host_port = ntohs(port);

	spin_lock_bh(&tcpwg_devices_lock);
	list_for_each_entry(wg, &tcpwg_devices, tcpwg_list) {
		if (wg->incoming_port == host_port &&
		    rcu_access_pointer(wg->creating_net) == net &&
		    netif_running(wg->dev)) {
			dev_hold(wg->dev);
			ret = wg;
			break;
		}
	}
	spin_unlock_bh(&tcpwg_devices_lock);

	return ret;
}

static bool tcpwg_endpoint_equal(const struct endpoint *a,
				 const struct endpoint *b)
{
	if (a->addr.sa_family != b->addr.sa_family)
		return false;
	if (a->addr.sa_family == AF_INET)
		return a->addr4.sin_port == b->addr4.sin_port &&
		       a->addr4.sin_addr.s_addr == b->addr4.sin_addr.s_addr;
	if (IS_ENABLED(CONFIG_IPV6) && a->addr.sa_family == AF_INET6)
		return a->addr6.sin6_port == b->addr6.sin6_port &&
		       a->addr6.sin6_scope_id == b->addr6.sin6_scope_id &&
		       ipv6_addr_equal(&a->addr6.sin6_addr,
				       &b->addr6.sin6_addr);
	return false;
}

static bool tcpwg_endpoint_tuple_equal(const struct endpoint *a,
				       const struct endpoint *b)
{
	if (a->addr.sa_family != b->addr.sa_family)
		return false;
	if (a->addr.sa_family == AF_INET)
		return a->addr4.sin_port == b->addr4.sin_port &&
		       a->addr4.sin_addr.s_addr == b->addr4.sin_addr.s_addr &&
		       a->src4.s_addr == b->src4.s_addr &&
		       a->src_if4 == b->src_if4;
	if (IS_ENABLED(CONFIG_IPV6) && a->addr.sa_family == AF_INET6)
		return a->addr6.sin6_port == b->addr6.sin6_port &&
		       a->addr6.sin6_scope_id == b->addr6.sin6_scope_id &&
		       ipv6_addr_equal(&a->addr6.sin6_addr,
				       &b->addr6.sin6_addr) &&
		       ipv6_addr_equal(&a->src6, &b->src6);
	return false;
}

static u32 tcpwg_peerless_hash(struct wg_device *wg,
			       const struct endpoint *endpoint)
{
	u32 hash = jhash(&wg, sizeof(wg), endpoint->addr.sa_family);

	if (endpoint->addr.sa_family == AF_INET) {
		hash = jhash(&endpoint->addr4.sin_port,
			     sizeof(endpoint->addr4.sin_port), hash);
		hash = jhash(&endpoint->addr4.sin_addr.s_addr,
			     sizeof(endpoint->addr4.sin_addr.s_addr), hash);
		hash = jhash(&endpoint->src4.s_addr,
			     sizeof(endpoint->src4.s_addr), hash);
		hash = jhash(&endpoint->src_if4,
			     sizeof(endpoint->src_if4), hash);
	} else if (IS_ENABLED(CONFIG_IPV6) &&
		   endpoint->addr.sa_family == AF_INET6) {
		hash = jhash(&endpoint->addr6.sin6_port,
			     sizeof(endpoint->addr6.sin6_port), hash);
		hash = jhash(&endpoint->addr6.sin6_scope_id,
			     sizeof(endpoint->addr6.sin6_scope_id), hash);
		hash = jhash(&endpoint->addr6.sin6_addr,
			     sizeof(endpoint->addr6.sin6_addr), hash);
		hash = jhash(&endpoint->src6, sizeof(endpoint->src6), hash);
	}
	return hash;
}

static struct wg_peer *tcpwg_lookup_peer_by_endpoint(struct wg_device *wg,
						     const struct endpoint *ep)
{
	struct wg_peer *peer, *found = NULL;

	rcu_read_lock_bh();
	list_for_each_entry_rcu(peer, &wg->peer_list, peer_list) {
		read_lock_bh(&peer->endpoint_lock);
		if (!READ_ONCE(peer->is_dead) &&
		    tcpwg_endpoint_equal(&peer->endpoint, ep))
			found = wg_peer_get_maybe_zero(peer);
		read_unlock_bh(&peer->endpoint_lock);
		if (found)
			break;
	}
	rcu_read_unlock_bh();

	return found;
}

static size_t tcpwg_skb_payload_len(const struct sk_buff *skb)
{
	const struct tcphdr *tcp = tcp_hdr(skb);
	size_t ip_len, ip_hdr_len, tcp_hdr_len;

	if (skb->protocol == htons(ETH_P_IP)) {
		ip_hdr_len = ip_hdr(skb)->ihl * 4;
		ip_len = ntohs(ip_hdr(skb)->tot_len);
	} else if (IS_ENABLED(CONFIG_IPV6) &&
		   skb->protocol == htons(ETH_P_IPV6)) {
		ip_hdr_len = sizeof(struct ipv6hdr);
		ip_len = ip_hdr_len + ntohs(ipv6_hdr(skb)->payload_len);
	} else {
		return 0;
	}

	tcp_hdr_len = tcp->doff * 4;
	if (unlikely(ip_len < ip_hdr_len + tcp_hdr_len))
		return 0;

	return ip_len - ip_hdr_len - tcp_hdr_len;
}

static int tcpwg_send_control_from_skb(struct wg_device *wg,
				       const struct sk_buff *skb, u8 flags,
				       u32 seq, u32 ack_seq)
{
	struct endpoint endpoint;
	const struct tcphdr *tcp = tcp_hdr(skb);
	u32 ts_ecr = 0;
	bool ts_enabled;

	if (wg_socket_endpoint_from_skb(&endpoint, skb))
		return -EINVAL;

	ts_enabled = tcpwg_tcp_get_timestamp(tcp, &ts_ecr, NULL);
	return tcpwg_send_empty(wg, &endpoint, flags, seq, ack_seq,
				ts_enabled, ts_ecr);
}

static void tcpwg_ack_reply_set(struct tcpwg_ack_reply *ack, u32 seq,
				u32 ack_seq, bool ts_enabled, u32 ts_ecr)
{
	ack->send = true;
	ack->seq = seq;
	ack->ack_seq = ack_seq;
	ack->ts_enabled = ts_enabled;
	ack->ts_ecr = ts_ecr;
}

static void tcpwg_send_ack_reply(struct wg_device *wg,
				 const struct endpoint *endpoint,
				 const struct tcpwg_ack_reply *ack)
{
	struct endpoint reply_endpoint;

	if (!ack->send)
		return;
	reply_endpoint = *endpoint;
	tcpwg_send_empty(wg, &reply_endpoint, TCPWG_ACK, ack->seq,
			 ack->ack_seq, ack->ts_enabled, ack->ts_ecr);
}

static void tcpwg_fake_schedule_ack(struct wg_peer *peer)
{
	if (unlikely(READ_ONCE(peer->is_dead)))
		return;

	wg_peer_get(peer);
	if (!queue_delayed_work(system_wq, &peer->fake_tcp.ack_work,
				TCPWG_FAKE_DELAYED_ACK_INTERVAL))
		wg_peer_put(peer);
}

static void tcpwg_fake_cancel_ack(struct wg_peer *peer)
{
	if (cancel_delayed_work(&peer->fake_tcp.ack_work))
		wg_peer_put(peer);
}

static void tcpwg_fake_clear_control_retry_locked(struct tcpwg_fake_tcp *state)
{
	state->control_retries = 0;
	state->control_flags = 0;
	state->control_seq = 0;
	state->control_ack_seq = 0;
	state->control_ts_ecr = 0;
	state->control_ts_enabled = false;
	state->control_retry_at = 0;
}

static void tcpwg_fake_note_control_retry_locked(struct tcpwg_fake_tcp *state,
						 u8 flags, u32 seq,
						 u32 ack_seq,
						 bool ts_enabled,
						 u32 ts_ecr,
						 unsigned long now)
{
	state->control_retries = 0;
	state->control_flags = flags;
	state->control_seq = seq;
	state->control_ack_seq = ack_seq;
	state->control_ts_enabled = ts_enabled;
	state->control_ts_ecr = ts_ecr;
	state->control_retry_at = now + TCPWG_FAKE_CONTROL_RETRY_INTERVAL;
}

static bool tcpwg_fake_epoch_expired(const struct wg_peer *peer,
				     const struct tcpwg_fake_tcp *state,
				     unsigned long now)
{
	unsigned long latest = READ_ONCE(peer->last_handshake_jiffies);
	unsigned long base = state->state_since;

	if (latest && time_after(latest, base))
		base = latest;

	return time_after_eq(now, base + TCPWG_FAKE_EPOCH_TIMEOUT);
}

static void tcpwg_fake_start_syn_locked(struct wg_peer *peer,
					const struct endpoint *endpoint,
					unsigned long now, u32 *syn_seq)
{
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;

	state->state = TCPWG_FAKE_SYN_SENT;
	state->local_isn = get_random_u32();
	state->peer_isn = 0;
	state->tx_seq = state->local_isn;
	state->rx_seq = 0;
	state->ts_recent = 0;
	state->ts_enabled = true;
	state->rx_packets_since_ack = 0;
	state->ack_pending = false;
	tcpwg_fake_reset_rx_ack(&state->rx_ack_target, &state->rx_ack_bytes,
				&state->rx_ack_window_start, now);
	tcpwg_fake_note_control_retry_locked(state, TCPWG_SYN,
					     state->local_isn, 0, true, 0,
					     now);
	state->state_since = now;
	state->last_seen = now;
	state->last_data = now;
	state->tuple = *endpoint;
	state->tuple_valid = true;
	*syn_seq = state->local_isn;
}

static unsigned int tcpwg_peerless_bucket(struct wg_device *wg,
					  const struct endpoint *endpoint)
{
	return tcpwg_peerless_hash(wg, endpoint) &
	       (TCPWG_PEERLESS_BUCKETS - 1);
}

static struct tcpwg_peerless_flow *
tcpwg_peerless_lookup_locked(struct wg_device *wg,
			     const struct endpoint *endpoint)
{
	struct tcpwg_peerless_flow *flow;
	unsigned int bucket = tcpwg_peerless_bucket(wg, endpoint);

	hlist_for_each_entry(flow, &tcpwg_peerless_flows[bucket], hnode) {
		if (flow->wg == wg &&
		    tcpwg_endpoint_tuple_equal(&flow->endpoint, endpoint))
			return flow;
	}
	return NULL;
}

static bool tcpwg_peerless_expired(const struct tcpwg_peerless_flow *flow,
				   unsigned long now)
{
	switch (flow->state) {
	case TCPWG_FAKE_SYN_RECEIVED:
		return time_after_eq(now, flow->state_since +
					  TCPWG_FAKE_HANDSHAKE_TIMEOUT);
	case TCPWG_FAKE_ESTABLISHED:
		return time_after_eq(now, flow->last_data +
					  TCPWG_FAKE_IDLE_TIMEOUT) ||
		       time_after_eq(now, flow->state_since +
					  TCPWG_FAKE_EPOCH_TIMEOUT);
	case TCPWG_FAKE_CLOSE_WAIT:
	case TCPWG_FAKE_CLOSED:
	default:
		return time_after_eq(now, flow->state_since +
					  TCPWG_FAKE_HANDSHAKE_TIMEOUT);
	}
}

static void tcpwg_peerless_unlink_locked(struct tcpwg_peerless_flow *flow,
					 struct hlist_head *free_list)
{
	hlist_del_init(&flow->hnode);
	atomic_dec(&tcpwg_peerless_count);
	hlist_add_head(&flow->hnode, free_list);
}

static void tcpwg_peerless_collect_locked(struct wg_device *wg,
					  bool expired_only,
					  unsigned long now,
					  struct hlist_head *free_list)
{
	struct tcpwg_peerless_flow *flow;
	struct hlist_node *tmp;
	unsigned int i;

	for (i = 0; i < TCPWG_PEERLESS_BUCKETS; ++i) {
		hlist_for_each_entry_safe(flow, tmp,
					  &tcpwg_peerless_flows[i], hnode) {
			if (wg && flow->wg != wg)
				continue;
			if (expired_only && !tcpwg_peerless_expired(flow, now))
				continue;
			tcpwg_peerless_unlink_locked(flow, free_list);
		}
	}
}

static void tcpwg_peerless_free_list(struct hlist_head *free_list)
{
	struct tcpwg_peerless_flow *flow;
	struct hlist_node *tmp;

	hlist_for_each_entry_safe(flow, tmp, free_list, hnode) {
		hlist_del(&flow->hnode);
		dev_put(flow->wg->dev);
		kfree(flow);
	}
}

static void tcpwg_peerless_schedule_maintenance(void)
{
	if (atomic_read(&tcpwg_peerless_count))
		queue_delayed_work(system_wq, &tcpwg_peerless_maintenance,
				   TCPWG_FAKE_HANDSHAKE_TIMEOUT);
}

static void tcpwg_peerless_maintenance_work(struct work_struct *work)
{
	HLIST_HEAD(free_list);
	bool reschedule;

	spin_lock_bh(&tcpwg_peerless_lock);
	tcpwg_peerless_collect_locked(NULL, true, jiffies, &free_list);
	reschedule = atomic_read(&tcpwg_peerless_count) > 0;
	spin_unlock_bh(&tcpwg_peerless_lock);

	tcpwg_peerless_free_list(&free_list);
	if (reschedule)
		tcpwg_peerless_schedule_maintenance();
}

static void tcpwg_peerless_purge_wg(struct wg_device *wg)
{
	HLIST_HEAD(free_list);

	spin_lock_bh(&tcpwg_peerless_lock);
	tcpwg_peerless_collect_locked(wg, false, jiffies, &free_list);
	spin_unlock_bh(&tcpwg_peerless_lock);

	tcpwg_peerless_free_list(&free_list);
}

static void tcpwg_peerless_purge_all(void)
{
	HLIST_HEAD(free_list);

	spin_lock_bh(&tcpwg_peerless_lock);
	tcpwg_peerless_collect_locked(NULL, false, jiffies, &free_list);
	spin_unlock_bh(&tcpwg_peerless_lock);

	tcpwg_peerless_free_list(&free_list);
}

static bool tcpwg_peerless_create_syn(struct wg_device *wg,
				      const struct endpoint *endpoint,
				      u32 seq, bool ts_enabled,
				      u32 ts_recent, u32 *local_isn)
{
	struct tcpwg_peerless_flow *flow, *new_flow;
	unsigned int bucket = tcpwg_peerless_bucket(wg, endpoint);
	HLIST_HEAD(free_list);
	unsigned long now = jiffies;
	bool send_synack = false;

	new_flow = kzalloc(sizeof(*new_flow), GFP_ATOMIC);
	if (!new_flow)
		return false;

	spin_lock_bh(&tcpwg_peerless_lock);
	flow = tcpwg_peerless_lookup_locked(wg, endpoint);
	if (flow && tcpwg_peerless_expired(flow, now)) {
		tcpwg_peerless_unlink_locked(flow, &free_list);
		flow = NULL;
	}
	if (flow && flow->state == TCPWG_FAKE_ESTABLISHED) {
		flow->state = TCPWG_FAKE_SYN_RECEIVED;
		flow->local_isn = get_random_u32();
		flow->peer_isn = seq;
		flow->tx_seq = flow->local_isn + 1;
		flow->rx_seq = seq + 1;
		flow->ts_enabled = ts_enabled;
		flow->ts_recent = ts_enabled ? ts_recent : 0;
		flow->rx_packets_since_ack = 0;
		tcpwg_fake_reset_rx_ack(&flow->rx_ack_target,
					&flow->rx_ack_bytes,
					&flow->rx_ack_window_start, now);
		flow->state_since = now;
		flow->last_seen = now;
		flow->last_data = now;
		*local_isn = flow->local_isn;
		send_synack = true;
		goto out;
	}
	if (flow && flow->state == TCPWG_FAKE_SYN_RECEIVED &&
	    flow->peer_isn == seq) {
		if (ts_enabled) {
			flow->ts_enabled = true;
			flow->ts_recent = ts_recent;
		}
		flow->last_seen = now;
		*local_isn = flow->local_isn;
		send_synack = true;
		goto out;
	}
	if (flow) {
		flow->last_seen = now;
		goto out;
	}
	if (atomic_read(&tcpwg_peerless_count) >= TCPWG_PEERLESS_MAX) {
		tcpwg_peerless_collect_locked(NULL, true, now, &free_list);
		if (atomic_read(&tcpwg_peerless_count) >=
		    TCPWG_PEERLESS_MAX)
			goto out;
	}

	dev_hold(wg->dev);
	new_flow->wg = wg;
	new_flow->endpoint = *endpoint;
	new_flow->state = TCPWG_FAKE_SYN_RECEIVED;
	new_flow->local_isn = get_random_u32();
	new_flow->peer_isn = seq;
	new_flow->tx_seq = new_flow->local_isn + 1;
	new_flow->rx_seq = seq + 1;
	new_flow->ts_enabled = ts_enabled;
	new_flow->ts_recent = ts_enabled ? ts_recent : 0;
	new_flow->rx_packets_since_ack = 0;
	tcpwg_fake_reset_rx_ack(&new_flow->rx_ack_target,
				&new_flow->rx_ack_bytes,
				&new_flow->rx_ack_window_start, now);
	new_flow->state_since = now;
	new_flow->last_seen = now;
	new_flow->last_data = now;
	*local_isn = new_flow->local_isn;
	hlist_add_head(&new_flow->hnode, &tcpwg_peerless_flows[bucket]);
	atomic_inc(&tcpwg_peerless_count);
	new_flow = NULL;
	send_synack = true;

out:
	spin_unlock_bh(&tcpwg_peerless_lock);
	tcpwg_peerless_free_list(&free_list);
	kfree(new_flow);
	if (send_synack)
		tcpwg_peerless_schedule_maintenance();
	return send_synack;
}

static bool tcpwg_peerless_ack(struct wg_device *wg,
			       const struct endpoint *endpoint,
			       const struct tcphdr *tcp)
{
	struct tcpwg_peerless_flow *flow;
	HLIST_HEAD(free_list);
	unsigned long now = jiffies;
	u32 seq = ntohl(tcp->seq), ack_seq = ntohl(tcp->ack_seq);
	u32 ts_recent;
	bool ts_enabled;
	bool established = false;

	ts_enabled = tcpwg_tcp_note_timestamp(tcp, &ts_recent);

	spin_lock_bh(&tcpwg_peerless_lock);
	flow = tcpwg_peerless_lookup_locked(wg, endpoint);
	if (!flow)
		goto out;
	if (tcpwg_peerless_expired(flow, now)) {
		tcpwg_peerless_unlink_locked(flow, &free_list);
		goto out;
	}
	if (flow->state == TCPWG_FAKE_SYN_RECEIVED &&
	    seq == flow->rx_seq &&
	    ack_seq == flow->local_isn + 1) {
		flow->tx_seq = flow->local_isn + 1;
		flow->ts_enabled = ts_enabled;
		flow->ts_recent = ts_enabled ? ts_recent : 0;
		flow->rx_packets_since_ack = 0;
		tcpwg_fake_reset_rx_ack(&flow->rx_ack_target,
					&flow->rx_ack_bytes,
					&flow->rx_ack_window_start, now);
		flow->state = TCPWG_FAKE_ESTABLISHED;
		flow->state_since = now;
		flow->last_seen = now;
		flow->last_data = now;
		established = true;
	} else if (flow->state == TCPWG_FAKE_ESTABLISHED) {
		if (ts_enabled) {
			flow->ts_enabled = true;
			flow->ts_recent = ts_recent;
		}
		flow->last_seen = now;
	}

out:
	spin_unlock_bh(&tcpwg_peerless_lock);
	tcpwg_peerless_free_list(&free_list);
	if (established) {
		tcpwg_peerless_schedule_maintenance();
	}
	return true;
}

static bool tcpwg_peerless_fin(struct wg_device *wg,
			       const struct endpoint *endpoint,
			       const struct tcphdr *tcp,
			       size_t payload_len,
			       u32 *tx_seq, u32 *rx_seq)
{
	struct tcpwg_peerless_flow *flow;
	HLIST_HEAD(free_list);
	unsigned long now = jiffies;
	u32 seq = ntohl(tcp->seq);
	u32 ts_recent;
	bool ts_enabled;
	bool send_ack = false;

	ts_enabled = tcpwg_tcp_note_timestamp(tcp, &ts_recent);

	spin_lock_bh(&tcpwg_peerless_lock);
	flow = tcpwg_peerless_lookup_locked(wg, endpoint);
	if (!flow)
		goto out;
	if (tcpwg_peerless_expired(flow, now)) {
		tcpwg_peerless_unlink_locked(flow, &free_list);
		goto out;
	}
	if (flow->state == TCPWG_FAKE_ESTABLISHED) {
		flow->rx_seq = seq + payload_len + 1;
		if (ts_enabled) {
			flow->ts_enabled = true;
			flow->ts_recent = ts_recent;
		}
		flow->state = TCPWG_FAKE_CLOSE_WAIT;
		flow->state_since = now;
		flow->last_seen = now;
		*tx_seq = flow->tx_seq;
		*rx_seq = flow->rx_seq;
		send_ack = true;
	}

out:
	spin_unlock_bh(&tcpwg_peerless_lock);
	tcpwg_peerless_free_list(&free_list);
	return send_ack;
}

static bool tcpwg_peerless_handle_control(struct wg_device *wg,
					  struct sk_buff *skb,
					  const struct endpoint *endpoint,
					  const struct tcphdr *tcp,
					  size_t payload_len)
{
	u32 local_isn = 0, tx_seq = 0, rx_seq = 0;
	u32 ts_recent = 0;
	bool ts_enabled;

	if (tcp->rst)
		return true;

	if (tcp->fin) {
		if (tcpwg_peerless_fin(wg, endpoint, tcp, payload_len,
				       &tx_seq, &rx_seq))
			tcpwg_send_control_from_skb(wg, skb, TCPWG_ACK,
						    tx_seq, rx_seq);
		return true;
	}

	if (tcp->syn && !tcp->ack) {
		ts_enabled = tcpwg_tcp_note_timestamp(tcp, &ts_recent);
		if (tcpwg_peerless_create_syn(wg, endpoint, ntohl(tcp->seq),
					      ts_enabled, ts_recent, &local_isn))
			tcpwg_send_control_from_skb(wg, skb,
						    TCPWG_SYN | TCPWG_ACK,
						    local_isn,
						    ntohl(tcp->seq) + 1);
		return true;
	}

	if (tcp->syn && tcp->ack)
		return true;

	if (tcp->ack && !payload_len)
		return tcpwg_peerless_ack(wg, endpoint, tcp);

	return false;
}

static bool tcpwg_peerless_accept_data(struct wg_device *wg,
				       const struct endpoint *endpoint,
				       const struct tcphdr *tcp,
				       size_t payload_len,
				       struct tcpwg_ack_reply *ack)
{
	struct tcpwg_peerless_flow *flow;
	HLIST_HEAD(free_list);
	unsigned long now = jiffies;
	u32 seq = ntohl(tcp->seq);
	u32 end_seq;
	u32 ts_recent;
	u8 ack_target;
	bool ts_enabled;
	bool accept = false;

	if (!tcp->ack || tcp->syn || !payload_len)
		return false;
	ts_enabled = tcpwg_tcp_note_timestamp(tcp, &ts_recent);

	spin_lock_bh(&tcpwg_peerless_lock);
	flow = tcpwg_peerless_lookup_locked(wg, endpoint);
	if (!flow)
		goto out;
	if (tcpwg_peerless_expired(flow, now)) {
		tcpwg_peerless_unlink_locked(flow, &free_list);
		goto out;
	}
	if (flow->state != TCPWG_FAKE_ESTABLISHED)
		goto out;

	flow->last_seen = now;
	if (ts_enabled) {
		flow->ts_enabled = true;
		flow->ts_recent = ts_recent;
	}

	end_seq = seq + payload_len;
	flow->last_data = now;
	if (after(end_seq, flow->rx_seq) || !flow->rx_seq)
		flow->rx_seq = end_seq;
	ack_target = tcpwg_fake_note_rx_payload(&flow->rx_ack_target,
						&flow->rx_ack_bytes,
						&flow->rx_ack_window_start,
						payload_len, now);
	if (++flow->rx_packets_since_ack >= ack_target) {
		tcpwg_ack_reply_set(ack, flow->tx_seq, flow->rx_seq,
				    flow->ts_enabled,
				    flow->ts_enabled ? flow->ts_recent : 0);
		flow->rx_packets_since_ack = 0;
	}
	accept = true;

out:
	spin_unlock_bh(&tcpwg_peerless_lock);
	tcpwg_peerless_free_list(&free_list);
	return accept;
}

static bool tcpwg_peerless_prepare_reply(struct wg_device *wg,
					 const struct endpoint *endpoint,
					 const struct sk_buff *skb,
					 u32 *seq, u32 *ack_seq,
					 bool *ts_enabled, u32 *ts_ecr)
{
	struct tcpwg_peerless_flow *flow;
	HLIST_HEAD(free_list);
	unsigned long now = jiffies;
	bool prepared = false;

	spin_lock_bh(&tcpwg_peerless_lock);
	flow = tcpwg_peerless_lookup_locked(wg, endpoint);
	if (!flow)
		goto out;
	if (tcpwg_peerless_expired(flow, now)) {
		tcpwg_peerless_unlink_locked(flow, &free_list);
		goto out;
	}
	if (flow->state != TCPWG_FAKE_ESTABLISHED)
		goto out;

	*seq = flow->tx_seq;
	*ack_seq = flow->rx_seq;
	*ts_enabled = flow->ts_enabled;
	*ts_ecr = flow->ts_enabled ? flow->ts_recent : 0;
	flow->rx_packets_since_ack = 0;
	flow->tx_seq += max_t(u32, 1U, skb->len);
	flow->last_seen = now;
	flow->last_data = now;
	prepared = true;

out:
	spin_unlock_bh(&tcpwg_peerless_lock);
	tcpwg_peerless_free_list(&free_list);
	if (prepared)
		tcpwg_peerless_schedule_maintenance();
	return prepared;
}

static bool tcpwg_peerless_bind_to_peer_locked(struct wg_peer *peer,
					       const struct endpoint *endpoint)
{
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;
	struct tcpwg_peerless_flow *flow;
	HLIST_HEAD(free_list);
	unsigned long now = jiffies;
	bool bound = false;

	spin_lock_bh(&tcpwg_peerless_lock);
	flow = tcpwg_peerless_lookup_locked(peer->device, endpoint);
	if (!flow)
		goto out;
	if (tcpwg_peerless_expired(flow, now) ||
	    flow->state != TCPWG_FAKE_ESTABLISHED) {
		tcpwg_peerless_unlink_locked(flow, &free_list);
		goto out;
	}

	state->state = TCPWG_FAKE_ESTABLISHED;
	state->local_isn = flow->local_isn;
	state->peer_isn = flow->peer_isn;
	state->tx_seq = flow->tx_seq;
	state->rx_seq = flow->rx_seq;
	state->ts_recent = flow->ts_recent;
	state->ts_enabled = flow->ts_enabled;
	state->state_since = flow->state_since;
	state->last_seen = now;
	state->last_data = flow->last_data;
	state->tuple = *endpoint;
	state->tuple_valid = true;
	tcpwg_peerless_unlink_locked(flow, &free_list);
	bound = true;

out:
	spin_unlock_bh(&tcpwg_peerless_lock);
	tcpwg_peerless_free_list(&free_list);
	return bound;
}

static void tcpwg_fake_reset_locked(struct wg_peer *peer,
				    const struct endpoint *ep)
{
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;

	state->state = TCPWG_FAKE_CLOSED;
	state->local_isn = get_random_u32();
	state->peer_isn = 0;
	state->tx_seq = state->local_isn;
	state->rx_seq = 0;
	state->ts_recent = 0;
	state->ts_enabled = true;
	state->rx_packets_since_ack = 0;
	state->ack_pending = false;
	tcpwg_fake_reset_rx_ack(&state->rx_ack_target, &state->rx_ack_bytes,
				&state->rx_ack_window_start, jiffies);
	tcpwg_fake_clear_control_retry_locked(state);
	state->state_since = jiffies;
	state->last_seen = jiffies;
	state->last_data = jiffies;
	state->tuple = *ep;
	state->tuple_valid = true;
}

static void tcpwg_fake_close_locked(struct wg_peer *peer)
{
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;

	state->state = TCPWG_FAKE_CLOSED;
	state->peer_isn = 0;
	state->rx_seq = 0;
	state->ts_recent = 0;
	state->ts_enabled = false;
	state->rx_packets_since_ack = 0;
	state->ack_pending = false;
	tcpwg_fake_reset_rx_ack(&state->rx_ack_target, &state->rx_ack_bytes,
				&state->rx_ack_window_start, jiffies);
	tcpwg_fake_clear_control_retry_locked(state);
	state->state_since = jiffies;
	state->last_seen = jiffies;
}

static void tcpwg_fake_schedule_maintenance(struct wg_peer *peer,
					    unsigned long delay)
{
	if (unlikely(READ_ONCE(peer->is_dead)))
		return;

	wg_peer_get(peer);
	if (mod_delayed_work(system_wq, &peer->fake_tcp.maintenance_work,
			     delay))
		wg_peer_put(peer);
}

static bool tcpwg_fake_accept_data(struct wg_peer *peer,
				   const struct endpoint *endpoint,
				   const struct tcphdr *tcp,
				   size_t payload_len,
				   struct tcpwg_ack_reply *ack,
				   bool *schedule_ack,
				   bool *cancel_ack)
{
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;
	u32 seq = ntohl(tcp->seq);
	u32 end_seq;
	u32 ts_recent;
	u8 ack_target;
	bool ts_enabled;
	bool seq_gap;
	bool accept = false;

	if (!tcp->ack || tcp->syn || !payload_len)
		return false;
	ts_enabled = tcpwg_tcp_note_timestamp(tcp, &ts_recent);

	spin_lock_bh(&state->lock);
	if (state->state != TCPWG_FAKE_ESTABLISHED ||
	    !state->tuple_valid ||
	    !tcpwg_endpoint_equal(&state->tuple, endpoint))
		goto out;
	if (tcpwg_fake_epoch_expired(peer, state, jiffies)) {
		tcpwg_fake_close_locked(peer);
		goto out;
	}

	seq_gap = seq != state->rx_seq;
	if (seq_gap)
		net_dbg_ratelimited("%s: FakeTCP unexpected seq from peer %llu: got %u expected %u len %zu\n",
				    peer->device->dev->name,
				    peer->internal_id, seq, state->rx_seq,
				    payload_len);

	end_seq = seq + payload_len;
	state->last_seen = jiffies;
	state->last_data = jiffies;
	if (ts_enabled) {
		state->ts_enabled = true;
		state->ts_recent = ts_recent;
	}
	if (after(end_seq, state->rx_seq) || !state->rx_seq)
		state->rx_seq = end_seq;
	ack_target = tcpwg_fake_note_rx_payload(&state->rx_ack_target,
						&state->rx_ack_bytes,
						&state->rx_ack_window_start,
						payload_len, jiffies);
	if (++state->rx_packets_since_ack >= ack_target) {
		tcpwg_ack_reply_set(ack, state->tx_seq, state->rx_seq,
				    state->ts_enabled,
				    state->ts_enabled ? state->ts_recent : 0);
		state->rx_packets_since_ack = 0;
		if (state->ack_pending) {
			state->ack_pending = false;
			*cancel_ack = true;
		}
	} else if (!state->ack_pending) {
		state->ack_pending = true;
		*schedule_ack = true;
	}
	accept = true;
out:
	spin_unlock_bh(&state->lock);
	return accept;
}

static bool tcpwg_fake_handle_control(struct wg_device *wg, struct sk_buff *skb,
				      const struct endpoint *endpoint,
				      const struct tcphdr *tcp,
				      size_t payload_len,
				      struct wg_peer *peer)
{
	struct tcpwg_fake_tcp *state;
	u32 seq = ntohl(tcp->seq), ack_seq = ntohl(tcp->ack_seq);
	u32 local_isn = 0, tx_seq = 0, rx_seq = 0;
	u32 ts_recent = 0;
	unsigned long now = jiffies;
	bool ts_enabled;
	bool send_ack = false, established = false;

	ts_enabled = tcpwg_tcp_note_timestamp(tcp, &ts_recent);

	if (!peer)
		return tcpwg_peerless_handle_control(wg, skb, endpoint, tcp,
						     payload_len);

	if (tcp->rst)
		return true;

	if (tcp->fin) {
		state = &peer->fake_tcp;
		spin_lock_bh(&state->lock);
		if (state->state == TCPWG_FAKE_ESTABLISHED &&
		    state->tuple_valid &&
		    tcpwg_endpoint_equal(&state->tuple, endpoint)) {
			state->rx_seq = seq + payload_len + 1;
			if (ts_enabled) {
				state->ts_enabled = true;
				state->ts_recent = ts_recent;
			}
			state->state = TCPWG_FAKE_CLOSE_WAIT;
			state->state_since = jiffies;
			state->last_seen = jiffies;
			tx_seq = state->tx_seq;
			rx_seq = state->rx_seq;
			send_ack = true;
		}
		spin_unlock_bh(&state->lock);
		if (send_ack)
			tcpwg_send_control_from_skb(wg, skb, TCPWG_ACK,
						    tx_seq, rx_seq);
		return true;
	}

	if (tcp->syn && !tcp->ack) {
		state = &peer->fake_tcp;
		spin_lock_bh(&state->lock);
		if (state->tuple_valid &&
		    tcpwg_endpoint_equal(&state->tuple, endpoint) &&
		    state->state == TCPWG_FAKE_SYN_RECEIVED &&
		    time_before_eq(now, state->state_since +
					TCPWG_FAKE_HANDSHAKE_TIMEOUT)) {
			local_isn = state->local_isn;
			if (ts_enabled) {
				state->ts_enabled = true;
				state->ts_recent = ts_recent;
			}
			tcpwg_fake_note_control_retry_locked(state,
					TCPWG_SYN | TCPWG_ACK, local_isn,
					seq + 1, ts_enabled,
					ts_enabled ? ts_recent : 0, now);
			spin_unlock_bh(&state->lock);
			tcpwg_send_control_from_skb(wg, skb,
						    TCPWG_SYN | TCPWG_ACK,
						    local_isn, seq + 1);
			tcpwg_fake_schedule_maintenance(peer,
					TCPWG_FAKE_CONTROL_RETRY_INTERVAL);
			return true;
		}
		if (state->tuple_valid &&
		    tcpwg_endpoint_equal(&state->tuple, endpoint) &&
		    state->state == TCPWG_FAKE_SYN_SENT) {
			local_isn = state->local_isn;
			state->tx_seq = state->local_isn + 1;
		} else {
			state->local_isn = get_random_u32();
			local_isn = state->local_isn;
			state->tx_seq = state->local_isn + 1;
		}
		state->state = TCPWG_FAKE_SYN_RECEIVED;
		state->peer_isn = seq;
		state->rx_seq = seq + 1;
		state->ts_enabled = ts_enabled;
		state->ts_recent = ts_enabled ? ts_recent : 0;
		state->rx_packets_since_ack = 0;
		state->ack_pending = false;
		tcpwg_fake_reset_rx_ack(&state->rx_ack_target,
					&state->rx_ack_bytes,
					&state->rx_ack_window_start, now);
		state->state_since = now;
		state->last_seen = now;
		state->last_data = now;
		state->tuple = *endpoint;
		state->tuple_valid = true;
		tcpwg_fake_note_control_retry_locked(state,
				TCPWG_SYN | TCPWG_ACK, local_isn, seq + 1,
				ts_enabled, ts_enabled ? ts_recent : 0, now);
		spin_unlock_bh(&state->lock);

		tcpwg_send_control_from_skb(wg, skb, TCPWG_SYN | TCPWG_ACK,
					    local_isn, seq + 1);
		tcpwg_fake_schedule_maintenance(peer,
				TCPWG_FAKE_CONTROL_RETRY_INTERVAL);
		return true;
	}

	if (tcp->syn && tcp->ack) {
		state = &peer->fake_tcp;
		spin_lock_bh(&state->lock);
		if ((state->state == TCPWG_FAKE_SYN_SENT ||
		     (state->state == TCPWG_FAKE_SYN_RECEIVED &&
		      seq == state->peer_isn)) &&
		    state->tuple_valid &&
		    tcpwg_endpoint_equal(&state->tuple, endpoint) &&
		    ack_seq == state->local_isn + 1) {
			state->peer_isn = seq;
			state->rx_seq = seq + 1;
			state->tx_seq = state->local_isn + 1;
			state->ts_enabled = ts_enabled;
			state->ts_recent = ts_enabled ? ts_recent : 0;
			state->rx_packets_since_ack = 0;
			state->ack_pending = false;
			tcpwg_fake_reset_rx_ack(&state->rx_ack_target,
						&state->rx_ack_bytes,
						&state->rx_ack_window_start,
						now);
			tcpwg_fake_clear_control_retry_locked(state);
			state->state = TCPWG_FAKE_ESTABLISHED;
			state->state_since = now;
			state->last_seen = now;
			state->last_data = now;
			tx_seq = state->tx_seq;
			rx_seq = state->rx_seq;
			send_ack = true;
			established = true;
		}
		spin_unlock_bh(&state->lock);
		if (send_ack)
			tcpwg_send_control_from_skb(wg, skb, TCPWG_ACK,
						    tx_seq, rx_seq);
		if (established) {
			tcpwg_fake_schedule_maintenance(peer,
					TCPWG_FAKE_KEEPALIVE_INTERVAL);
		}
		return true;
	}

	if (tcp->ack && !payload_len) {
		state = &peer->fake_tcp;
		spin_lock_bh(&state->lock);
		if (!state->tuple_valid ||
		    !tcpwg_endpoint_equal(&state->tuple, endpoint)) {
			spin_unlock_bh(&state->lock);
			return true;
		}
		if (state->state == TCPWG_FAKE_SYN_RECEIVED &&
		    state->tuple_valid &&
		    seq == state->rx_seq &&
		    ack_seq == state->local_isn + 1) {
			state->tx_seq = state->local_isn + 1;
			if (ts_enabled) {
				state->ts_enabled = true;
				state->ts_recent = ts_recent;
			}
			state->rx_packets_since_ack = 0;
			state->ack_pending = false;
			tcpwg_fake_reset_rx_ack(&state->rx_ack_target,
						&state->rx_ack_bytes,
						&state->rx_ack_window_start,
						now);
			tcpwg_fake_clear_control_retry_locked(state);
			state->state = TCPWG_FAKE_ESTABLISHED;
			state->state_since = now;
			state->last_seen = now;
			state->last_data = now;
			established = true;
		} else if (state->state == TCPWG_FAKE_ESTABLISHED) {
			if (ts_enabled) {
				state->ts_enabled = true;
				state->ts_recent = ts_recent;
			}
			state->last_seen = now;
		}
		spin_unlock_bh(&state->lock);
		if (established) {
			tcpwg_fake_schedule_maintenance(peer,
					TCPWG_FAKE_KEEPALIVE_INTERVAL);
		}
		return true;
	}

	return false;
}

static unsigned int tcpwg_consume_packet(struct wg_device *wg,
					 struct sk_buff *skb,
					 const struct tcphdr *tcp,
					 size_t payload_len)
{
	struct endpoint endpoint;
	struct wg_peer *peer = NULL;
	struct tcpwg_ack_reply ack = { 0 };
	bool accepted;
	bool schedule_ack = false, cancel_ack = false;

	if (wg_socket_endpoint_from_skb(&endpoint, skb))
		goto drop;
	peer = tcpwg_lookup_peer_by_endpoint(wg, &endpoint);

	if (tcpwg_fake_handle_control(wg, skb, &endpoint, tcp, payload_len,
				      peer))
		goto drop;

	if (!payload_len)
		goto drop;

	if (peer) {
		accepted = tcpwg_fake_accept_data(peer, &endpoint, tcp,
						  payload_len, &ack,
						  &schedule_ack, &cancel_ack);
		if (cancel_ack)
			tcpwg_fake_cancel_ack(peer);
		if (ack.send)
			tcpwg_send_ack_reply(wg, &endpoint, &ack);
		else if (schedule_ack)
			tcpwg_fake_schedule_ack(peer);
		if (!accepted)
			goto drop;
	} else {
		accepted = tcpwg_peerless_accept_data(wg, &endpoint, tcp,
						      payload_len, &ack);
		if (ack.send)
			tcpwg_send_ack_reply(wg, &endpoint, &ack);
		if (!accepted)
			goto drop;
	}

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		goto stolen;

	skb_mark_not_on_list(skb);
	wg_packet_receive(wg, skb);
	dev_put(wg->dev);
	if (peer)
		wg_peer_put(peer);
	return NF_STOLEN;

drop:
	kfree_skb(skb);
stolen:
	dev_put(wg->dev);
	if (peer)
		wg_peer_put(peer);
	return NF_STOLEN;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
#define TCPWG_NF_NET dev_net(in)
#define TCPWG_NF_HOOK_ARGS const struct nf_hook_ops *ops, struct sk_buff *skb, \
			    const struct net_device *in,			      \
			    const struct net_device *out,		      \
			    int (*okfn)(struct sk_buff *)
#else
#define TCPWG_NF_NET state->net
#define TCPWG_NF_HOOK_ARGS void *priv, struct sk_buff *skb,		      \
			    const struct nf_hook_state *state
#endif

static unsigned int tcpwg_nf4(TCPWG_NF_HOOK_ARGS)
{
	struct wg_device *wg;
	struct iphdr *iph;
	struct tcphdr *tcp;
	size_t ip_len, ip_hdr_len, tcp_hdr_len, payload_len;

	if (unlikely(!skb))
		return NF_ACCEPT;
	if (unlikely(!pskb_may_pull(skb, sizeof(struct iphdr))))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	ip_hdr_len = iph->ihl * 4;
	if (unlikely(ip_hdr_len < sizeof(struct iphdr) ||
		     !pskb_may_pull(skb, ip_hdr_len + sizeof(struct tcphdr))))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	skb_set_transport_header(skb, ip_hdr_len);
	tcp = tcp_hdr(skb);
	wg = tcpwg_lookup_device(TCPWG_NF_NET, tcp->dest);
	if (!wg)
		return NF_ACCEPT;

	tcp_hdr_len = tcp->doff * 4;
	ip_len = ntohs(iph->tot_len);
	if (unlikely(tcp_hdr_len < sizeof(struct tcphdr) ||
		     ip_len < ip_hdr_len + tcp_hdr_len ||
		     ip_len > skb->len ||
		     !pskb_may_pull(skb, ip_hdr_len + tcp_hdr_len))) {
		kfree_skb(skb);
		dev_put(wg->dev);
		return NF_STOLEN;
	}

	tcp = tcp_hdr(skb);
	payload_len = ip_len - ip_hdr_len - tcp_hdr_len;
	if (unlikely(pskb_trim(skb, ip_len) < 0)) {
		kfree_skb(skb);
		dev_put(wg->dev);
		return NF_STOLEN;
	}
	tcp = tcp_hdr(skb);

	return tcpwg_consume_packet(wg, skb, tcp, payload_len);
}

#if IS_ENABLED(CONFIG_IPV6)
static unsigned int tcpwg_nf6(TCPWG_NF_HOOK_ARGS)
{
	struct wg_device *wg;
	struct ipv6hdr *ip6h;
	struct tcphdr *tcp;
	size_t ip_len, tcp_hdr_len, payload_len;

	if (unlikely(!skb))
		return NF_ACCEPT;
	if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr))))
		return NF_ACCEPT;

	ip6h = ipv6_hdr(skb);
	if (ip6h->nexthdr != IPPROTO_TCP)
		return NF_ACCEPT;
	if (unlikely(!pskb_may_pull(skb, sizeof(struct ipv6hdr) +
					 sizeof(struct tcphdr))))
		return NF_ACCEPT;

	ip6h = ipv6_hdr(skb);
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));
	tcp = tcp_hdr(skb);
	wg = tcpwg_lookup_device(TCPWG_NF_NET, tcp->dest);
	if (!wg)
		return NF_ACCEPT;

	tcp_hdr_len = tcp->doff * 4;
	ip_len = sizeof(struct ipv6hdr) + ntohs(ip6h->payload_len);
	if (unlikely(tcp_hdr_len < sizeof(struct tcphdr) ||
		     ip_len < sizeof(struct ipv6hdr) + tcp_hdr_len ||
		     ip_len > skb->len ||
		     !pskb_may_pull(skb, sizeof(struct ipv6hdr) + tcp_hdr_len))) {
		kfree_skb(skb);
		dev_put(wg->dev);
		return NF_STOLEN;
	}

	tcp = tcp_hdr(skb);
	payload_len = ip_len - sizeof(struct ipv6hdr) - tcp_hdr_len;
	if (unlikely(pskb_trim(skb, ip_len) < 0)) {
		kfree_skb(skb);
		dev_put(wg->dev);
		return NF_STOLEN;
	}
	tcp = tcp_hdr(skb);

	return tcpwg_consume_packet(wg, skb, tcp, payload_len);
}
#endif

static const struct nf_hook_ops tcpwg_nf_ops[] = {
	{
		.hook = tcpwg_nf4,
		.pf = NFPROTO_IPV4,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP_PRI_FIRST
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook = tcpwg_nf6,
		.pf = NFPROTO_IPV6,
		.hooknum = NF_INET_LOCAL_IN,
		.priority = NF_IP6_PRI_FIRST
	}
#endif
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
int wg_socket_tcp_init(void)
{
	return nf_register_hooks(tcpwg_nf_ops, ARRAY_SIZE(tcpwg_nf_ops));
}

void wg_socket_tcp_uninit(void)
{
	nf_unregister_hooks(tcpwg_nf_ops, ARRAY_SIZE(tcpwg_nf_ops));
	cancel_delayed_work_sync(&tcpwg_peerless_maintenance);
	tcpwg_peerless_purge_all();
	cancel_delayed_work_sync(&tcpwg_peerless_maintenance);
}
#else
static int tcpwg_net_init(struct net *net)
{
	return nf_register_net_hooks(net, tcpwg_nf_ops, ARRAY_SIZE(tcpwg_nf_ops));
}

static void tcpwg_net_exit(struct net *net)
{
	nf_unregister_net_hooks(net, tcpwg_nf_ops, ARRAY_SIZE(tcpwg_nf_ops));
}

static struct pernet_operations tcpwg_net_ops = {
	.init = tcpwg_net_init,
	.exit = tcpwg_net_exit
};

int wg_socket_tcp_init(void)
{
	return register_pernet_subsys(&tcpwg_net_ops);
}

void wg_socket_tcp_uninit(void)
{
	unregister_pernet_subsys(&tcpwg_net_ops);
	cancel_delayed_work_sync(&tcpwg_peerless_maintenance);
	tcpwg_peerless_purge_all();
	cancel_delayed_work_sync(&tcpwg_peerless_maintenance);
}
#endif
#else
static void tcpwg_list_set(struct wg_device *wg, bool active)
{
}

int wg_socket_tcp_init(void)
{
	return 0;
}

void wg_socket_tcp_uninit(void)
{
}
#endif

#if IS_ENABLED(CONFIG_IPV6)
static void tcpwg_tunnel_xmit6(struct dst_entry *dst, struct sock *sock,
			       struct sk_buff *skb, struct net_device *dev,
			       const struct in6_addr *src,
			       const struct in6_addr *dst_addr, u8 ds, u8 ttl,
			       __be16 sport, __be16 dport, u8 flags, u32 seq,
			       u32 ack_seq, bool ts_enabled, u32 ts_ecr)
{
	struct ipv6hdr *ip6h;
	struct tcphdr *tcp;
	size_t tcp_len = tcpwg_tcp_hdr_len(flags, ts_enabled);
	u16 mss = tcpwg_tcp_mss(dst_mtu(dst), sizeof(struct ipv6hdr),
				TCPWG_TCP_MIN_MSS6);

	__skb_push(skb, tcp_len);
	skb_reset_transport_header(skb);
	tcp = tcp_hdr(skb);
	tcpwg_fill_header(tcp, sport, dport, flags, seq, ack_seq,
			  ts_enabled, ts_ecr, mss);

	skb_dst_set(skb, dst);
	tcpwg_set_v6_csum(skb, src, dst_addr, dst->dev);

	__skb_push(skb, sizeof(*ip6h));
	skb_reset_network_header(skb);
	ip6h = ipv6_hdr(skb);
	ip6_flow_hdr(ip6h, ds, 0);
	ip6h->payload_len = htons(skb->len - sizeof(*ip6h));
	ip6h->nexthdr = IPPROTO_TCP;
	ip6h->hop_limit = ttl;
	ip6h->daddr = *dst_addr;
	ip6h->saddr = *src;

	tcpwg_setup_skb_sock(sock, skb);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0) || defined(ISRHEL9)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 17, 0)
	ip6tunnel_xmit(sock, skb, dev, 0);
#else
	ip6tunnel_xmit(sock, skb, dev);
#endif
#else
	ip6tunnel_xmit(skb, dev);
#endif
}
#endif

static int send4(struct wg_device *wg, struct sk_buff *skb,
		 struct endpoint *endpoint, u8 ds, struct dst_cache *cache,
		 u8 tcp_flags, u32 tcp_seq, u32 tcp_ack_seq,
		 bool ts_enabled, u32 ts_ecr)
{
	struct flowi4 fl = {
		.saddr = endpoint->src4.s_addr,
		.daddr = endpoint->addr4.sin_addr.s_addr,
		.fl4_dport = endpoint->addr4.sin_port,
		.flowi4_mark = wg->fwmark,
		.flowi4_proto = IPPROTO_TCP
	};
	struct rtable *rt = NULL;
	struct sock *sock;
	int ret = 0;

	skb_mark_not_on_list(skb);
	skb->dev = wg->dev;
	skb->mark = wg->fwmark;

	rcu_read_lock_bh();
	sock = rcu_dereference_bh(wg->sock4);

	if (unlikely(!sock)) {
		ret = -ENONET;
		goto err;
	}

	fl.fl4_sport = inet_sk(sock)->inet_sport;

	if (cache)
		rt = dst_cache_get_ip4(cache, &fl.saddr);

	if (!rt) {
		security_sk_classify_flow(sock, flowi4_to_flowi_common(&fl));
		if (unlikely(!inet_confirm_addr(sock_net(sock), NULL, 0,
						fl.saddr, RT_SCOPE_HOST))) {
			endpoint->src4.s_addr = 0;
			endpoint->src_if4 = 0;
			fl.saddr = 0;
			if (cache)
				dst_cache_reset(cache);
		}
		rt = ip_route_output_flow(sock_net(sock), &fl, sock);
		if (unlikely(endpoint->src_if4 && ((IS_ERR(rt) &&
			     PTR_ERR(rt) == -EINVAL) || (!IS_ERR(rt) &&
			     rt->dst.dev->ifindex != endpoint->src_if4)))) {
			endpoint->src4.s_addr = 0;
			endpoint->src_if4 = 0;
			fl.saddr = 0;
			if (cache)
				dst_cache_reset(cache);
			if (!IS_ERR(rt))
				ip_rt_put(rt);
			rt = ip_route_output_flow(sock_net(sock), &fl, sock);
		}
		if (IS_ERR(rt)) {
			ret = PTR_ERR(rt);
			net_dbg_ratelimited("%s: No route to %pISpfsc, error %d\n",
					    wg->dev->name, &endpoint->addr, ret);
			goto err;
		}
		if (cache)
			dst_cache_set_ip4(cache, &rt->dst, fl.saddr);
	}

	ds = TCPWG_FAKE_DSCP_TOS | (ds & 0x03);
	skb->ignore_df = 1;
	tcpwg_tunnel_xmit4(rt, sock, skb, fl.saddr, fl.daddr, ds,
			   ip4_dst_hoplimit(&rt->dst), fl.fl4_sport,
			   fl.fl4_dport, tcp_flags, tcp_seq, tcp_ack_seq,
			   ts_enabled, ts_ecr);
	goto out;

err:
	kfree_skb(skb);
out:
	rcu_read_unlock_bh();
	return ret;
}

static int send6(struct wg_device *wg, struct sk_buff *skb,
		 struct endpoint *endpoint, u8 ds, struct dst_cache *cache,
		 u8 tcp_flags, u32 tcp_seq, u32 tcp_ack_seq,
		 bool ts_enabled, u32 ts_ecr)
{
#if IS_ENABLED(CONFIG_IPV6)
	struct flowi6 fl = {
		.saddr = endpoint->src6,
		.daddr = endpoint->addr6.sin6_addr,
		.fl6_dport = endpoint->addr6.sin6_port,
		.flowi6_mark = wg->fwmark,
		.flowi6_oif = endpoint->addr6.sin6_scope_id,
		.flowi6_proto = IPPROTO_TCP
		/* TODO: addr->sin6_flowinfo */
	};
	struct dst_entry *dst = NULL;
	struct sock *sock;
	int ret = 0;

	skb_mark_not_on_list(skb);
	skb->dev = wg->dev;
	skb->mark = wg->fwmark;

	rcu_read_lock_bh();
	sock = rcu_dereference_bh(wg->sock6);

	if (unlikely(!sock)) {
		ret = -ENONET;
		goto err;
	}

	fl.fl6_sport = inet_sk(sock)->inet_sport;

	if (cache)
		dst = dst_cache_get_ip6(cache, &fl.saddr);

	if (!dst) {
		security_sk_classify_flow(sock, flowi6_to_flowi_common(&fl));
		if (unlikely(!ipv6_addr_any(&fl.saddr) &&
			     !ipv6_chk_addr(sock_net(sock), &fl.saddr, NULL, 0))) {
			endpoint->src6 = fl.saddr = in6addr_any;
			if (cache)
				dst_cache_reset(cache);
		}
		dst = ip6_dst_lookup_flow(sock_net(sock), sock, &fl, NULL);
		if (IS_ERR(dst)) {
			ret = PTR_ERR(dst);
			net_dbg_ratelimited("%s: No route to %pISpfsc, error %d\n",
					    wg->dev->name, &endpoint->addr, ret);
			goto err;
		}
		if (cache)
			dst_cache_set_ip6(cache, dst, &fl.saddr);
	}

	ds = TCPWG_FAKE_DSCP_TOS | (ds & 0x03);
	skb->ignore_df = 1;
	tcpwg_tunnel_xmit6(dst, sock, skb, skb->dev, &fl.saddr, &fl.daddr,
			   ds, ip6_dst_hoplimit(dst), fl.fl6_sport,
			   fl.fl6_dport, tcp_flags, tcp_seq, tcp_ack_seq,
			   ts_enabled, ts_ecr);
	goto out;

err:
	kfree_skb(skb);
out:
	rcu_read_unlock_bh();
	return ret;
#else
	kfree_skb(skb);
	return -EAFNOSUPPORT;
#endif
}

static int tcpwg_send_empty(struct wg_device *wg, struct endpoint *endpoint,
			    u8 flags, u32 seq, u32 ack_seq,
			    bool ts_enabled, u32 ts_ecr)
{
	struct sk_buff *skb;

	skb = alloc_skb(SKB_HEADER_LEN, GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOMEM;
	skb_reserve(skb, SKB_HEADER_LEN);
	skb_set_inner_network_header(skb, 0);

	if (endpoint->addr.sa_family == AF_INET)
		return send4(wg, skb, endpoint, 0, NULL, flags, seq, ack_seq,
			     ts_enabled, ts_ecr);
	if (IS_ENABLED(CONFIG_IPV6) && endpoint->addr.sa_family == AF_INET6)
		return send6(wg, skb, endpoint, 0, NULL, flags, seq, ack_seq,
			     ts_enabled, ts_ecr);

	kfree_skb(skb);
	return -EAFNOSUPPORT;
}

static unsigned long tcpwg_fake_delay_until(unsigned long expires)
{
	unsigned long now = jiffies;

	return time_after(expires, now) ? expires - now : 1;
}

void tcpwg_fake_ack_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct wg_peer *peer = container_of(dwork, struct wg_peer,
					    fake_tcp.ack_work);
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;
	struct tcpwg_ack_reply ack = { 0 };
	struct endpoint endpoint;
	bool send_ack = false;

	read_lock_bh(&peer->endpoint_lock);
	spin_lock_bh(&state->lock);

	if (state->state == TCPWG_FAKE_ESTABLISHED &&
	    state->tuple_valid &&
	    tcpwg_endpoint_equal(&state->tuple, &peer->endpoint) &&
	    state->ack_pending) {
		endpoint = state->tuple;
		tcpwg_ack_reply_set(&ack, state->tx_seq, state->rx_seq,
				    state->ts_enabled,
				    state->ts_enabled ? state->ts_recent : 0);
		state->ack_pending = false;
		state->rx_packets_since_ack = 0;
		state->last_seen = jiffies;
		send_ack = true;
	}

	spin_unlock_bh(&state->lock);
	read_unlock_bh(&peer->endpoint_lock);

	if (send_ack)
		tcpwg_send_ack_reply(peer->device, &endpoint, &ack);
	wg_peer_put(peer);
}

void tcpwg_fake_maintenance_work(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct wg_peer *peer = container_of(dwork, struct wg_peer,
					    fake_tcp.maintenance_work);
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;
	unsigned long now = jiffies, next_delay = 0;
	unsigned long keepalive_at, idle_close_at;
	struct endpoint endpoint;
	bool send_syn = false;
	bool send_keepalive = false;
	bool send_control_retry = false;
	u8 control_flags = 0;
	bool ts_enabled = false;
	u32 seq = 0, ack = 0;
	u32 ts_ecr = 0;

	read_lock_bh(&peer->endpoint_lock);
	spin_lock_bh(&state->lock);

	if (state->state == TCPWG_FAKE_SYN_SENT ||
	    state->state == TCPWG_FAKE_SYN_RECEIVED) {
		if (time_after_eq(now, state->state_since +
				       TCPWG_FAKE_HANDSHAKE_TIMEOUT)) {
			tcpwg_fake_close_locked(peer);
		} else {
			if (state->control_flags && state->tuple_valid &&
			    state->control_retries <
				    TCPWG_FAKE_CONTROL_MAX_RETRIES &&
			    time_after_eq(now, state->control_retry_at)) {
				endpoint = state->tuple;
				control_flags = state->control_flags;
				seq = state->control_seq;
				ack = state->control_ack_seq;
				ts_enabled = state->control_ts_enabled;
				ts_ecr = state->control_ts_ecr;
				++state->control_retries;
				state->control_retry_at = now +
					TCPWG_FAKE_CONTROL_RETRY_INTERVAL;
				state->last_seen = now;
				send_control_retry = true;
			}
			next_delay = tcpwg_fake_delay_until(state->state_since +
					TCPWG_FAKE_HANDSHAKE_TIMEOUT);
			if (state->control_flags &&
			    state->control_retries <
				    TCPWG_FAKE_CONTROL_MAX_RETRIES)
				next_delay = min(next_delay,
					tcpwg_fake_delay_until(
						state->control_retry_at));
		}
	} else if (state->state == TCPWG_FAKE_ESTABLISHED) {
		idle_close_at = state->last_data + TCPWG_FAKE_IDLE_TIMEOUT;
		if (time_after_eq(now, idle_close_at)) {
			tcpwg_fake_close_locked(peer);
		} else if (tcpwg_fake_epoch_expired(peer, state, now)) {
			if (state->tuple_valid &&
			    tcpwg_endpoint_equal(&state->tuple,
						 &peer->endpoint)) {
				endpoint = peer->endpoint;
				tcpwg_fake_start_syn_locked(peer, &endpoint,
							    now, &seq);
				send_syn = true;
				next_delay = TCPWG_FAKE_CONTROL_RETRY_INTERVAL;
			} else {
				tcpwg_fake_close_locked(peer);
			}
		} else {
			keepalive_at = state->last_seen +
				       TCPWG_FAKE_KEEPALIVE_INTERVAL;
			if (time_after_eq(now, keepalive_at) &&
			    state->tuple_valid &&
			    tcpwg_endpoint_equal(&state->tuple,
						 &peer->endpoint)) {
				endpoint = peer->endpoint;
				seq = state->tx_seq;
				ack = state->rx_seq;
				ts_enabled = state->ts_enabled;
				ts_ecr = state->ts_enabled ?
					 state->ts_recent : 0;
				state->last_seen = now;
				send_keepalive = true;
				keepalive_at = now +
					       TCPWG_FAKE_KEEPALIVE_INTERVAL;
			}
			next_delay = min(tcpwg_fake_delay_until(keepalive_at),
					 tcpwg_fake_delay_until(idle_close_at));
		}
	} else if (state->state == TCPWG_FAKE_CLOSE_WAIT) {
		if (time_after_eq(now, state->state_since +
				       TCPWG_FAKE_HANDSHAKE_TIMEOUT))
			tcpwg_fake_close_locked(peer);
		else
			next_delay = tcpwg_fake_delay_until(state->state_since +
					TCPWG_FAKE_HANDSHAKE_TIMEOUT);
	}

	spin_unlock_bh(&state->lock);
	read_unlock_bh(&peer->endpoint_lock);

	if (send_syn)
		tcpwg_send_empty(peer->device, &endpoint, TCPWG_SYN, seq, 0,
				 true, 0);
	else if (send_control_retry)
		tcpwg_send_empty(peer->device, &endpoint, control_flags, seq,
				 ack, ts_enabled, ts_ecr);
	else if (send_keepalive)
		tcpwg_send_empty(peer->device, &endpoint, TCPWG_ACK, seq, ack,
				 ts_enabled, ts_ecr);
	if (next_delay)
		tcpwg_fake_schedule_maintenance(peer, next_delay);

	wg_peer_put(peer);
}

static bool tcpwg_fake_prepare_data(struct wg_peer *peer, struct endpoint *ep,
				    struct sk_buff *skb, u32 *seq, u32 *ack,
				    bool *ts_enabled, u32 *ts_ecr)
{
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;
	unsigned long now = jiffies;
	u32 syn_seq = 0;

	spin_lock_bh(&state->lock);
	if (!state->tuple_valid || !tcpwg_endpoint_equal(&state->tuple, ep)) {
		tcpwg_fake_reset_locked(peer, ep);
	}

	if (state->state == TCPWG_FAKE_ESTABLISHED &&
	    !tcpwg_fake_epoch_expired(peer, state, now)) {
		*seq = state->tx_seq;
		*ack = state->rx_seq;
		*ts_enabled = state->ts_enabled;
		*ts_ecr = state->ts_enabled ? state->ts_recent : 0;
		state->ack_pending = false;
		state->rx_packets_since_ack = 0;
		state->tx_seq += max_t(u32, 1U, skb->len);
		state->last_seen = now;
		state->last_data = now;
		spin_unlock_bh(&state->lock);
		tcpwg_fake_schedule_maintenance(peer,
				TCPWG_FAKE_KEEPALIVE_INTERVAL);
		return true;
	}

	if ((state->state == TCPWG_FAKE_SYN_SENT ||
	     state->state == TCPWG_FAKE_SYN_RECEIVED) &&
	    time_before_eq(now,
			   state->state_since + TCPWG_FAKE_HANDSHAKE_TIMEOUT)) {
		spin_unlock_bh(&state->lock);
		dev_kfree_skb(skb);
		return false;
	}

	tcpwg_fake_start_syn_locked(peer, ep, now, &syn_seq);
	spin_unlock_bh(&state->lock);

	tcpwg_send_empty(peer->device, ep, TCPWG_SYN, syn_seq, 0, true, 0);
	tcpwg_fake_schedule_maintenance(peer, TCPWG_FAKE_CONTROL_RETRY_INTERVAL);
	dev_kfree_skb(skb);
	return false;
}

int wg_socket_send_skb_to_peer(struct wg_peer *peer, struct sk_buff *skb, u8 ds)
{
	size_t skb_len = skb->len;
	u32 seq, ack_seq;
	u32 ts_ecr;
	bool ts_enabled;
	int ret = -EAFNOSUPPORT;

	read_lock_bh(&peer->endpoint_lock);
	if (peer->endpoint.addr.sa_family == AF_INET) {
		if (!tcpwg_fake_prepare_data(peer, &peer->endpoint, skb,
					     &seq, &ack_seq, &ts_enabled,
					     &ts_ecr)) {
			read_unlock_bh(&peer->endpoint_lock);
			return 0;
		}
		tcpwg_fake_cancel_ack(peer);
		ret = send4(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache, TCPWG_ACK | TCPWG_PSH,
			    seq, ack_seq, ts_enabled, ts_ecr);
	} else if (peer->endpoint.addr.sa_family == AF_INET6) {
		if (!tcpwg_fake_prepare_data(peer, &peer->endpoint, skb,
					     &seq, &ack_seq, &ts_enabled,
					     &ts_ecr)) {
			read_unlock_bh(&peer->endpoint_lock);
			return 0;
		}
		tcpwg_fake_cancel_ack(peer);
		ret = send6(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache, TCPWG_ACK | TCPWG_PSH,
			    seq, ack_seq, ts_enabled, ts_ecr);
	} else {
		dev_kfree_skb(skb);
	}
	if (likely(!ret))
		peer->tx_bytes += skb_len;
	read_unlock_bh(&peer->endpoint_lock);

	return ret;
}

int wg_socket_send_data_skb_to_peer(struct wg_peer *peer, struct sk_buff *skb,
				    u8 ds)
{
	size_t skb_len = skb->len;
	u32 seq, ack_seq;
	u32 ts_ecr;
	bool ts_enabled;
	int ret = -EAFNOSUPPORT;

	read_lock_bh(&peer->endpoint_lock);
	if (peer->endpoint.addr.sa_family == AF_INET) {
		if (!tcpwg_fake_prepare_data(peer, &peer->endpoint, skb,
					     &seq, &ack_seq, &ts_enabled,
					     &ts_ecr)) {
			read_unlock_bh(&peer->endpoint_lock);
			return 0;
		}
		tcpwg_fake_cancel_ack(peer);
		ret = send4(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache, TCPWG_ACK | TCPWG_PSH,
			    seq, ack_seq, ts_enabled, ts_ecr);
	} else if (peer->endpoint.addr.sa_family == AF_INET6) {
		if (!tcpwg_fake_prepare_data(peer, &peer->endpoint, skb,
					     &seq, &ack_seq, &ts_enabled,
					     &ts_ecr)) {
			read_unlock_bh(&peer->endpoint_lock);
			return 0;
		}
		tcpwg_fake_cancel_ack(peer);
		ret = send6(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache, TCPWG_ACK | TCPWG_PSH,
			    seq, ack_seq, ts_enabled, ts_ecr);
	} else {
		dev_kfree_skb(skb);
	}
	if (likely(!ret))
		peer->tx_bytes += skb_len;
	read_unlock_bh(&peer->endpoint_lock);

	return ret;
}

int wg_socket_send_buffer_to_peer(struct wg_peer *peer, void *buffer,
				  size_t len, u8 ds, size_t junk_size)
{
	void* junk;
	struct sk_buff *skb = alloc_skb(len + junk_size + SKB_HEADER_LEN, GFP_ATOMIC);

	if (unlikely(!skb))
		return -ENOMEM;

	skb_reserve(skb, SKB_HEADER_LEN);
	skb_set_inner_network_header(skb, 0);
	junk = skb_put(skb, junk_size);
	get_random_bytes(junk, junk_size);
	skb_put_data(skb, buffer, len);
	return wg_socket_send_skb_to_peer(peer, skb, ds);
}

int wg_socket_send_buffer_as_reply_to_skb(struct wg_device *wg,
					  struct sk_buff *in_skb, void *buffer,
					  size_t len, size_t junk_size)
{
	int ret = 0;
	struct sk_buff *skb;
	struct endpoint endpoint;
	const struct tcphdr *tcp;
	struct wg_peer *peer = NULL;
	struct tcpwg_fake_tcp *state;
	size_t payload_len;
	unsigned long now = jiffies;
	u32 seq, ack_seq;
	u32 ts_recent, ts_ecr = 0;
	bool ts_enabled;
	bool drop_reply = false;
	bool used_fake_state = false;
	bool used_peerless_state = false;
	bool cancel_ack = false;
	void* junk;

	if (unlikely(!in_skb))
		return -EINVAL;
	ret = wg_socket_endpoint_from_skb(&endpoint, in_skb);
	if (unlikely(ret < 0))
		return ret;
	tcp = tcp_hdr(in_skb);
	payload_len = tcpwg_skb_payload_len(in_skb);
	seq = ntohl(tcp->ack_seq);
	ack_seq = ntohl(tcp->seq) + (tcp->syn ? 1 : 0) + payload_len;
	ts_enabled = tcpwg_tcp_note_timestamp(tcp, &ts_recent);
	if (ts_enabled)
		ts_ecr = ts_recent;

	skb = alloc_skb(len + junk_size + SKB_HEADER_LEN, GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOMEM;
	skb_reserve(skb, SKB_HEADER_LEN);
	skb_set_inner_network_header(skb, 0);
	junk = skb_put(skb, junk_size);
	get_random_bytes(junk, junk_size);
	skb_put_data(skb, buffer, len);

	peer = tcpwg_lookup_peer_by_endpoint(wg, &endpoint);
	if (peer) {
		state = &peer->fake_tcp;
		spin_lock_bh(&state->lock);
		if (state->state == TCPWG_FAKE_ESTABLISHED &&
		    state->tuple_valid &&
		    tcpwg_endpoint_equal(&state->tuple, &endpoint)) {
			if (tcpwg_fake_epoch_expired(peer, state, now)) {
				tcpwg_fake_close_locked(peer);
				drop_reply = true;
			} else {
				if (ts_enabled) {
					state->ts_enabled = true;
					state->ts_recent = ts_recent;
				}
				seq = state->tx_seq;
				ack_seq = state->rx_seq;
				ts_enabled = state->ts_enabled;
				ts_ecr = state->ts_enabled ?
					 state->ts_recent : 0;
				if (state->ack_pending) {
					state->ack_pending = false;
					state->rx_packets_since_ack = 0;
					cancel_ack = true;
				}
				state->tx_seq += max_t(u32, 1U, skb->len);
				state->last_seen = now;
				state->last_data = now;
				used_fake_state = true;
			}
		}
		spin_unlock_bh(&state->lock);
		if (cancel_ack)
			tcpwg_fake_cancel_ack(peer);
		if (drop_reply) {
			kfree_skb(skb);
			wg_peer_put(peer);
			return 0;
		}
	}
	if (!used_fake_state)
		used_peerless_state = tcpwg_peerless_prepare_reply(wg,
								   &endpoint,
								   skb, &seq,
								   &ack_seq,
								   &ts_enabled,
								   &ts_ecr);

	if (endpoint.addr.sa_family == AF_INET)
		ret = send4(wg, skb, &endpoint, 0, NULL,
			    TCPWG_ACK | TCPWG_PSH, seq, ack_seq,
			    ts_enabled, ts_ecr);
	else if (endpoint.addr.sa_family == AF_INET6)
		ret = send6(wg, skb, &endpoint, 0, NULL,
			    TCPWG_ACK | TCPWG_PSH, seq, ack_seq,
			    ts_enabled, ts_ecr);
	/* No other possibilities if the endpoint is valid, which it is,
	 * as we checked above.
	 */

	if (used_fake_state)
		tcpwg_fake_schedule_maintenance(peer,
				TCPWG_FAKE_KEEPALIVE_INTERVAL);
	else if (used_peerless_state)
		tcpwg_peerless_schedule_maintenance();
	wg_peer_put(peer);
	return ret;
}

int wg_socket_endpoint_from_skb(struct endpoint *endpoint,
				const struct sk_buff *skb)
{
	u8 proto = skb_outer_proto(skb);

	memset(endpoint, 0, sizeof(*endpoint));
	if (proto != IPPROTO_TCP)
		return -EINVAL;
	if (skb->protocol == htons(ETH_P_IP)) {
		endpoint->addr4.sin_family = AF_INET;
		endpoint->addr4.sin_port = tcp_hdr(skb)->source;
		endpoint->addr4.sin_addr.s_addr = ip_hdr(skb)->saddr;
		endpoint->src4.s_addr = ip_hdr(skb)->daddr;
		endpoint->src_if4 = skb->skb_iif;
	} else if (IS_ENABLED(CONFIG_IPV6) && skb->protocol == htons(ETH_P_IPV6)) {
		endpoint->addr6.sin6_family = AF_INET6;
		endpoint->addr6.sin6_port = tcp_hdr(skb)->source;
		endpoint->addr6.sin6_addr = ipv6_hdr(skb)->saddr;
		endpoint->addr6.sin6_scope_id = ipv6_iface_scope_id(
			&ipv6_hdr(skb)->saddr, skb->skb_iif);
		endpoint->src6 = ipv6_hdr(skb)->daddr;
	} else {
		return -EINVAL;
	}
	return 0;
}

static bool endpoint_eq(const struct endpoint *a, const struct endpoint *b)
{
	return (a->addr.sa_family == AF_INET && b->addr.sa_family == AF_INET &&
		a->addr4.sin_port == b->addr4.sin_port &&
		a->addr4.sin_addr.s_addr == b->addr4.sin_addr.s_addr &&
		a->src4.s_addr == b->src4.s_addr && a->src_if4 == b->src_if4) ||
	       (a->addr.sa_family == AF_INET6 &&
		b->addr.sa_family == AF_INET6 &&
		a->addr6.sin6_port == b->addr6.sin6_port &&
		ipv6_addr_equal(&a->addr6.sin6_addr, &b->addr6.sin6_addr) &&
		a->addr6.sin6_scope_id == b->addr6.sin6_scope_id &&
		ipv6_addr_equal(&a->src6, &b->src6)) ||
	       unlikely(!a->addr.sa_family && !b->addr.sa_family);
}

static void wg_socket_set_peer_endpoint_sync(struct wg_peer *peer,
					     const struct endpoint *endpoint)
{
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;
	bool same_remote;
	bool bound_peerless = false;

	/* First we check unlocked, in order to optimize, since it's pretty rare
	 * that an endpoint will change. If we happen to be mid-write, and two
	 * CPUs wind up writing the same thing or something slightly different,
	 * it doesn't really matter much either.
	 */
	if (endpoint_eq(endpoint, &peer->endpoint))
		return;

	same_remote = tcpwg_endpoint_equal(endpoint, &peer->endpoint);
	write_lock_bh(&peer->endpoint_lock);
	if (endpoint->addr.sa_family == AF_INET) {
		peer->endpoint.addr4 = endpoint->addr4;
		peer->endpoint.src4 = endpoint->src4;
		peer->endpoint.src_if4 = endpoint->src_if4;
	} else if (IS_ENABLED(CONFIG_IPV6) && endpoint->addr.sa_family == AF_INET6) {
		peer->endpoint.addr6 = endpoint->addr6;
		peer->endpoint.src6 = endpoint->src6;
	} else {
		goto out;
	}
	if (!same_remote) {
		spin_lock_bh(&state->lock);
		bound_peerless = tcpwg_peerless_bind_to_peer_locked(peer,
								    endpoint);
		if (!bound_peerless)
			tcpwg_fake_reset_locked(peer, endpoint);
		spin_unlock_bh(&state->lock);
	}
	dst_cache_reset(&peer->endpoint_cache);
out:
	write_unlock_bh(&peer->endpoint_lock);

	if (bound_peerless)
		tcpwg_fake_schedule_maintenance(peer,
				TCPWG_FAKE_KEEPALIVE_INTERVAL);
}

void wg_socket_set_peer_endpoint(struct wg_peer *peer,
				 const struct endpoint *endpoint)
{
	wg_socket_set_peer_endpoint_sync(peer, endpoint);
}

void wg_socket_set_peer_endpoint_from_rx(struct wg_peer *peer,
					 const struct endpoint *endpoint)
{
	wg_socket_set_peer_endpoint_sync(peer, endpoint);
}

void wg_socket_set_peer_endpoint_from_skb(struct wg_peer *peer,
					  const struct sk_buff *skb)
{
	struct endpoint endpoint;

	if (!wg_socket_endpoint_from_skb(&endpoint, skb))
		wg_socket_set_peer_endpoint_from_rx(peer, &endpoint);
}

void wg_socket_clear_peer_endpoint_src(struct wg_peer *peer)
{
	write_lock_bh(&peer->endpoint_lock);
	memset(&peer->endpoint.src6, 0, sizeof(peer->endpoint.src6));
	dst_cache_reset_now(&peer->endpoint_cache);
	write_unlock_bh(&peer->endpoint_lock);
}

static int wg_receive(struct sock *sk, struct sk_buff *skb)
{
	kfree_skb(skb);
	return 0;
}

static void sock_free(struct sock *sock)
{
	if (unlikely(!sock))
		return;
	sk_clear_memalloc(sock);
	udp_tunnel_sock_release(sock->sk_socket);
}

static void set_sock_opts(struct socket *sock)
{
	sock->sk->sk_allocation = GFP_ATOMIC;
	sock->sk->sk_sndbuf = INT_MAX;
	sk_set_memalloc(sock->sk);
}

int wg_socket_init(struct wg_device *wg, u16 port)
{
	struct net *net;
	int ret;
	struct udp_tunnel_sock_cfg cfg = {
		.sk_user_data = wg,
		.encap_type = 1,
		.encap_rcv = wg_receive
	};
	struct socket *new4 = NULL, *new6 = NULL;
	struct udp_port_cfg port4 = {
		.family = AF_INET,
		.local_ip.s_addr = htonl(INADDR_ANY),
		.local_udp_port = htons(port),
		.use_udp_checksums = true
	};
#if IS_ENABLED(CONFIG_IPV6)
	int retries = 0;
	struct udp_port_cfg port6 = {
		.family = AF_INET6,
		.local_ip6 = IN6ADDR_ANY_INIT,
		.use_udp6_tx_checksums = true,
		.use_udp6_rx_checksums = true,
		.ipv6_v6only = true
	};
#endif

	rcu_read_lock();
	net = rcu_dereference(wg->creating_net);
	net = net ? maybe_get_net(net) : NULL;
	rcu_read_unlock();
	if (unlikely(!net))
		return -ENONET;

#if IS_ENABLED(CONFIG_IPV6)
retry:
#endif

	ret = udp_sock_create(net, &port4, &new4);
	if (ret < 0) {
		pr_err("%s: Could not create IPv4 socket\n", wg->dev->name);
		goto out;
	}
	set_sock_opts(new4);
	setup_udp_tunnel_sock(net, new4, &cfg);

#if IS_ENABLED(CONFIG_IPV6)
	if (ipv6_mod_enabled()) {
		port6.local_udp_port = inet_sk(new4->sk)->inet_sport;
		ret = udp_sock_create(net, &port6, &new6);
		if (ret < 0) {
			udp_tunnel_sock_release(new4);
			if (ret == -EADDRINUSE && !port && retries++ < 100)
				goto retry;
			pr_err("%s: Could not create IPv6 socket\n",
			       wg->dev->name);
			goto out;
		}
		set_sock_opts(new6);
		setup_udp_tunnel_sock(net, new6, &cfg);
	}
#endif

	wg_socket_reinit(wg, new4->sk, new6 ? new6->sk : NULL);
	ret = 0;
out:
	put_net(net);
	return ret;
}

void wg_socket_reinit(struct wg_device *wg, struct sock *new4,
		      struct sock *new6)
{
	struct sock *old4, *old6;
	u16 old_port;

	mutex_lock(&wg->socket_update_lock);
	old4 = rcu_dereference_protected(wg->sock4,
				lockdep_is_held(&wg->socket_update_lock));
	old6 = rcu_dereference_protected(wg->sock6,
				lockdep_is_held(&wg->socket_update_lock));
	old_port = wg->incoming_port;
	rcu_assign_pointer(wg->sock4, new4);
	rcu_assign_pointer(wg->sock6, new6);
	if (new4)
		wg->incoming_port = ntohs(inet_sk(new4)->inet_sport);
	tcpwg_list_set(wg, new4 || new6);
	mutex_unlock(&wg->socket_update_lock);
	synchronize_net();
	if (!new4 || old_port != wg->incoming_port)
		tcpwg_peerless_purge_wg(wg);
	sock_free(old4);
	sock_free(old6);
}
