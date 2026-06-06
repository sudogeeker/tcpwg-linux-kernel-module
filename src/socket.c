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
#include <linux/net.h>
#include <linux/if_vlan.h>
#include <linux/if_ether.h>
#include <linux/random.h>
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

static LIST_HEAD(tcpwg_devices);
static DEFINE_SPINLOCK(tcpwg_devices_lock);

enum {
	TCPWG_SYN = 0x02,
	TCPWG_PSH = 0x08,
	TCPWG_ACK = 0x10
};

#define TCPWG_FAKE_PENDING_MAX 256

static atomic64_t tcpwg_fake_syn_sent = ATOMIC64_INIT(0);
static atomic64_t tcpwg_fake_synack_sent = ATOMIC64_INIT(0);
static atomic64_t tcpwg_fake_ack_sent = ATOMIC64_INIT(0);
static atomic64_t tcpwg_fake_established = ATOMIC64_INIT(0);
static atomic64_t tcpwg_fake_pending_queued = ATOMIC64_INIT(0);
static atomic64_t tcpwg_fake_pending_dropped = ATOMIC64_INIT(0);
static atomic64_t tcpwg_fake_endpoint_reset = ATOMIC64_INIT(0);

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

static void tcpwg_fill_header(struct tcphdr *tcp, __be16 source, __be16 dest,
			      u8 flags, u32 seq, u32 ack_seq)
{
	memset(tcp, 0, sizeof(*tcp));
	tcp->source = source;
	tcp->dest = dest;
	tcp->seq = htonl(seq);
	tcp->ack_seq = htonl(ack_seq);
	tcp->doff = sizeof(*tcp) / 4;
	tcp->window = htons(65535);
	tcp->syn = !!(flags & TCPWG_SYN);
	tcp->ack = !!(flags & TCPWG_ACK);
	tcp->psh = !!(flags & TCPWG_PSH);
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
			       u8 flags, u32 seq, u32 ack_seq)
{
	struct tcphdr *tcp;

	__skb_push(skb, sizeof(*tcp));
	skb_reset_transport_header(skb);
	tcp = tcp_hdr(skb);
	tcpwg_fill_header(tcp, sport, dport, flags, seq, ack_seq);

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
			    u8 flags, u32 seq, u32 ack_seq);

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
	int ret;

	if (wg_socket_endpoint_from_skb(&endpoint, skb))
		return -EINVAL;

	ret = tcpwg_send_empty(wg, &endpoint, flags, seq, ack_seq);
	if (!ret) {
		if ((flags & (TCPWG_SYN | TCPWG_ACK)) ==
		    (TCPWG_SYN | TCPWG_ACK))
			atomic64_inc(&tcpwg_fake_synack_sent);
		else if (flags & TCPWG_SYN)
			atomic64_inc(&tcpwg_fake_syn_sent);
		else if (flags & TCPWG_ACK)
			atomic64_inc(&tcpwg_fake_ack_sent);
	}
	return ret;
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
	state->last_syn_sent = 0;
	state->last_seen = jiffies;
	state->tuple = *ep;
	state->tuple_valid = true;
	atomic64_inc(&tcpwg_fake_endpoint_reset);
}

static void tcpwg_fake_schedule_drain(struct wg_peer *peer)
{
	wg_peer_get(peer);
	if (!queue_work(system_wq, &peer->fake_tcp.drain_work))
		wg_peer_put(peer);
}

static bool tcpwg_fake_accept_data(struct wg_peer *peer,
				   const struct endpoint *endpoint,
				   const struct tcphdr *tcp,
				   size_t payload_len)
{
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;
	u32 end_seq;
	bool accept = false;

	if (!tcp->ack || tcp->syn || !payload_len)
		return false;

	spin_lock_bh(&state->lock);
	if (state->state != TCPWG_FAKE_ESTABLISHED ||
	    !state->tuple_valid ||
	    !tcpwg_endpoint_equal(&state->tuple, endpoint))
		goto out;

	end_seq = ntohl(tcp->seq) + payload_len;
	state->last_seen = jiffies;
	if (after(end_seq, state->rx_seq) || !state->rx_seq)
		state->rx_seq = end_seq;
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
	bool send_ack = false, established = false;

	if (tcp->syn && !tcp->ack) {
		if (!peer)
			return true;

		state = &peer->fake_tcp;
		spin_lock_bh(&state->lock);
		state->state = TCPWG_FAKE_SYN_RECV;
		state->local_isn = get_random_u32();
		state->peer_isn = seq;
		state->tx_seq = state->local_isn + 1;
		state->rx_seq = seq + 1;
		state->last_syn_sent = 0;
		state->last_seen = jiffies;
		state->tuple = *endpoint;
		state->tuple_valid = true;
		local_isn = state->local_isn;
		spin_unlock_bh(&state->lock);

		tcpwg_send_control_from_skb(wg, skb, TCPWG_SYN | TCPWG_ACK,
					    local_isn, seq + 1);
		return true;
	}

	if (tcp->syn && tcp->ack) {
		if (!peer)
			return true;
		state = &peer->fake_tcp;
		spin_lock_bh(&state->lock);
		if (state->state == TCPWG_FAKE_SYN_SENT &&
		    state->tuple_valid &&
		    tcpwg_endpoint_equal(&state->tuple, endpoint) &&
		    ack_seq == state->local_isn + 1) {
			state->peer_isn = seq;
			state->rx_seq = seq + 1;
			state->tx_seq = state->local_isn + 1;
			state->state = TCPWG_FAKE_ESTABLISHED;
			state->last_seen = jiffies;
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
			atomic64_inc(&tcpwg_fake_established);
			tcpwg_fake_schedule_drain(peer);
		}
		return true;
	}

	if (tcp->ack && !payload_len) {
		if (!peer)
			return true;
		state = &peer->fake_tcp;
		spin_lock_bh(&state->lock);
		if (state->state == TCPWG_FAKE_SYN_RECV &&
		    state->tuple_valid &&
		    tcpwg_endpoint_equal(&state->tuple, endpoint) &&
		    seq == state->rx_seq &&
		    ack_seq == state->local_isn + 1) {
			state->tx_seq = state->local_isn + 1;
			state->state = TCPWG_FAKE_ESTABLISHED;
			state->last_seen = jiffies;
			established = true;
		}
		spin_unlock_bh(&state->lock);
		if (established) {
			atomic64_inc(&tcpwg_fake_established);
			tcpwg_fake_schedule_drain(peer);
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

	if (wg_socket_endpoint_from_skb(&endpoint, skb))
		goto drop;
	peer = tcpwg_lookup_peer_by_endpoint(wg, &endpoint);

	if (tcp->rst)
		goto drop;

	if (tcpwg_fake_handle_control(wg, skb, &endpoint, tcp, payload_len,
				      peer))
		goto drop;

	if (!payload_len)
		goto drop;

	if (!peer || !tcpwg_fake_accept_data(peer, &endpoint, tcp, payload_len))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (unlikely(!skb))
		goto stolen;

	skb_mark_not_on_list(skb);
	wg_packet_receive(wg, skb);
	dev_put(wg->dev);
	wg_peer_put(peer);
	return NF_STOLEN;

drop:
	kfree_skb(skb);
stolen:
	dev_put(wg->dev);
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
			       u32 ack_seq)
{
	struct ipv6hdr *ip6h;
	struct tcphdr *tcp;

	__skb_push(skb, sizeof(*tcp));
	skb_reset_transport_header(skb);
	tcp = tcp_hdr(skb);
	tcpwg_fill_header(tcp, sport, dport, flags, seq, ack_seq);

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
		 u8 tcp_flags, u32 tcp_seq, u32 tcp_ack_seq)
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

	skb->ignore_df = 1;
	tcpwg_tunnel_xmit4(rt, sock, skb, fl.saddr, fl.daddr, ds,
			   ip4_dst_hoplimit(&rt->dst), fl.fl4_sport,
			   fl.fl4_dport, tcp_flags, tcp_seq, tcp_ack_seq);
	goto out;

err:
	kfree_skb(skb);
out:
	rcu_read_unlock_bh();
	return ret;
}

static int send6(struct wg_device *wg, struct sk_buff *skb,
		 struct endpoint *endpoint, u8 ds, struct dst_cache *cache,
		 u8 tcp_flags, u32 tcp_seq, u32 tcp_ack_seq)
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
		dst = ipv6_stub->ipv6_dst_lookup_flow(sock_net(sock), sock, &fl,
						      NULL);
		if (IS_ERR(dst)) {
			ret = PTR_ERR(dst);
			net_dbg_ratelimited("%s: No route to %pISpfsc, error %d\n",
					    wg->dev->name, &endpoint->addr, ret);
			goto err;
		}
		if (cache)
			dst_cache_set_ip6(cache, dst, &fl.saddr);
	}

	skb->ignore_df = 1;
	tcpwg_tunnel_xmit6(dst, sock, skb, skb->dev, &fl.saddr, &fl.daddr,
			   ds, ip6_dst_hoplimit(dst), fl.fl6_sport,
			   fl.fl6_dport, tcp_flags, tcp_seq, tcp_ack_seq);
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
			    u8 flags, u32 seq, u32 ack_seq)
{
	struct sk_buff *skb;

	skb = alloc_skb(SKB_HEADER_LEN, GFP_ATOMIC);
	if (unlikely(!skb))
		return -ENOMEM;
	skb_reserve(skb, SKB_HEADER_LEN);
	skb_set_inner_network_header(skb, 0);

	if (endpoint->addr.sa_family == AF_INET)
		return send4(wg, skb, endpoint, 0, NULL, flags, seq, ack_seq);
	if (IS_ENABLED(CONFIG_IPV6) && endpoint->addr.sa_family == AF_INET6)
		return send6(wg, skb, endpoint, 0, NULL, flags, seq, ack_seq);

	kfree_skb(skb);
	return -EAFNOSUPPORT;
}

static bool tcpwg_fake_prepare_data(struct wg_peer *peer, struct endpoint *ep,
				    struct sk_buff *skb, u32 *seq, u32 *ack)
{
	struct tcpwg_fake_tcp *state = &peer->fake_tcp;
	bool send_syn = false;
	u32 syn_seq = 0;
	int ret;

	spin_lock_bh(&state->lock);
	if (!state->tuple_valid || !tcpwg_endpoint_equal(&state->tuple, ep)) {
		skb_queue_purge(&state->pending_tx);
		tcpwg_fake_reset_locked(peer, ep);
	}

	if (state->state == TCPWG_FAKE_ESTABLISHED) {
		*seq = state->tx_seq;
		*ack = state->rx_seq;
		state->tx_seq += max_t(u32, 1U, skb->len);
		state->last_seen = jiffies;
		spin_unlock_bh(&state->lock);
		return true;
	}

	if (skb_queue_len(&state->pending_tx) >= TCPWG_FAKE_PENDING_MAX) {
		atomic64_inc(&tcpwg_fake_pending_dropped);
		spin_unlock_bh(&state->lock);
		dev_kfree_skb(skb);
		return false;
	}

	skb_queue_tail(&state->pending_tx, skb);
	atomic64_inc(&tcpwg_fake_pending_queued);
	if (!state->last_syn_sent ||
	    time_after(jiffies, state->last_syn_sent + HZ)) {
		state->last_syn_sent = jiffies;
		state->state = TCPWG_FAKE_SYN_SENT;
		syn_seq = state->local_isn;
		send_syn = true;
	}
	spin_unlock_bh(&state->lock);

	if (send_syn) {
		ret = tcpwg_send_empty(peer->device, ep, TCPWG_SYN, syn_seq, 0);
		if (!ret)
			atomic64_inc(&tcpwg_fake_syn_sent);
	}
	return false;
}

void tcpwg_drain_pending_work(struct work_struct *work)
{
	struct wg_peer *peer = container_of(work, struct wg_peer,
					    fake_tcp.drain_work);
	struct sk_buff *skb;
	size_t skb_len;
	u32 seq, ack;
	int ret;

	while ((skb = skb_dequeue(&peer->fake_tcp.pending_tx)) != NULL) {
		skb_len = skb->len;
		read_lock_bh(&peer->endpoint_lock);
		spin_lock_bh(&peer->fake_tcp.lock);
		if (peer->fake_tcp.state != TCPWG_FAKE_ESTABLISHED ||
		    !peer->fake_tcp.tuple_valid ||
		    !tcpwg_endpoint_equal(&peer->fake_tcp.tuple,
					  &peer->endpoint)) {
			spin_unlock_bh(&peer->fake_tcp.lock);
			read_unlock_bh(&peer->endpoint_lock);
			dev_kfree_skb(skb);
			continue;
		}
		seq = peer->fake_tcp.tx_seq;
		ack = peer->fake_tcp.rx_seq;
		peer->fake_tcp.tx_seq += max_t(u32, 1U, skb_len);
		spin_unlock_bh(&peer->fake_tcp.lock);

		if (peer->endpoint.addr.sa_family == AF_INET)
			ret = send4(peer->device, skb, &peer->endpoint, 0,
				    &peer->endpoint_cache, TCPWG_ACK | TCPWG_PSH,
				    seq, ack);
		else if (peer->endpoint.addr.sa_family == AF_INET6)
			ret = send6(peer->device, skb, &peer->endpoint, 0,
				    &peer->endpoint_cache, TCPWG_ACK | TCPWG_PSH,
				    seq, ack);
		else {
			dev_kfree_skb(skb);
			ret = -EAFNOSUPPORT;
		}
		if (likely(!ret))
			peer->tx_bytes += skb_len;
		read_unlock_bh(&peer->endpoint_lock);
	}

	wg_peer_put(peer);
}

int wg_socket_send_skb_to_peer(struct wg_peer *peer, struct sk_buff *skb, u8 ds)
{
	size_t skb_len = skb->len;
	u32 seq, ack_seq;
	int ret = -EAFNOSUPPORT;

	read_lock_bh(&peer->endpoint_lock);
	if (peer->endpoint.addr.sa_family == AF_INET) {
		if (!tcpwg_fake_prepare_data(peer, &peer->endpoint, skb,
					     &seq, &ack_seq)) {
			read_unlock_bh(&peer->endpoint_lock);
			return 0;
		}
		ret = send4(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache, TCPWG_ACK | TCPWG_PSH,
			    seq, ack_seq);
	} else if (peer->endpoint.addr.sa_family == AF_INET6) {
		if (!tcpwg_fake_prepare_data(peer, &peer->endpoint, skb,
					     &seq, &ack_seq)) {
			read_unlock_bh(&peer->endpoint_lock);
			return 0;
		}
		ret = send6(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache, TCPWG_ACK | TCPWG_PSH,
			    seq, ack_seq);
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
	int ret = -EAFNOSUPPORT;

	read_lock_bh(&peer->endpoint_lock);
	if (peer->endpoint.addr.sa_family == AF_INET) {
		if (!tcpwg_fake_prepare_data(peer, &peer->endpoint, skb,
					     &seq, &ack_seq)) {
			read_unlock_bh(&peer->endpoint_lock);
			return 0;
		}
		ret = send4(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache, TCPWG_ACK | TCPWG_PSH,
			    seq, ack_seq);
	} else if (peer->endpoint.addr.sa_family == AF_INET6) {
		if (!tcpwg_fake_prepare_data(peer, &peer->endpoint, skb,
					     &seq, &ack_seq)) {
			read_unlock_bh(&peer->endpoint_lock);
			return 0;
		}
		ret = send6(peer->device, skb, &peer->endpoint, ds,
			    &peer->endpoint_cache, TCPWG_ACK | TCPWG_PSH,
			    seq, ack_seq);
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
	u32 seq, ack_seq;
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
			seq = state->tx_seq;
			ack_seq = state->rx_seq;
			state->tx_seq += max_t(u32, 1U, skb->len);
			state->last_seen = jiffies;
		}
		spin_unlock_bh(&state->lock);
	}

	if (endpoint.addr.sa_family == AF_INET)
		ret = send4(wg, skb, &endpoint, 0, NULL,
			    TCPWG_ACK | TCPWG_PSH, seq, ack_seq);
	else if (endpoint.addr.sa_family == AF_INET6)
		ret = send6(wg, skb, &endpoint, 0, NULL,
			    TCPWG_ACK | TCPWG_PSH, seq, ack_seq);
	/* No other possibilities if the endpoint is valid, which it is,
	 * as we checked above.
	 */

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
		skb_queue_purge(&state->pending_tx);
		tcpwg_fake_reset_locked(peer, endpoint);
		spin_unlock_bh(&state->lock);
	}
	dst_cache_reset(&peer->endpoint_cache);
out:
	write_unlock_bh(&peer->endpoint_lock);
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
	spin_lock_bh(&peer->fake_tcp.lock);
	skb_queue_purge(&peer->fake_tcp.pending_tx);
	peer->fake_tcp.state = TCPWG_FAKE_CLOSED;
	peer->fake_tcp.tuple_valid = false;
	peer->fake_tcp.local_isn = get_random_u32();
	peer->fake_tcp.tx_seq = peer->fake_tcp.local_isn;
	peer->fake_tcp.rx_seq = 0;
	peer->fake_tcp.last_syn_sent = 0;
	spin_unlock_bh(&peer->fake_tcp.lock);
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

	mutex_lock(&wg->socket_update_lock);
	old4 = rcu_dereference_protected(wg->sock4,
				lockdep_is_held(&wg->socket_update_lock));
	old6 = rcu_dereference_protected(wg->sock6,
				lockdep_is_held(&wg->socket_update_lock));
	rcu_assign_pointer(wg->sock4, new4);
	rcu_assign_pointer(wg->sock6, new6);
	if (new4)
		wg->incoming_port = ntohs(inet_sk(new4)->inet_sport);
	tcpwg_list_set(wg, new4 || new6);
	mutex_unlock(&wg->socket_update_lock);
	synchronize_net();
	sock_free(old4);
	sock_free(old6);
}
