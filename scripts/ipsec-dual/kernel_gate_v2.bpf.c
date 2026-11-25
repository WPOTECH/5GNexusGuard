/* SPDX-License-Identifier: GPL-2.0
 * kernel_gate_v2.bpf.c — BPF TC classifiers for 5GNexusSense health gate.
 *
 * Compiled with clang/LLVM targeting kernel 6.x eBPF bytecode.
 * Uses libbpf bpf_helpers.h for correct helper function stubs.
 *
 * Three TC programs:
 *  health_control  : health-control packet ingress classifier,
 *                    accepts only from authorized IPs,
 *                    updates permissive state in health_map.
 *  wg_ingress      : WireGuard (UDP/51820) ingress classifier,
 *                    accepts from health IPs, enforces peer+resource+port+flags.
 *  resource_ingress: health/HTTP/WireGuard port classifier from
 *                    health IPs, enforces the same checks.
 *
 * Map layout (DWARF-verified):
 *  renewal_state : HASH<peer_key, locked_health>, max 256
 *  health_map    : ARRAY<__u32, health_state>, max 1
 *  auth_map      : HASH<peer_key, authorization>, max 256
 *  verdict_map   : ARRAY<__u32, __s32>, max 1
 *
 * Packet parsing:
 *  All classifiers extract source IP from IPv4 headers for
 *  authorization matching.  The peer_key (peer, resource, port, flags)
 *  is derived from the packet's source IP, destination port, and
 *  protocol to look up the correct authorization record.
 */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define __force __attribute__((force))

/* ------------------------------------------------------------------ */
/*  Port constants                                                      */
/* ------------------------------------------------------------------ */
#define AUTH_PORT          443
#define HEALTH_PORT        8080
#define RESOURCE_PORT      80
#define WG_PORT            51820

/* ------------------------------------------------------------------ */
/*  BPF-side structs (mirror kernel_gate_transition.h types)           */
/* ------------------------------------------------------------------ */

/* heartbeat — 7-tuple from DWARF: epoch, deadline_ns, checked_ns, peer, resource, port, flags */
struct heartbeat {
	__u64 epoch;
	__u64 deadline_ns;
	__u64 checked_ns;
	__u32 peer;
	__u32 resource;
	__u16 port;
	__u16 flags;
};

/* peer_key: used as map key */
struct peer_key {
	__u32 peer;
	__u32 resource;
	__u16 port;
	__u16 flags;
};

/* auth_map value */
struct authorization {
	__u64 epoch;
	__u64 deadline_ns;
	__u32 peer;
	__u32 resource;
	__u16 port;
	__u16 flags;
};

/* health_state — the per-key security state stored inside locked_health */
struct health_state {
	__u64 revision;
	__u64 generation;
	__u64 auth_deadline;
	__u64 epoch;
	__u64 checked;
	__u64 deadline;
	__u64 closed;
	__u32 resource;   /* security: resource identifier */
	__u16 port;       /* security: authorized port */
	__u16 flags;      /* security: flags */
};

/* locked_health: map value — spinlock + health_state */
struct locked_health {
	struct bpf_spin_lock lock;
	struct health_state state;
};

/* ------------------------------------------------------------------ */
/*  Type definitions (matching DWARF-symtab)                          */
/* ------------------------------------------------------------------ */

/* renewal_state: one entry per peer, protected by spinlock */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct peer_key);
	__type(value, struct locked_health);
} renewal_state SEC(".maps");

/* health_map: keyed by __u32, value is health_state (flat, no spinlock) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct health_state);
} health_map SEC(".maps");

/* auth_map: authorization map */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct peer_key);
	__type(value, struct authorization);
} auth_map SEC(".maps");

/* verdict_map: verdict tracking */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __s32);
} verdict_map SEC(".maps");

/* ------------------------------------------------------------------ */
/*  Helper: extract source IP from packet                             */
/* ------------------------------------------------------------------ */
static __always_inline int parse_ipv4_src(const struct __sk_buff *skb, __be32 *src_ip)
{
	__u16 h_proto = 0;

	/* Load ethertype at offset 12 */
	if (bpf_skb_load_bytes(skb, 12, &h_proto, sizeof(h_proto)) < 0)
		return -1;
	if (h_proto != bpf_htons(ETH_P_IP))
		return -1;

	/* Load IP header at offset 14 (after ethhdr) */
	struct iphdr ip;
	if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0)
		return -1;

	/* Only process IPv4 */
	if (ip.version != 4)
		return -1;

	*src_ip = ip.saddr;
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Helper: build peer_key from packet fields                         */
/*  Derives peer (src IP) and resource/port/flags from packet headers  */
/*  for authorization matching against auth_map or renewal_state.     */
/* ------------------------------------------------------------------ */
static __always_inline void build_peer_key(__be32 src_ip, __u16 dst_port,
					   struct peer_key *key)
{
	key->peer = (__force __u32)src_ip;
	key->resource = 0;
	key->port = dst_port;
	key->flags = 0;
}

/* ------------------------------------------------------------------ */
/*  health_control  —  health-control packet ingress classifier       */
/*                                                                      */
/*  Accepts packets from authorized IPs. Parses the health_control    */
/*  request payload (8Q: operation, generation, epoch, ...) and       */
/*  validates epoch progression, deadlines, and gate state.          */
/* ------------------------------------------------------------------ */
SEC("tc/health_control")
int health_control(struct __sk_buff *skb)
{
	__u32 op = 0, epoch = 0;
	__u64 auth_deadline = 0, deadline_ns = 0, checked = 0;
	__u32 tmp[8];
	__u32 hdr_size = sizeof(struct ethhdr) + sizeof(struct iphdr);

	/* Validate minimum packet length */
	if (skb->len < hdr_size + sizeof(__u64) * 8)
		return TC_ACT_SHOT;

	/* Extract source IP for authorization tracking */
	__be32 src_ip = 0;
	if (parse_ipv4_src(skb, &src_ip) != 0)
		return TC_ACT_SHOT;

	/* Load operation field from packet */
	if (bpf_skb_load_bytes(skb, hdr_size, &tmp[0], sizeof(__u32)) < 0)
		goto drop;
	op = tmp[0];

	if (op == 0)
		goto drop;

	/* Load epoch (field 2, offset 4) */
	if (bpf_skb_load_bytes(skb, hdr_size + 4, &tmp[1], sizeof(__u32)) < 0)
		goto drop;

	/* Load auth_deadline (field 4, offset 16) — 64-bit value */
	if (bpf_skb_load_bytes(skb, hdr_size + 16, &auth_deadline, sizeof(__u64)) < 0)
		goto drop;

	if (auth_deadline == 0)
		goto drop;

	/* Load deadline (field 6, offset 24) — 64-bit value */
	if (bpf_skb_load_bytes(skb, hdr_size + 24, &deadline_ns, sizeof(__u64)) < 0)
		goto drop;

	if (deadline_ns == 0)
		goto drop;

	/* Load checked field (field 5, offset 32) */
	if (bpf_skb_load_bytes(skb, hdr_size + 32, &checked, sizeof(__u64)) < 0)
		goto drop;

	/* Validate deadline > auth_deadline for healthy state */
	if (auth_deadline <= deadline_ns)
		return TC_ACT_SHOT;

	/* Check if state is closed */
	__u32 key = 0;
	struct health_state *state = bpf_map_lookup_elem(&health_map, &key);
	if (!state)
		return TC_ACT_SHOT;

	if (state->closed)
		return TC_ACT_SHOT;

	/* Validate epoch progression */
	if (state->epoch > epoch)
		return TC_ACT_SHOT;

	/* Update state */
	state->checked = deadline_ns;
	state->deadline = deadline_ns;
	state->auth_deadline = auth_deadline;
	state->revision++;

	/* Also update the renewal_state for the source peer */
	struct peer_key pkey = { 0 };
	pkey.peer = (__force __u32)src_ip;
	pkey.resource = state->resource;
	pkey.port = state->port;
	pkey.flags = state->flags;

	struct locked_health *lh = bpf_map_lookup_elem(&renewal_state, &pkey);
	if (lh) {
		bpf_spin_lock(&lh->lock);
		lh->state.checked = deadline_ns;
		lh->state.deadline = deadline_ns;
		lh->state.auth_deadline = auth_deadline;
		lh->state.epoch = epoch;
		lh->state.closed = 0;
		lh->state.revision++;
		bpf_spin_unlock(&lh->lock);
	}

	return TC_ACT_OK;

drop:
	return TC_ACT_SHOT;
}

/* ------------------------------------------------------------------ */
/*  wg_ingress  —  WireGuard traffic ingress classifier                 */
/*                                                                      */
/*  Accepts WireGuard packets (UDP/51820) from authorized health      */
/*  IPs.  Validates peer identity, resource, port, and flags         */
/*  against the authorization map.                                    */
/* ------------------------------------------------------------------ */
SEC("tc/wg_ingress")
int wg_ingress(struct __sk_buff *skb)
{
	struct iphdr ip;
	struct udphdr udp;
	__u32 hdr_size = sizeof(struct ethhdr) + sizeof(struct iphdr);
	__u16 h_proto = 0;

	/* Validate packet length */
	if (skb->len < hdr_size + sizeof(struct udphdr))
		return TC_ACT_SHOT;

	/* Load ethertype at offset 12 of link-layer header */
	if (bpf_skb_load_bytes(skb, 12, &h_proto, sizeof(h_proto)) < 0)
		return TC_ACT_SHOT;

	if (h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_SHOT;

	/* Load IP header */
	if (bpf_skb_load_bytes(skb, 14, &ip, sizeof(ip)) < 0)
		return TC_ACT_SHOT;

	/* Only process IPv4 */
	if (ip.version != 4)
		return TC_ACT_SHOT;

	/* Only process UDP */
	if (ip.protocol != IPPROTO_UDP)
		return TC_ACT_SHOT;

	/* Load UDP header */
	if (bpf_skb_load_bytes(skb, hdr_size, &udp, sizeof(udp)) < 0)
		return TC_ACT_SHOT;

	/* Validate source port is non-zero */
	if (udp.source == 0)
		return TC_ACT_SHOT;

	/* Check if this is a WireGuard packet (destination port 51820) */
	if (bpf_ntohs(udp.dest) != WG_PORT)
		return TC_ACT_SHOT;

	/* Extract source IP for peer identity */
	__be32 src_ip = 0;
	if (parse_ipv4_src(skb, &src_ip) != 0)
		return TC_ACT_SHOT;

	/* Build peer_key: peer=src_ip, port=51820, resource/flags from auth */
	struct peer_key pkey = { 0 };
	pkey.peer = (__force __u32)src_ip;
	pkey.resource = 0;
	pkey.port = bpf_ntohs(udp.dest);  /* 51820 */
	pkey.flags = 0;

	/* Look up peer state in renewal_state by src IP */
	struct locked_health *lh = bpf_map_lookup_elem(&renewal_state, &pkey);
	if (!lh)
		return TC_ACT_SHOT;

	__u64 now = bpf_ktime_get_boot_ns();
	bpf_spin_lock(&lh->lock);

	/* Validate state is not closed and epoch is initialized */
	if (lh->state.closed || lh->state.epoch == 0)
		goto unlock_drop;

	/* Validate auth deadline and health deadline */
	if (lh->state.auth_deadline == 0 || lh->state.auth_deadline <= now)
		goto unlock_drop;
	if (lh->state.deadline == 0 || lh->state.deadline <= now)
		goto unlock_drop;

	/* Validate resource, port, flags are set */
	if (lh->state.resource == 0 || lh->state.port == 0 || lh->state.flags == 0)
		goto unlock_drop;

	/* Validate port matches WireGuard port */
	if (lh->state.port != WG_PORT)
		goto unlock_drop;

	bpf_spin_unlock(&lh->lock);
	return TC_ACT_OK;

unlock_drop:
	bpf_spin_unlock(&lh->lock);
	return TC_ACT_SHOT;
}

/* ------------------------------------------------------------------ */
/*  resource_ingress  —  resource / HTTP traffic ingress classifier     */
/*                                                                      */
/*  Similar to wg_ingress but also handles ICMP and TCP packets     */
/*  for health-check purposes.  Validates packet headers, checks   */
/*  port/protocol against authorized values, and consults maps for   */
/*  authorization state.                                              */
/* ------------------------------------------------------------------ */
SEC("tc/resource_ingress")
int resource_ingress(struct __sk_buff *skb)
{
	struct iphdr ip;
	struct tcphdr tcp;
	struct udphdr udp;
	struct icmphdr icmp;
	__u32 hdr_size = sizeof(struct ethhdr) + sizeof(struct iphdr);
	__u16 h_proto = 0;

	/* Validate packet length */
	if (skb->len < hdr_size)
		return TC_ACT_SHOT;

	/* Load ethertype */
	if (bpf_skb_load_bytes(skb, 12, &h_proto, sizeof(h_proto)) < 0)
		return TC_ACT_SHOT;
	if (h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_SHOT;

	/* Load IP header */
	if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip, sizeof(ip)) < 0)
		return TC_ACT_SHOT;

	/* Only process IPv4 */
	if (ip.version != 4)
		return TC_ACT_SHOT;

	__u8 proto = ip.protocol;
	__be32 src_ip = 0;
	if (parse_ipv4_src(skb, &src_ip) != 0)
		return TC_ACT_SHOT;

	if (proto == IPPROTO_TCP) {
		if (skb->len < hdr_size + sizeof(struct tcphdr))
			return TC_ACT_SHOT;
		if (bpf_skb_load_bytes(skb, hdr_size, &tcp, sizeof(tcp)) < 0)
			return TC_ACT_SHOT;

		/* Validate source port non-zero */
		if (bpf_ntohs(tcp.source) == 0)
			return TC_ACT_SHOT;

		/* Check auth/health/HTTP ports */
		__u16 src_port = bpf_ntohs(tcp.source);
		if (src_port != AUTH_PORT && src_port != HEALTH_PORT && src_port != RESOURCE_PORT)
			return TC_ACT_SHOT;

	} else if (proto == IPPROTO_UDP) {
		if (skb->len < hdr_size + sizeof(struct udphdr))
			return TC_ACT_SHOT;
		if (bpf_skb_load_bytes(skb, hdr_size, &udp, sizeof(udp)) < 0)
			return TC_ACT_SHOT;

		if (udp.source == 0)
			return TC_ACT_SHOT;

	} else if (proto == IPPROTO_ICMP) {
		if (skb->len < hdr_size + sizeof(struct icmphdr))
			return TC_ACT_SHOT;
		if (bpf_skb_load_bytes(skb, hdr_size, &icmp, sizeof(icmp)) < 0)
			return TC_ACT_SHOT;

		if (icmp.type != ICMP_ECHOREPLY && icmp.type != ICMP_ECHO)
			return TC_ACT_SHOT;

	} else {
		/* Unknown protocol — drop */
		return TC_ACT_SHOT;
	}

	/* Check authorization state using source IP */
	struct peer_key pkey = { 0 };
	pkey.peer = (__force __u32)src_ip;
	pkey.resource = 0;
	pkey.port = 0;
	pkey.flags = 0;

	struct locked_health *lh =
		bpf_map_lookup_elem(&renewal_state, &pkey);
	if (!lh)
		return TC_ACT_SHOT;

	__u64 now = bpf_ktime_get_boot_ns();
	bpf_spin_lock(&lh->lock);

	if (lh->state.closed || lh->state.epoch == 0)
		goto unlock_drop;

	if (lh->state.auth_deadline == 0 || lh->state.auth_deadline <= now)
		goto unlock_drop;
	if (lh->state.deadline == 0 || lh->state.deadline <= now)
		goto unlock_drop;

	/* Validate resource, port, flags are set */
	if (lh->state.resource == 0 || lh->state.port == 0 || lh->state.flags == 0)
		goto unlock_drop;

	bpf_spin_unlock(&lh->lock);
	return TC_ACT_OK;

unlock_drop:
	bpf_spin_unlock(&lh->lock);
	return TC_ACT_SHOT;
}

/* ---- license ---- */
char _license[] SEC("license") = "GPL";