// Isolated TC classifier prototype. NOT attached by production native.py.
// Install nft independent deny interlock before attaching BOTH TC ingress hooks.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define GATE_MARK 0x5a17c0deU
#define PEER 0x0a4f0001U      // 10.79.0.1
#define RESOURCE 0x0a500002U  // 10.80.0.2
#define PORT 8080
#define ARPHRD_ETHER 1
#define ARPOP_REPLY 2

// One slot per isolated gate. Userspace must NEVER rewrite a live auth epoch
// from a wall-clock lease; fresh BOOTTIME-issued authority is required.
struct authorization {
    __u64 epoch;
    __u64 deadline_ns;
    __u32 peer;
    __u32 resource;
    __u16 port;
    __u16 reserved;
};
struct heartbeat {
    __u64 epoch;
    __u64 deadline_ns;
    __u64 checked_ns;
    __u32 peer;
    __u32 resource;
    __u16 port;
    __u16 reserved;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct authorization);
} auth_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct heartbeat);
} health_map SEC(".maps");

// Diagnostic-only, monotonic counters. Index 0..15 is wg-inner ingress;
// 16..31 is resource ingress. Scoped counters count ONLY the expected SYN.
// These never participate in an authorization decision.
enum reason {
    INVOKED, PARSE_DENIED, SCOPE_DENIED, SYN_MATCHED,
    AUTH_MISSING, HEALTH_MISSING, EPOCH_SCOPE_DENIED,
    AUTH_DEADLINE_DENIED, HEALTH_DEADLINE_DENIED,
    SYN_PASSED, SYN_DROPPED, ICMP_PASSED, ARP_REPLY_PASSED
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, __u64);
} verdict_map SEC(".maps");

static __always_inline void count(int reverse, __u32 reason)
{
    __u32 key = (__u32)(reverse * 16) + reason;
    __u64 *value = bpf_map_lookup_elem(&verdict_map, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

struct arp_eth_ipv4 {
    __be16 ar_hrd;
    __be16 ar_pro;
    __u8 ar_hln;
    __u8 ar_pln;
    __be16 ar_op;
    __u8 sha[ETH_ALEN];
    __be32 ar_sip;
    __u8 tha[ETH_ALEN];
    __be32 ar_tip;
} __attribute__((packed));

static __always_inline int classify(struct __sk_buff *skb, int reverse)
{
    count(reverse, INVOKED);
    // Clear any incoming mark first. nft's independent base chain accepts
    // ONLY this gate's mark AND its exact tuple; detach leaves no marker.
    skb->mark = 0;
    void *data = (void *)(long)skb->data;
    void *end = (void *)(long)skb->data_end;
    struct iphdr *ip;
    if (reverse) {
        // resource ingress is veth/Ethernet; wg-inner ingress is L3/IP.
        struct ethhdr *eth = data;
        if ((void *)(eth + 1) > end) {
            count(reverse, PARSE_DENIED);
            return TC_ACT_SHOT;
        }
        // Neighbor resolution is local L2 plumbing, not an IP grant. Accept
        // only this resource's ARP reply to the gateway; keep the mark clear.
        if (eth->h_proto == bpf_htons(ETH_P_ARP)) {
            struct arp_eth_ipv4 *arp = (void *)(eth + 1);
            if ((void *)(arp + 1) > end ||
                arp->ar_hrd != bpf_htons(ARPHRD_ETHER) ||
                arp->ar_pro != bpf_htons(ETH_P_IP) ||
                arp->ar_hln != ETH_ALEN || arp->ar_pln != 4 ||
                arp->ar_op != bpf_htons(ARPOP_REPLY) ||
                arp->ar_sip != bpf_htonl(RESOURCE) ||
                arp->ar_tip != bpf_htonl(0x0a500001U) ||
                __builtin_memcmp(arp->sha, eth->h_source, ETH_ALEN) ||
                __builtin_memcmp(arp->tha, eth->h_dest, ETH_ALEN)) {
                count(reverse, PARSE_DENIED);
                return TC_ACT_SHOT;
            }
            count(reverse, ARP_REPLY_PASSED);
            return TC_ACT_OK;  // No forwarded IP permit.
        }
        if (eth->h_proto != bpf_htons(ETH_P_IP)) {
            count(reverse, PARSE_DENIED);
            return TC_ACT_SHOT;
        }
        ip = (void *)(eth + 1);
    } else {
        if (skb->protocol != bpf_htons(ETH_P_IP)) {
            count(reverse, PARSE_DENIED);
            return TC_ACT_SHOT;
        }
        ip = data;
    }
    if ((void *)(ip + 1) > end || ip->version != 4 || ip->ihl < 5 ||
        (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_ICMP) ||
        (bpf_ntohs(ip->frag_off) & 0x3fff)) {
        count(reverse, PARSE_DENIED);
        return TC_ACT_SHOT;
    }
    __u32 bytes = (__u32)ip->ihl * 4;
    if ((void *)ip + bytes > end) {
        count(reverse, PARSE_DENIED);
        return TC_ACT_SHOT;
    }
    // Only unmarked echo requests to the gateway's own inner-local address.
    // No ICMP forwarding, replies, or authorization-map access in this branch.
    if (!reverse && ip->protocol == IPPROTO_ICMP) {
        struct { __u8 type, code; __u16 checksum, id, sequence; } *icmp = (void *)ip + bytes;
        if ((void *)(icmp + 1) > end || ip->saddr != bpf_htonl(PEER) ||
            ip->daddr != bpf_htonl(0x0a4f0002U) ||
            bpf_ntohs(ip->tot_len) < bytes + sizeof(*icmp) + 16 ||
            bpf_ntohs(ip->tot_len) > bytes + sizeof(*icmp) + 64 ||
            icmp->type != 8 || icmp->code != 0) {
            count(reverse, PARSE_DENIED);
            return TC_ACT_SHOT;
        }
        count(reverse, ICMP_PASSED);
        return TC_ACT_OK;
    }
    if (ip->protocol != IPPROTO_TCP) {
        count(reverse, PARSE_DENIED);
        return TC_ACT_SHOT;
    }
    struct tcphdr *tcp = (void *)ip + bytes;
    if ((void *)(tcp + 1) > end) {
        count(reverse, PARSE_DENIED);
        return TC_ACT_SHOT;
    }
    __u32 peer = bpf_htonl(PEER), resource = bpf_htonl(RESOURCE);
    if (reverse ? (ip->saddr != resource || ip->daddr != peer ||
                   tcp->source != bpf_htons(PORT)) :
                  (ip->saddr != peer || ip->daddr != resource ||
                   tcp->dest != bpf_htons(PORT))) {
        count(reverse, SCOPE_DENIED);
        return TC_ACT_SHOT;
    }
    int tracked_syn = !reverse && tcp->syn && !tcp->ack;
    if (tracked_syn)
        count(reverse, SYN_MATCHED);
    __u32 key = 0;
    struct authorization *auth = bpf_map_lookup_elem(&auth_map, &key);
    struct heartbeat *health = bpf_map_lookup_elem(&health_map, &key);
    if (!auth || !auth->epoch) {
        if (tracked_syn) { count(reverse, AUTH_MISSING); count(reverse, SYN_DROPPED); }
        return TC_ACT_SHOT;
    }
    if (!health || !health->epoch) {
        if (tracked_syn) { count(reverse, HEALTH_MISSING); count(reverse, SYN_DROPPED); }
        return TC_ACT_SHOT;
    }
    if (health->epoch != auth->epoch ||
        auth->peer != peer || auth->resource != resource || auth->port != PORT ||
        health->peer != auth->peer || health->resource != auth->resource ||
        health->port != auth->port) {
        if (tracked_syn) { count(reverse, EPOCH_SCOPE_DENIED); count(reverse, SYN_DROPPED); }
        return TC_ACT_SHOT;
    }
    __u64 now = bpf_ktime_get_boot_ns();
    if (!auth->deadline_ns || now >= auth->deadline_ns) {
        if (tracked_syn) { count(reverse, AUTH_DEADLINE_DENIED); count(reverse, SYN_DROPPED); }
        return TC_ACT_SHOT;
    }
    if (!health->deadline_ns ||
        health->deadline_ns <= health->checked_ns ||
        health->deadline_ns - health->checked_ns > 500000000ULL ||
        now < health->checked_ns ||
        now >= health->deadline_ns) {
        if (tracked_syn) { count(reverse, HEALTH_DEADLINE_DENIED); count(reverse, SYN_DROPPED); }
        return TC_ACT_SHOT;
    }
    skb->mark = GATE_MARK;
    if (tracked_syn) count(reverse, SYN_PASSED);
    return TC_ACT_OK;
}

SEC("tc/wg_ingress")
int wg_ingress(struct __sk_buff *skb) { return classify(skb, 0); }

SEC("tc/resource_ingress")
int resource_ingress(struct __sk_buff *skb) { return classify(skb, 1); }

char LICENSE[] SEC("license") = "GPL";
