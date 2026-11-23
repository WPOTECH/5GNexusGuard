/* SPDX-License-Identifier: GPL-2.0
 * kernel_gate_v2.bpf.c — dual ingress BPF gate with optional atomic health.
 *
 * Base implementation (commit 8b09e0f) plus atomic health patch (diff in bpf_diff.txt).
 * Compiled with -DNEXUS_ATOMIC_HEALTH for the acceptance guest.
 */
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "kernel_gate_transition.h"

/* ---- constants ---- */
#define PEER      0xc0000201  /* 192.0.2.1 */
#define RESOURCE  0xc0000202  /* 192.0.2.2 */
#define PORT      51821
#define GATE_MARK 0x80000001
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

/* ---- map definitions ---- */
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
#ifdef NEXUS_ATOMIC_HEALTH
    __uint(map_flags, BPF_F_RDONLY);
#endif
} health_map SEC(".maps");

#ifdef NEXUS_ATOMIC_HEALTH
struct locked_health {
    struct bpf_spin_lock lock;
    struct health_control_state state;
};
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __uint(map_flags, BPF_F_RDONLY);
    __type(key, __u32);
    __type(value, struct locked_health);
} renewal_state SEC(".maps");
#endif

/* ---- diagnostic counters ---- */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

static __always_inline void count(int reverse, int index)
{
    __u32 key = reverse ? index + 16 : index;
    __u64 *val = bpf_map_lookup_elem(&counters, &key);
    if (val)
        (*val)++;
}

/* ---- SYN diagnostic indices ---- */
enum { SYN_MATCHED = 0, SYN_DROPPED, SYN_PASSED,
       AUTH_DEADLINE_DENIED, HEALTH_DEADLINE_DENIED, EPOCH_SCOPE_DENIED };

/* ---- classify (shared between ingress hooks) ---- */
static __always_inline int classify(struct __sk_buff *skb, int reverse)
{
    /* Simple SYN check: look for TCP SYN in ip_proto==6 */
    struct iphdr *iph;
    int proto;
    if (bpf_skb_load_bytes(skb, offsetof(struct iphdr, protocol), &proto, sizeof(proto)))
        return TC_ACT_OK;

    bool tracked_syn = (proto == 6);

#ifdef NEXUS_ATOMIC_HEALTH
    int verdict = atomic_verdict(0);
    if (verdict != 1) {
        if (tracked_syn) {
            count(reverse, verdict == -2 ? AUTH_DEADLINE_DENIED :
                           verdict == -1 ? HEALTH_DEADLINE_DENIED : EPOCH_SCOPE_DENIED);
            count(reverse, SYN_DROPPED);
        }
        return TC_ACT_SHOT;
    }
#else
    struct authorization *auth = bpf_map_lookup_elem(&auth_map, &key);
    struct heartbeat *health = bpf_map_lookup_elem(&health_map, &key);
    if (!auth || !auth->epoch) {
        if (tracked_syn) { count(reverse, EPOCH_SCOPE_DENIED); count(reverse, SYN_DROPPED); }
        return TC_ACT_SHOT;
    }
    __u64 now = bpf_ktime_get_boot_ns();
    if (now >= auth->deadline_ns) {
        if (tracked_syn) { count(reverse, AUTH_DEADLINE_DENIED); count(reverse, SYN_DROPPED); }
        return TC_ACT_SHOT;
    }
    if (!health || !health->epoch || now >= health->deadline_ns ||
        now < health->checked_ns) {
        if (tracked_syn) { count(reverse, HEALTH_DEADLINE_DENIED); count(reverse, SYN_DROPPED); }
        return TC_ACT_SHOT;
    }
#endif
    skb->mark = GATE_MARK;
    if (tracked_syn) count(reverse, SYN_PASSED);
    return TC_ACT_OK;
}

/* ---- ingress hooks (placeholder — TC attach is host-side) ---- */
SEC("tc/wg-inner")
int wg_inner_ingress(struct __sk_buff *skb)
{
    return classify(skb, 0);
}

SEC("tc/resource")
int resource_ingress(struct __sk_buff *skb)
{
    return classify(skb, 1);
}

char _license[] SEC("license") = "GPL";