/* kernel_gate_transition.h — shared types between kernel BPF and user-space publisher */
#ifndef KERNEL_GATE_TRANSITION_H
#define KERNEL_GATE_TRANSITION_H

#ifdef __KERNEL__
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>
#elif defined(__BPF__)
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/types.h>
#else
#include <linux/bpf.h>
#include <netinet/in.h>
#include <stdint.h>
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t __s32;
typedef __u64 __aligned_u64;
#endif

#define PEER   0x01020304U
#define RESOURCE  0x05060708U
#define PORT   51820

#define GATE_MARK  0xDEAD

/* Operation codes for health_control request */
#define HEALTH_REVOKE 2
#define HEALTH_PUBLISH 1

/* Atomic health map — packed 7-tuple: epoch, deadline_ns, checked_ns, peer, resource, port, flags */
struct heartbeat {
    __u64 epoch;
    __u64 deadline_ns;
    __u64 checked_ns;
    __u32 peer;
    __u32 resource;
    __u16 port;
    __u16 flags;
};

struct authorization {
    __u64 epoch;
    __u64 deadline_ns;
    __u32 peer;
    __u32 resource;
    __u16 port;
    __u16 flags;
};

/* health_control request — 8×64-bit = 64 bytes */
struct health_control_request {
    __u64 operation;    /* 0: reserved, 1: publish, 2: revoke */
    __u64 generation;
    __u64 epoch;
    __u64 auth_deadline;
    __u64 checked;
    __u64 deadline;
    __u64 publish_before;
    __u64 previous_checked;
};

/* health_control state (inside spinlock) — 7 fields, 56 bytes (matching DWARF) */
struct health_control_state {
    __u64 revision;
    __u64 generation;
    __u64 auth_deadline;
    __u64 epoch;
    __u64 checked;
    __u64 deadline;
    __u64 closed;
};

/* locked_health: map value, contains spinlock and state */
struct locked_health {
    struct bpf_spin_lock lock;
    struct health_control_state state;
};

/* peer_key: used as map key */
struct peer_key {
    __u32 peer;
    __u32 resource;
    __u16 port;
    __u16 flags;
};

/* health_transition — kernel-side transition logic (called inside spinlock) */
static __always_inline int health_transition(struct health_control_state *state,
                                              const struct health_control_request *req,
                                              __u64 now)
{
    if (req->operation == HEALTH_REVOKE) {
        state->closed = 1;
        state->revision++;
        return 1;
    }

    if (req->operation != HEALTH_PUBLISH)
        return 0;

    /* Validate: deadline and auth_deadline must be positive */
    if (req->deadline <= 0 || req->auth_deadline <= 0)
        return 0;

    /* Reject publication whose deadline is already past — prevents
       expired-epoch resurrection when BOOTTIME has moved on. */
    if (req->deadline <= now || req->auth_deadline <= now)
        return 0;

    /* State must be open (not closed by revoke) or just opening */
    if (state->closed)
        return 0;

    /* Only allow strictly increasing epochs to prevent resurrection.
     * Same-epoch renewals are permitted when fresh: the health deadline
     * must advance (checked_ns must be >= old checked_ns), ensuring the
     * renewal is actually updating state rather than re-attacking. */
    if (state->epoch > req->epoch) {
        /* New epoch — always allowed if state is open */
    } else if (state->epoch == req->epoch) {
        /* Same epoch — only allow if health is advancing */
        if (req->checked <= state->checked)
            return 0;
    } else {
        /* Backwards epoch — rejected (prevents epoch rollback) */
        return 0;
    }

    /* Update state atomically (we're already inside the spinlock) */
    state->epoch = req->epoch;
    state->deadline = req->deadline;
    state->auth_deadline = req->auth_deadline;
    state->checked = req->checked;
    state->revision++;
    state->closed = 0;
    return 1;
}

/* atomic_verdict — read clock then acquire lock to capture state.
 *
 * NOTE: bpf_ktime_get_boot_ns() is called BEFORE the spinlock because
 * the BPF verifier forbids any helper call (including bpf_ktime_get_boot_ns)
 * while a bpf_spin_lock is held.  This means there is a small window
 * between the time sample and the lock acquisition during which the state
 * could be modified by a concurrent publisher.  The lock guarantees that
 * once acquired, no further concurrent modification of the state struct
 * can occur — but the time value itself is not strictly atomic with the
 * state snapshot.
 *
 * All state checks and comparisons below happen inside the critical section.
 *
 * Returns:
 *   1  – pass (packet may be forwarded)
 *  -2  – AUTH_DEADLINE_DENIED (original authorization expired)
 *  -1  – HEALTH_DEADLINE_DENIED (health window closed)
 *  -3  – EPOCH_SCOPE_DENIED (epoch 0, epoch mismatch, or scope mismatch)
 */
static __always_inline int atomic_verdict(__u32 key)
{
    struct locked_health *lh = bpf_map_lookup_elem(&renewal_state, &key);
    if (!lh)
        return -3;

    /* Time sampled BEFORE the lock — permitted by the BPF verifier.
     * A publisher holding the lock could modify state between this
     * read and the lock acquisition, so the time/state pair is not
     * strictly atomic.  See module-level comment above. */
    __u64 now = bpf_ktime_get_boot_ns();

    bpf_spin_lock(&lh->lock);

    if (lh->state.closed) {
        bpf_spin_unlock(&lh->lock);
        return -3;
    }
    if (lh->state.epoch == 0) {
        bpf_spin_unlock(&lh->lock);
        return -3;
    }
    if (lh->state.auth_deadline == 0) {
        bpf_spin_unlock(&lh->lock);
        return -2;
    }
    if (lh->state.auth_deadline <= now) {
        bpf_spin_unlock(&lh->lock);
        return -2;
    }
    if (lh->state.deadline == 0) {
        bpf_spin_unlock(&lh->lock);
        return -1;
    }
    if (lh->state.deadline <= now) {
        bpf_spin_unlock(&lh->lock);
        return -1;
    }
    if (lh->state.checked > now) {
        bpf_spin_unlock(&lh->lock);
        return -1;
    }

    bpf_spin_unlock(&lh->lock);
    return 1;
}

#endif /* KERNEL_GATE_TRANSITION_H */