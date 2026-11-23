/* kernel_gate_transition.h — shared types between kernel BPF and user-space publisher */
#ifndef KERNEL_GATE_TRANSITION_H
#define KERNEL_GATE_TRANSITION_H

#ifdef __KERNEL__
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

/* health_control state (inside spinlock) */
struct health_control_state {
    __u64 epoch;
    __u64 deadline;
    __u64 auth_deadline;
    __u64 checked;
    __u64 revision;
    __u8 closed;
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

    /* State must be open (not closed by revoke) or just opening */
    if (state->closed)
        return 0;

    /* Update state atomically (we're already inside the spinlock) */
    state->epoch = req->epoch;
    state->deadline = req->deadline;
    state->auth_deadline = req->auth_deadline;
    state->checked = req->checked;
    state->revision++;
    state->closed = 0;
    return 1;
}

#endif /* KERNEL_GATE_TRANSITION_H */