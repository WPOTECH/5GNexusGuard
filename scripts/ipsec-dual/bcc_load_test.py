#!/usr/bin/env python3
"""BCC loader for TC health check BPF program."""
import ctypes, ctypes.util, os, sys
from bcc import BPF

# Minimal BCC program — only linux/pkt_cls.h to avoid broken linux/bpf.h on kernel 6.17
prog_text = """\
#include <linux/pkt_cls.h>

int tc_health_check(struct __sk_buff *skb) {
    return TC_ACT_OK;
}
"""

print("Loading BPF program via bcc...")
b = BPF(text=prog_text)
fn = b.load_func("tc_health_check", BPF.SCHED_CLS)
print(f"Program loaded: fd={fn.fd}")

libc = ctypes.CDLL("libc.so.6")

# Try various interface names
idx = 0
for ifname in ["ns_tc:veth_tc", "veth_tc", "ns_tc2:veth_tc2", "veth_tc2"]:
    i = libc.if_nametoindex(ifname.encode())
    if i > 0:
        idx = i
        print(f"Found {ifname} with ifindex={idx}")
        break

if idx == 0:
    print("No suitable interface found, trying container's eth0")
    idx = libc.if_nametoindex(b"eth0")

if idx == 0:
    print("ERROR: No interface found")
    sys.exit(1)

BPF_PROG_ATTACH = 44
syscall_fn = libc.syscall
syscall_fn.restype = ctypes.c_long
syscall_fn.argtypes = []

# Try new kernel format (with target_revision)
class bpf_prog_attach_attr(ctypes.Structure):
    _fields_ = [
        ("target_fd", ctypes.c_uint),
        ("attach_bpf_fd", ctypes.c_uint),
        ("attach_type", ctypes.c_uint),
        ("attach_flags", ctypes.c_uint),
        ("target_revision", ctypes.c_uint),
    ]

attr = bpf_prog_attach_attr()
attr.target_fd = idx
attr.attach_bpf_fd = fn.fd
attr.attach_type = 32  # BPF_ATTACH_TYPE_SCHED_CLS_INGRESS
attr.attach_flags = 0

result = syscall_fn(BPF_PROG_ATTACH, ctypes.addressof(attr))
if result < 0:
    err = ctypes.get_errno()
    print(f"New-format TC attach failed: {os.strerror(err)} (errno={err})")

    # Try old kernel format (without target_revision)
    class bpf_prog_attach_attr_old(ctypes.Structure):
        _fields_ = [
            ("target_fd", ctypes.c_uint),
            ("attach_bpf_fd", ctypes.c_uint),
            ("attach_type", ctypes.c_uint),
            ("attach_flags", ctypes.c_uint),
        ]

    attr_old = bpf_prog_attach_attr_old()
    attr_old.target_fd = idx
    attr_old.attach_bpf_fd = fn.fd
    attr_old.attach_type = 32
    attr_old.attach_flags = 0

    result2 = syscall_fn(BPF_PROG_ATTACH, ctypes.addressof(attr_old))
    if result2 < 0:
        err2 = ctypes.get_errno()
        print(f"Old-format TC attach also failed: {os.strerror(err2)} (errno={err2})")
        print("NOTE: BPF_PROG_ATTACH to TC may not be supported in this container/kernel")
        print(f"BPF program successfully loaded (fd={fn.fd}) — kernel verifier accepted it")
    else:
        print("Old-format TC attach: SUCCESS")
else:
    print("TC attach via syscall: SUCCESS")

# Verify with tc filter
print("\nChecking TC filters...")
os.system("tc filter show dev veth_tc2 2>&1 | head -20")

print("Done.")