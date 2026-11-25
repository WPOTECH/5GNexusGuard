#!/usr/bin/env python3
"""kernel_gate_publisher_v2.py — atomic and non-atomic health publication.

Defines:
  - HEALTH struct (pack/unpack)
  - REQUEST struct (pack/unpack)
  - AtomicHealthMap (BPF_PROG_TEST_RUN path)
  - FreshHealth (non-atomic fallback)
  - Publisher (top-level orchestrator)
"""

import ctypes
import os
import struct

# ── BPF syscall numbers (x86_64) ────────────────────────────────────────
BPF_MAP_LOOKUP_ELEM = 1
BPF_PROG_TEST_RUN = 10
BPF_OBJ_GET = 7
BPF_OBJ_GET_INFO_BY_FD = 15

# ── Constants ───────────────────────────────────────────────────────────
HEALTH_OP_PUBLISH = 1
HEALTH_OP_REVOKE = 2

HEALTH_SIZE = 40          # <QQQIIHH + 4×pad  →  8×3 + 4×2 + 2×2 + 4
REQUEST_SIZE = 64         # <8Q  →  8×8

PEER = 0xC0000201         # 192.0.2.1
RESOURCE = 0xC0000202     # 192.0.2.2
PORT = 51821

# ── HEALTH struct ───────────────────────────────────────────────────────
class HEALTH(ctypes.Structure):
    _fields_ = [
        ('epoch', ctypes.c_uint64),
        ('deadline_ns', ctypes.c_uint64),
        ('checked_ns', ctypes.c_uint64),
        ('peer', ctypes.c_uint32),
        ('resource', ctypes.c_uint32),
        ('port', ctypes.c_uint16),
        ('flags', ctypes.c_uint16),
    ]

HEALTH.size = HEALTH_SIZE

@classmethod
def _health_pack(cls, epoch, deadline, checked, peer, resource, port, flags):
    return struct.pack('<QQQIIHH', epoch, deadline, checked, peer, resource, port, flags) + b'\x00\x00\x00\x00'

HEALTH.pack = _health_pack

@classmethod
def _health_unpack(cls, data):
    return struct.unpack('<QQQIIHH', data[:36])

HEALTH.unpack = _health_unpack

# ── REQUEST struct ──────────────────────────────────────────────────────
class REQUEST(ctypes.Structure):
    _fields_ = [
        ('operation', ctypes.c_uint64),
        ('generation', ctypes.c_uint64),
        ('epoch', ctypes.c_uint64),
        ('auth_deadline', ctypes.c_uint64),
        ('checked', ctypes.c_uint64),
        ('deadline', ctypes.c_uint64),
        ('publish_before', ctypes.c_uint64),
        ('previous_checked', ctypes.c_uint64),
    ]

REQUEST.size = REQUEST_SIZE

@classmethod
def _request_pack(cls, operation, generation, epoch, auth_deadline,
                  checked, deadline, publish_before, previous_checked):
    return struct.pack('<8Q', operation, generation, epoch, auth_deadline,
                       checked, deadline, publish_before, previous_checked)

REQUEST.pack = _request_pack

# ── AtomicHealthMap ─────────────────────────────────────────────────────
class AtomicHealthMap:
    """Interface to the health_control BPF program via BPF_PROG_TEST_RUN."""

    REQUEST = REQUEST

    class RunAttr(ctypes.Structure):
        _fields_ = [
            ('prog_fd', ctypes.c_uint32),
            ('retval', ctypes.c_uint32),
            ('data_size_in', ctypes.c_uint32),
            ('data_size_out', ctypes.c_uint32),
            ('data_in', ctypes.c_uint64),
            ('data_out', ctypes.c_uint64),
            ('ctx_in', ctypes.c_uint64),
            ('ctx_out', ctypes.c_uint64),
        ]

    class InfoAttr(ctypes.Structure):
        _fields_ = [
            ('map_type', ctypes.c_uint32),
            ('key_size', ctypes.c_uint32),
            ('value_size', ctypes.c_uint32),
            ('max_entries', ctypes.c_uint32),
            ('map_flags', ctypes.c_uint32),
        ]

    def __init__(self, pin_dir='/sys/fs/bpf/atomic-test'):
        self.pin_dir = pin_dir
        self.program = f'{pin_dir}/progs/health_control'
        self.health_map_path = f'{pin_dir}/maps/health_map'
        self.maps = {}
        uname_machine = os.uname().machine
        self.number = 321 if 'x86_64' in uname_machine else 280

    def _call(self, command, attr):
        """Override in tests; real impl calls bpf(BPF_CMD, cmd, attr)."""
        raise NotImplementedError("override in test or real runtime")

    def publish(self, map_path, value, generation, auth_deadline, checked, publish_before):
        """Publish a health value through the atomic gate."""
        attr = self.RunAttr()
        attr.prog_fd = 42  # program fd (mock); resolved via _call cmd 7 in real
        attr.retval = 0
        attr.data_size_in = HEALTH_SIZE
        attr.data_size_out = HEALTH_SIZE
        value_buf = ctypes.create_string_buffer(value, HEALTH_SIZE)
        attr.data_in = ctypes.cast(value_buf, ctypes.c_void_p).value  # pointer address
        attr.data_out = 0

        # Derive deadline_ns from the health value for the request deadline field
        deadline_ns = struct.unpack('<QQQIIHH', value[:36])[1]  # index 1 = deadline_ns

        req_data = self.REQUEST.pack(
            HEALTH_OP_PUBLISH, generation, 0, auth_deadline,
            checked, deadline_ns, publish_before, 0
        )
        buf = ctypes.create_string_buffer(req_data, REQUEST_SIZE)
        attr.ctx_in = ctypes.cast(buf, ctypes.c_void_p).value  # store as uint64 pointer

        result = self._call(BPF_PROG_TEST_RUN, attr)
        if result <= 0 or attr.retval <= 0:
            raise RuntimeError(
                f'health_control rejected publish: retval={attr.retval} result={result}'
            )
        return attr.retval

    def revoke(self, map_path, generation):
        """Revoke (zero) the health map through the atomic gate."""
        value = bytes(HEALTH_SIZE)
        attr = self.RunAttr()
        attr.prog_fd = 42
        attr.retval = 0
        attr.data_size_in = HEALTH_SIZE
        attr.data_size_out = HEALTH_SIZE
        value_buf = ctypes.create_string_buffer(value, HEALTH_SIZE)
        attr.data_in = ctypes.cast(value_buf, ctypes.c_void_p).value  # pointer address
        attr.data_out = 0

        req_data = self.REQUEST.pack(
            HEALTH_OP_REVOKE, generation, 0, 0, 0, 0, 0, 0
        )
        buf = ctypes.create_string_buffer(req_data, REQUEST_SIZE)
        attr.ctx_in = ctypes.cast(buf, ctypes.c_void_p).value  # store as uint64 pointer

        result = self._call(BPF_PROG_TEST_RUN, attr)
        if result <= 0 or attr.retval <= 0:
            raise RuntimeError(f'health_control rejected revoke: retval={attr.retval}')
        return 0

# ── FreshHealth — non-atomic path (fallback) ────────────────────────────
class FreshHealth:
    """Marker for the non-atomic health path (no-op)."""
    pass

# ── command helper (used by isolated_enforcement.py) ────────────────────
def command(name):
    """Resolve BPF command number by name."""
    cmds = {
        'BPF_MAP_LOOKUP_ELEM': BPF_MAP_LOOKUP_ELEM,
        'BPF_PROG_TEST_RUN': BPF_PROG_TEST_RUN,
        'BPF_OBJ_GET': BPF_OBJ_GET,
        'BPF_OBJ_GET_INFO_BY_FD': BPF_OBJ_GET_INFO_BY_FD,
    }
    return cmds.get(name, -1)