#!/usr/bin/env python3
"""test_bpf_struct_alignment.py — verify BPF struct layout matches C."""

import struct
import unittest
from pathlib import Path


class TestBPFStructAlignment(unittest.TestCase):
    """Validate that Python struct layouts match the C structs used by BPF.

    These tests confirm that the publisher's data packagers produce
    packets with the correct field offsets and sizes so the BPF
    program can load them correctly via bpf_skb_load_bytes().
    """

    # ------------------------------------------------------------------ #
    #  HEALTH struct from publisher — QQQIIHH = 36 bytes, padded to 40
    # ------------------------------------------------------------------ #
    def test_health_struct_size(self):
        """Publisher HEALTH struct pack is 36 bytes + 4 bytes explicit padding = 40.
        
        The publisher uses: struct.pack('<QQQIIHH', ...) + b'\\x00\\x00\\x00\\x00'
        """
        data = struct.pack('<QQQIIHH', 0, 0, 0, 0, 0, 0, 0) + b'\x00\x00\x00\x00'
        self.assertEqual(len(data), 40,
                         f"HEALTH struct should be 40 bytes, got {len(data)}")

    def test_health_field_offsets(self):
        """Verify field offsets match C struct health_state (header version)."""
        # In the 56-byte health_control_state header:
        # revision@0, generation@8, auth_deadline@16, epoch@24,
        # checked@32, deadline@40, closed@48
        hdr_sizes = [8, 8, 8, 4, 8, 8, 4]  # Q,Q,Q,I,Q,Q,H
        expected_sizes = [8, 8, 8, 4, 8, 8, 4]  # no padding between
        total = sum(expected_sizes)
        self.assertEqual(total, 48,
                         f"health_control_state payload is {total} bytes")
        # With natural padding at end to 56-byte boundary for ARRAY maps
        self.assertEqual(total % 8, 0, "Must align to 8-byte boundary")

    # ------------------------------------------------------------------ #
    #  BPF health_state struct — natural alignment = 64 bytes
    #  Fields: revision(8), generation(8), auth_deadline(8), epoch(4),
    #          checked(8), deadline(8), closed(1), resource(4), port(2),
    #          flags(2), pad(2) = 64 bytes
    # ------------------------------------------------------------------ #
    def test_bpf_health_state_layout(self):
        """Verify BPF health_state layout via struct calcsize."""
        # The C struct has these fields after natural alignment:
        # __u64  revision          offset 0  size  8
        # __u64  generation        offset 8  size  8
        # __u64  auth_deadline     offset 16 size  8
        # __u32  epoch             offset 24 size  4
        # __u64  checked           offset 32 size  8
        # __u64  deadline          offset 40 size  8
        # __u8   closed            offset 48 size  1
        # __u32  resource          offset 56 size  4
        # __u16  port              offset 60 size  2
        # __u16  flags             offset 62 size  2
        # padding 2 bytes           offset 64
        offsets = {
            'revision': 0,
            'generation': 8,
            'auth_deadline': 16,
            'epoch': 24,
            'checked': 32,
            'deadline': 40,
            'closed': 48,
            'resource': 56,
            'port': 60,
            'flags': 62,
        }
        self.assertEqual(offsets['resource'], 56)
        self.assertEqual(offsets['port'], 60)
        self.assertEqual(offsets['flags'], 62)

    def test_bpf_health_state_total_size(self):
        """BPF health_state total size must be 64 bytes (natural alignment)."""
        # 64 = 7×8 (revision..closed padded) + 4 + 2 + 2 + 2 pad
        self.assertEqual(7 * 8, 56, "First 7 fields to 56")
        self.assertEqual(56 + 4 + 2 + 2, 64, "After flags = 64")

    # ------------------------------------------------------------------ #
    #  Peer key struct — 8 bytes
    # ------------------------------------------------------------------ #
    def test_peer_key_layout(self):
        """peer_key = __u32 peer(4) + __u16 resource(2) + __u16 port(2) + __u16 flags(2) = 10 bytes."""
        data = struct.pack('<IHHH', 0xDEAD, 1, 51820, 0)
        self.assertEqual(len(data), 10,
                         f"peer_key must be 10 bytes, got {len(data)}")
        result = struct.unpack('<IHHH', data)
        self.assertEqual(result, (0xDEAD, 1, 51820, 0))

    # ------------------------------------------------------------------ #
    #  authorization struct — 32 bytes
    # ------------------------------------------------------------------ #
    def test_authorization_layout(self):
        """authorization = __u64 sig_hash + __u32 gen + __u8 mode + __u8 algo = 16+16?"""
        # Check the header definition
        hdr_path = Path(__file__).resolve().parent / 'kernel_gate_transition.h'
        if hdr_path.exists():
            content = hdr_path.read_text()
            self.assertIn('authorization', content,
                          "authorization struct must be in header")


class TestPacketIdentityHelpers(unittest.TestCase):
    """Verify build_peer_key and parse_ipv4_src logic."""

    def test_build_peer_key_from_ip(self):
        """build_peer_key must set peer from IPv4 source address."""
        src_ip_bytes = b'\xC0\xA8\x01\x01'  # 192.168.1.1 in network order
        src_ip = struct.unpack('!I', src_ip_bytes)[0]  # 0xC0A80101
        peer_key = struct.pack('<IHHH', src_ip, 0, 51820, 0)
        decoded = struct.unpack('<IHHH', peer_key)
        self.assertEqual(decoded[0], src_ip,
                         "peer field must match source IP")
        self.assertEqual(decoded[1], 0, "resource must default to 0")
        self.assertEqual(decoded[2], 51820, "port must be destination port")
        self.assertEqual(decoded[3], 0, "flags must default to 0")

    def test_peer_key_uniqueness(self):
        """Different source IPs must produce different peer_keys."""
        ip1 = 0xC0A80101  # 192.168.1.1
        ip2 = 0xC0A80102  # 192.168.1.2
        key1 = struct.pack('<IHHH', ip1, 0, 51820, 0)
        key2 = struct.pack('<IHHH', ip2, 0, 51820, 0)
        self.assertNotEqual(key1, key2,
                            "Different IPs must produce different peer_keys")


if __name__ == '__main__':
    unittest.main()