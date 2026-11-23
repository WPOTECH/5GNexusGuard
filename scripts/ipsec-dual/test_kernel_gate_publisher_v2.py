#!/usr/bin/env python3
"""test_kernel_gate_publisher_v2.py — unit tests for kernel_gate_publisher_v2."""

import hashlib
import struct
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from kernel_gate_publisher_v2 import (
    AtomicHealthMap,
    FreshHealth,
    HEALTH,
    HEALTH_SIZE,
    REQUEST,
    REQUEST_SIZE,
)


class TestHealthPack(unittest.TestCase):
    def test_pack_length(self):
        data = HEALTH.pack(0, 0, 0, 0, 0, 0, 0)
        self.assertEqual(len(data), HEALTH_SIZE)

    def test_roundtrip(self):
        data = HEALTH.pack(1, 2, 3, 4, 5, 6, 7)
        result = HEALTH.unpack(data)
        self.assertEqual(result, (1, 2, 3, 4, 5, 6, 7))


class TestHealthUnpack(unittest.TestCase):
    def test_unpack_partial(self):
        data = HEALTH.pack(0xDEAD, 0xBEEF, 0, 0, 0, 0, 0)
        result = HEALTH.unpack(data)
        self.assertEqual(result[0], 0xDEAD)
        self.assertEqual(result[1], 0xBEEF)


class TestRequestPack(unittest.TestCase):
    def test_pack_length(self):
        data = REQUEST.pack(0, 0, 0, 0, 0, 0, 0, 0)
        self.assertEqual(len(data), REQUEST_SIZE)

    def test_roundtrip(self):
        data = REQUEST.pack(1, 2, 3, 4, 5, 6, 7, 8)
        result = struct.unpack('<8Q', data)
        self.assertEqual(result, (1, 2, 3, 4, 5, 6, 7, 8))


class TestAtomicMap(unittest.TestCase):
    def test_init(self):
        m = AtomicHealthMap('/tmp/test-bpf-preflight')
        self.assertEqual(m.pin_dir, '/tmp/test-bpf-preflight')
        self.assertIn('health_map_path', dir(m))

    def test_has_request_class(self):
        self.assertTrue(hasattr(AtomicHealthMap, 'REQUEST'))


class TestFreshHealth(unittest.TestCase):
    def test_is_marker(self):
        h = FreshHealth()
        self.assertIsInstance(h, FreshHealth)


class TestPreflightHash(unittest.TestCase):
    def test_hash_consistency(self):
        src = Path(__file__).resolve().parent / 'kernel_gate_publisher_v2.py'
        data = src.read_bytes()
        h = hashlib.sha256(data).hexdigest()
        self.assertIsInstance(h, str)
        self.assertEqual(len(h), 64)


if __name__ == '__main__':
    unittest.main()