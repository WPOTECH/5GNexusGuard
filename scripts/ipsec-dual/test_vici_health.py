"""Test fixtures and helpers for vici_health.py.

Provides a VICI wire-format builder (named, value, section, fields) and
a synthetic BODY that mimics a strongSwan LIST_SAS response for the hybrid
(5GNexus) tunnel scenario.
"""
import socket
import threading
from pathlib import Path


# ── helpers ──────────────────────────────────────────────────────────
def _raw_len(val):
    """Return the raw bytes for a tagged-string value."""
    return val if isinstance(val, bytes) else val.encode()


def named(key, val):
    """Return a VICI-tagged string (key + value) for the wire format."""
    kb = _raw_len(key) if isinstance(key, bytes) else key.encode()
    vb = _raw_len(val)
    return struct.pack('!I', len(kb)) + kb + struct.pack('!I', len(vb)) + vb


def value(val):
    """Return just the value part of a tagged-string entry."""
    vb = _raw_len(val)
    return struct.pack('!I', len(vb)) + vb


def section(key, *children):
    """Return a section start marker, children, and section end marker."""
    kb = _raw_len(key) if isinstance(key, bytes) else key.encode()
    parts = struct.pack('!I', len(kb)) + kb + b'\x04'  # start marker
    for c in children:
        parts += c
    parts += b'\x05'  # end marker
    return parts


def fields(*pairs):
    """Return a flat list of key-value tagged-strings."""
    out = b''
    for key, val in pairs:
        kb = _raw_len(key) if isinstance(key, bytes) else key.encode()
        vb = _raw_len(val)
        out += struct.pack('!I', len(kb)) + kb + struct.pack('!I', len(vb)) + vb
    return out


# ── decode ───────────────────────────────────────────────────────────
import struct


def decode(raw_data):
    """Decode a VICI LIST_SAS response body into a nested dict.

    Expects raw VICI wire format: sequence of key-value pairs where
    b'\\x04' starts a new section and b'\\x05' ends it.
    """
    if not isinstance(raw_data, (bytes, bytearray)):
        return {}

    result = {}
    sections = [result]

    i = 0
    while i < len(raw_data):
        if i + 4 > len(raw_data):
            break
        key_len = struct.unpack('!I', raw_data[i:i + 4])[0]
        i += 4

        if i + key_len > len(raw_data):
            break
        key = raw_data[i:i + key_len]
        i += key_len

        if i + 4 > len(raw_data):
            break
        val_len = struct.unpack('!I', raw_data[i:i + 4])[0]
        i += 4

        if i + val_len > len(raw_data):
            break
        value_bytes = raw_data[i:i + val_len]
        i += val_len

        current = sections[-1]
        if val_len == 1 and value_bytes == b'\x05':
            if len(sections) > 1:
                sections.pop()
        elif val_len == 1 and value_bytes == b'\x04':
            new_section = {}
            current[key] = new_section
            sections.append(new_section)
        else:
            current[key] = value_bytes

    return result


# ── synthetic BODY ──────────────────────────────────────────────────
# Mimics a strongSwan LIST_SAS response for the hybrid 5GNexus tunnel.
# Format: VICI wire-protocol with nested tagged strings.

_LOCAL_TS = '10.79.0.1/32'
_REMOTE_TS = '10.79.0.2/32'

_HOSTS = ('10.77.0.1', '10.78.0.2')

BODY = (
    # hybrid section start
    section('hybrid',
        # IKE version and state
        fields(
            ('version', '2'),
            ('state', 'ESTABLISHED'),
            ('initiator-spi', 'deadbeefcafebabe'),
            ('responder-spi', 'feedfacebabedead'),
            ('uniqueid', '42'),
        ),
        # hybrid section end
    )
)

LOCAL_TS = _LOCAL_TS
REMOTE_TS = _REMOTE_TS
HOSTS = _HOSTS


def exchange(conn, messages):
    """Drive a single VICI exchange round on *conn*.

    *conn* is a connected socket (client side).  *messages* is an ordered
    list of ``(request, *responses)`` pairs.
    """
    for request, *responses in messages:
        conn.sendall(request)
        for resp in responses:
            data = conn.recv(len(resp))
            if len(data) != len(resp):
                raise AssertionError(f'expected {len(resp)} bytes, got {len(data)}')


def _make_body():
    """Build a proper VICI wire-format BODY for testing."""
    parts = []

    # hybrid section header
    parts.append(struct.pack('!I', 6) + b'hybrid' + b'\x04')  # hybrid section start

    hybrid_fields = (
        (b'version', b'2'),
        (b'state', b'ESTABLISHED'),
        (b'initiator-spi', b'deadbeefcafebabe'),
        (b'responder-spi', b'feedfacebabedead'),
        (b'uniqueid', b'42'),
        (b'child-sas', None),  # will add nested section
    )
    for k, v in hybrid_fields:
        if v is None:
            # child-sas section start
            parts.append(struct.pack('!I', 9) + b'child-sas' + b'\x04')
            # inner-transport child section
            parts.append(section('inner-transport',
                fields(
                    (b'name', b'inner-transport'),
                    (b'state', b'INSTALLED'),
                    (b'reqid', b'42'),
                    (b'mode', b'TUNNEL'),
                    (b'protocol', b'ESP'),
                    (b'spi-in', b'cafe0001'),
                    (b'spi-out', b'cafe0002'),
                    (b'uniqueid', b'99'),
                    (b'local-ts', LOCAL_TS.encode()),
                    (b'remote-ts', REMOTE_TS.encode()),
                ),
            ))
            # child-sas section end
            parts.append(b'\x05')
        else:
            parts.append(struct.pack('!I', len(k)) + k + struct.pack('!I', len(v)) + v)

    # hybrid section end
    parts.append(b'\x05')

    return b''.join(parts)


# Build the actual BODY wire format
BODY = _make_body()


class FakeVICIServer:
    """Mock VICI server for testing HealthVici."""

    def __init__(self):
        self.responses = []

    def add_response(self, data):
        self.responses.append(data)

    def get_response(self):
        if self.responses:
            return self.responses.pop(0)
        return None


class FakeVICIStream:
    """Stream wrapper for FakeVICIServer."""

    def __init__(self, server):
        self.server = server
        self.buffer = b''
        self.pending = []

    def push_body(self, body):
        self.buffer += body

    def push_section(self, key, *values):
        self.buffer += section(key, *values)

    def next_event(self):
        if self.pending:
            return self.pending.pop(0)
        return None