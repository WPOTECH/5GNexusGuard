"""strongSwan VICI protocol helpers for IPsec tunnel health validation.

Encodes and decodes strongSwan's VICI protocol (RFC 8220) to validate that
IPsec tunnels are healthy (ESTABLISHED, INSTALLED state, correct selectors).
"""
import socket
import struct
import threading
import time
import hashlib
import logging

logger = logging.getLogger(__name__)

# VICI constants
LIST_EVENT = b'list-sas'
CHANGE_EVENTS = (b'child-rekey',)

# Boottime reference (seconds since boot as float)
def boottime():
    """Return the system boot time as a monotonic timestamp."""
    try:
        return time.monotonic_ns()
    except AttributeError:
        return time.monotonic() * 1_000_000_000


class HealthVici:
    """strongSwan VICI client for tunnel health snapshots."""

    def __init__(self, vici_dir, pid, timeout=5.0):
        self.vici_dir = vici_dir
        self.pid = pid
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._lock = threading.Lock()
        self._gen = 0
        self._closed = False
        self._peer_verified = False
        self.pending = 0
        self._connect()

    def _connect(self):
        path = self.vici_dir / 'vici'
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(self.timeout)
        self._sock.connect(str(path))
        self._peer_verified = False

    def close(self):
        if self._sock and not self._closed:
            try:
                self._sock.close()
            except OSError:
                pass
            self._closed = True
            self._sock = None

    def _check_peer(self):
        if self._peer_verified or self._sock is None:
            return
        try:
            data = self._read_vici_message_raw()
            if data is None:
                raise RuntimeError('no peer announcement')
            if len(data) < 6:
                raise RuntimeError(f'invalid peer announcement: {len(data)} bytes')
            msg_type = struct.unpack('!I', data[:4])[0]
            if msg_type != 0:
                raise RuntimeError(f'unexpected peer msg type: {msg_type}')
            self._peer_verified = True
        except (OSError, RuntimeError) as exc:
            logger.warning('peer verification failed: %s', exc)
            self._peer_verified = False
            raise

    def _read_vici_message_raw(self):
        """Read raw bytes from socket for peer verification."""
        if self._sock is None:
            return None
        try:
            header = self._sock.recv(4)
            if len(header) < 4:
                return None
            return header
        except (OSError, struct.error):
            return None

    def _send_vici_message(self, name, parts):
        """Send a VICI command message."""
        if self._sock is None:
            return
        msg = self._build_message(name, parts)
        self._sock.sendall(msg)

    def _build_message(self, name, parts=None):
        """Build a VICI command message."""
        name_bytes = name.encode() if isinstance(name, str) else name
        if parts is None:
            parts = []
        part_list = [name_bytes] + list(parts)
        total_len = 4  # msg_id (reserved = 0)
        for p in part_list:
            total_len += 4 + len(p)  # key_len + key_value
        header = struct.pack('!I', 0)  # msg_id = 0 for command
        return header + b''.join(struct.pack('!I', len(p)) + p for p in part_list)

    def _read_vici_message(self):
        """Read a VICI message from the socket."""
        if self._sock is None:
            return None
        try:
            header = self._sock.recv(4)
            if len(header) < 4:
                return None
            msg_id = struct.unpack('!I', header)[0]
            parts = []
            while True:
                try:
                    key_len = self._sock.recv(4)
                    if len(key_len) < 4:
                        break
                    klen = struct.unpack('!I', key_len)[0]
                    key_val = self._sock.recv(klen)
                    if len(key_val) < klen:
                        break
                    parts.append(key_val)
                except (OSError, struct.error):
                    break
            return (msg_id, parts)
        except (OSError, struct.error):
            return None

    def _parse_vici_response(self, raw):
        """Parse a VICI response into a nested dict."""
        if raw is None:
            return {}
        msg_id, parts = raw
        return _build_vici_dict(parts)

    def snapshot(self, deadline_ns=None):
        """Take a stable snapshot of IPsec tunnel state.

        Returns (generation, row_dict) or None if unstable/unavailable.
        """
        with self._lock:
            return self._snapshot_internal(deadline_ns)

    def _snapshot_internal(self, deadline_ns=None):
        if self._sock is None:
            return None
        inner = None
        try:
            self._check_peer()
            self._send_vici_message(LIST_EVENT)
            raw = self._read_vici_message()
            if raw is None:
                return None
            msg_id, parts = raw
            row = _build_vici_dict(parts)
            self._gen += 1
            inner = (self._gen, row)
        except Exception as exc:
            logger.warning('snapshot failed: %s', exc)
            return None
        finally:
            sock = self._sock
            self._sock = None
            try:
                sock.close()
            except OSError:
                pass
        return inner


def _build_vici_dict(parts):
    """Build nested VICI dict from a flat list of key-value bytes."""
    result = {}
    current = result
    depth = 0
    for i in range(0, len(parts), 2):
        if i + 1 >= len(parts):
            break
        key = parts[i]
        val = parts[i + 1]
        if val == b'\x05':  # Section end marker
            if depth > 0:
                depth -= 1
                current = list(result.values())[depth] if depth > 0 else result
            continue
        if val == b'\x04':  # Section start marker
            depth += 1
            new_section = {}
            current[key] = new_section
            current = new_section
            continue
        current[key] = val
    return result


def _parse_vici_dict(data):
    """Parse VICI nested dict from a nested structure."""
    return data


def decode(raw_data):
    """Decode a VICI LIST_SAS response body into a nested dict.

    Expects raw VICI wire format: sequence of key-value pairs where
    b'\\x04' starts a new section and b'\\x05' ends it.
    """
    if not isinstance(raw_data, (bytes, bytearray)):
        return {}

    result = {}
    sections = [result]  # Stack of current sections

    i = 0
    while i < len(raw_data):
        # Parse key length
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
        value = raw_data[i:i + val_len]
        i += val_len

        current = sections[-1]
        if val_len == 1 and value == b'\x05':
            # Section end — pop from stack
            if len(sections) > 1:
                sections.pop()
        elif val_len == 1 and value == b'\x04':
            # Section start — push new dict
            new_section = {}
            current[key] = new_section
            sections.append(new_section)
        else:
            current[key] = value

    return result


def association(snapshot, local_selector, remote_selector, local_host, remote_host, diagnostic=None):
    """Return the matching IKE/ESP identifiers and this daemon's generation.

    Only b'INSTALLED' CHILD_SAs count as active, authorised evidence.
    b'REKEYED' is retiring and never accepted as the sole positive proof
    that the tunnel is healthy (strongSwan CHILD_REKEYED semantics).
    Unknown states are rejected by exact byte match -- no stripping or
    normalisation.
    """
    import re

    if snapshot is None:
        if diagnostic:
            diagnostic('vici_no_stable_snapshot', None)
        return None
    generation, row = snapshot
    ike = row.get(b'hybrid')
    if not isinstance(ike, dict) or len(row) != 1:
        return None
    if (ike.get(b'version') != b'2' or ike.get(b'state') != b'ESTABLISHED' or
            ike.get(b'local-host') != local_host.encode() or ike.get(b'remote-host') != remote_host.encode()):
        return None
    children = ike.get(b'child-sas')
    if not isinstance(children, dict):
        return None
    if diagnostic and isinstance(children, dict):
        def public(section, keys):
            return {key.decode(): section[key].decode('ascii', 'replace')[:64]
                    for key in keys if isinstance(section.get(key), bytes)}
        diagnostic('vici_associations', dict(
            generation=generation,
            ike=public(ike, (b'uniqueid', b'state', b'initiator-spi', b'responder-spi')),
            children=[public(child, (b'name', b'uniqueid', b'state', b'reqid', b'spi-in', b'spi-out'))
                      for child in list(children.values())[:8] if isinstance(child, dict)]))

    # Classify CHILD_SAs by exact state: INSTALLED (active) vs REKEYED
    # (retiring) vs anything else (rejected).  No whitespace stripping,
    # no normalisation of unknown states.
    active_children = []
    retiring_children = []
    for _name_key, child in children.items():
        if not isinstance(child, dict):
            continue
        child_state = child.get(b'state')
        if child_state == b'INSTALLED':
            active_children.append(child)
        elif child_state == b'REKEYED':
            retiring_children.append(child)

    if diagnostic:
        diagnostic('vici_child_classification', dict(
            active_count=len(active_children),
            retiring_count=len(retiring_children),
        ))

    # Retiring only is not positive health evidence.
    if not active_children:
        if diagnostic:
            diagnostic('vici_no_active_child', dict(
                active_count=0,
                retiring_count=len(retiring_children),
            ))
        return None

    # Pick the latest active child by uniqueid.
    def _uid_int(c):
        uid = c.get(b'uniqueid', b'0')
        try:
            return int(uid)
        except (ValueError, TypeError):
            return 0
    child = max(active_children, key=_uid_int)

    if any(child.get(key) != expected for key, expected in (
            (b'name', b'inner-transport'), (b'reqid', b'42'),
            (b'mode', b'TUNNEL'), (b'protocol', b'ESP'))):
        return None

    for key, selector in ((b'local-ts', local_selector), (b'remote-ts', remote_selector)):
        child_val = child.get(key)
        expected = [selector.encode(), selector.replace('[17/', '[udp/').encode()]
        if child_val not in expected:
            return None

    if retiring_children:
        uids = [int(c.get(b'uniqueid', b'0')) for c in retiring_children]
        if diagnostic:
            diagnostic('vici_retiring_rekeyed', dict(uniqueids=uids))

    ike_spis = tuple(ike.get(k) for k in (b'initiator-spi', b'responder-spi'))
    esp_spis = tuple(child.get(k) for k in (b'spi-in', b'spi-out'))
    for values, pattern in ((ike_spis, rb'[0-9a-f]{16}'),
                            (esp_spis, rb'[0-9a-f]{8}')):
        if not all(isinstance(v, bytes) and re.fullmatch(pattern, v) and int(v, 16)
                   for v in values):
            return None

    uniqueids = (ike.get(b'uniqueid'), child.get(b'uniqueid'))
    if not all(isinstance(v, bytes) and v.isdigit() for v in uniqueids):
        return None

    return ike_spis, int(esp_spis[0], 16), int(esp_spis[1], 16), \
        (generation, uniqueids)