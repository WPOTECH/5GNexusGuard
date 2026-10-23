"""Focused, isolated P0 probes. No rule, route, grant, or map writes.

AF_PACKET injections intentionally exercise ingress enforcement even where an
endpoint's output firewall would reject ordinary out-of-scope socket traffic.
All packets remain inside the disposable four-namespace topology.
"""
import json
from pathlib import Path
import socket
import struct
import sys
import time

from continuous_evidence import EvidenceError, TrafficStream
from grant_boundary_diagnostic import packet_deltas, sample
from kernel_gate_publisher_v2 import command
from native import NAMES

# Fixed identities make absence/presence checks bind to the injected packets.
PROBES = {
    'wrong_port': ('10.79.0.1', '10.80.0.2', 43001, 8081, 0x50300001),
    'wrong_resource': ('10.80.0.3', '10.79.0.1', 8080, 43002, 0x50300002),
    'underlay': ('10.79.0.1', '10.80.0.2', 43003, 8080, 0x50300003),
}


def checksum(data):
    data += bytes(len(data) % 2)
    value = sum(struct.unpack('!%dH' % (len(data)//2), data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    return (~value) & 0xffff


def syn_packet(identity):
    src, dst, sport, dport, seq = identity
    src, dst = socket.inet_aton(src), socket.inet_aton(dst)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, 2, 8192, 0, 0)
    tcp = tcp[:16] + struct.pack('!H', checksum(src+dst+struct.pack('!BBH', 0, 6, 20)+tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 40, 0x5030, 0, 64, 6, 0, src, dst)
    return ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:] + tcp


def mac(role, iface):
    rows = json.loads(command(['ip', 'netns', 'exec', NAMES[role],
                               'ip', '-j', 'link', 'show', 'dev', iface]))
    return bytes.fromhex(rows[0]['address'].replace(':', ''))


def inject(role, iface, identity, destination=None):
    packet = syn_packet(identity)
    kind = 'SOCK_DGRAM'
    if destination is not None:
        packet = destination + mac(role, iface) + b'\x08\x00' + packet
        kind = 'SOCK_RAW'
    script = (f'import socket; s=socket.socket(socket.AF_PACKET,socket.{kind},socket.htons(0x0800)); '
              's.bind(("' + iface + '",0)); p=bytes.fromhex("' + packet.hex() + '"); '
              'assert s.send(p)==len(p); s.close()')
    command(['ip', 'netns', 'exec', NAMES[role], sys.executable, '-c', script])


def assert_live(snapshot, epoch):
    auth = snapshot['maps']['authorization']['value']
    health = snapshot['maps']['health']['value']
    if (snapshot['controller_status'] != 'ATTESTED' or snapshot['admission_state'] != 'AUTHORIZED'
            or auth['epoch'] != epoch or health['epoch'] != epoch or not epoch
            or not snapshot['boottime_ns'] < health['deadline_ns'] <= auth['deadline_ns']
            or snapshot['boottime_ns'] < health['checked_ns']
            or not 0 < health['deadline_ns'] - health['checked_ns'] <= 500_000_000
            or any((entry['peer'], entry['resource'], entry['port']) !=
                   ('10.79.0.1', '10.80.0.2', 8080) for entry in (auth, health))
            or not all(row['attached'] for row in snapshot['tc'].values())):
        raise EvidenceError('P0: authorization, heartbeat, or TC hook lost during negative probes')


def assert_pregrant(report):
    snapshots = dict(report['snapshots'])
    pre = snapshots['pre']
    attempts = [row for row in report['attempts'] if row['verdict_ns'] < report['grant_event_ns']]
    if (not attempts or any(row['delivered'] for row in attempts) or
            any(entry['value']['epoch'] or entry['value']['deadline_ns']
                for entry in pre['maps'].values()) or
            snapshots['post-grant']['verdicts']['wg_ingress']['auth_missing'] <=
            pre['verdicts']['wg_ingress']['auth_missing']):
        raise EvidenceError('P0: pre-grant zero maps and BPF denial not demonstrated')


def assert_negative_counts(before, after, rows, window=None):
    epoch = before['maps']['authorization']['value']['epoch']
    assert_live(before, epoch)
    assert_live(after, epoch)
    if before['maps']['authorization'] != after['maps']['authorization']:
        raise EvidenceError('P0: original authorization changed during negative probes')
    if (before['nft_hooks'] != after['nft_hooks'] or
            any(before['tc'][iface]['program_id'] != after['tc'][iface]['program_id']
                for iface in ('wg-inner', 'resource'))):
        raise EvidenceError('P0: nft hooks or TC programs changed during negative probes')
    delta = packet_deltas(before, after)
    if any(delta['tc'][direction]['scope_denied'] < 1
           for direction in ('wg_ingress', 'resource_ingress')):
        raise EvidenceError('P0: out-of-scope TC denial counters absent')
    drops = [r for r in delta['nft']['ipsec_dual'] if r['verdicts'] == ['drop']]
    if len(drops) != 1 or drops[0]['packet_deltas'][0] < 1:
        raise EvidenceError('P0: direct-underlay nft denial counter absent')
    if not rows or not all(row['delivered'] for row in rows):
        raise EvidenceError('P0: authorized TCP failed during negative probes')
    if window is not None and not (
            any(row['verdict_ns'] <= window[0] for row in rows) and
            any(row['attempt_ns'] >= window[1] for row in rows)):
        raise EvidenceError('P0: authorized TCP must succeed before and after negative probes')
    return delta


def active_grant_probe(root, fixture, ticker, publisher, inner):
    root = Path(root)
    directory = root/'active-grant'
    directory.mkdir(mode=0o700)
    # Keep raw expressions local, separate from the sanitized diagnostic summary.
    for table in ('ipsec_dual', 'kernel_gate_v2_test'):
        (directory/(table+'.nft.local.json')).write_text(inner([
            'nft', '-j', 'list', 'chain', 'inet', table, 'forward']))
    stream = TrafficStream(namespace=NAMES['e'])
    rows = []
    try:
        stream.start(directory)
        stream.ready(delivered=True)
        with ticker.lock:
            ticker.check()
            before = sample(fixture, publisher, inner)
        assert_live(before, before['maps']['authorization']['value']['epoch'])
        probe_start = time.monotonic_ns()
        # Same encrypted path, wrong port: WG ingress must drop.
        inject('e', 'wg-inner', PROBES['wrong_port'])
        # Same local L2 segment, wrong resource source: resource TC must drop.
        inject('r', 'resource', PROBES['wrong_resource'], mac('i', 'resource'))
        # Deliberately unencapsulated valid TCP tuple on transit: nft must drop.
        inject('o', 'transit', PROBES['underlay'], mac('i', 'transit'))
        probe_finish = time.monotonic_ns()
        time.sleep(.06)
        with ticker.lock:
            ticker.check()
            after = sample(fixture, publisher, inner)
    finally:
        if stream.child is not None:
            rows = stream.stop()
    result = {'before': before, 'after': after, 'authorized_attempts': rows,
              'probe_window_monotonic_ns': [probe_start, probe_finish]}
    (directory/'counters.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    result['deltas'] = assert_negative_counts(before, after, rows, (probe_start, probe_finish))
    result['status'] = 'PASS'
    return result


def frames(path):
    data = Path(path).read_bytes()
    if not 24 <= len(data) <= 10_000_000:
        raise EvidenceError('P0: invalid capture size')
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
              b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}.get(data[:4])
    if endian is None:
        raise EvidenceError('P0: unsupported capture format')
    link = struct.unpack_from(endian+'I', data, 20)[0]
    if link not in (1, 101):
        raise EvidenceError('P0: unsupported capture link')
    offset = 24
    while offset < len(data):
        if offset+16 > len(data):
            raise EvidenceError('P0: truncated capture record')
        length, wire = struct.unpack_from(endian+'II', data, offset+8)
        offset += 16
        if length > wire or offset+length > len(data):
            raise EvidenceError('P0: invalid capture length')
        frame = data[offset:offset+length]
        offset += length
        yield link, frame


def packet_id(link, frame):
    start = 14 if link == 1 else 0
    if link == 1 and (len(frame) < 14 or frame[12:14] != b'\x08\x00'):
        return None
    if len(frame) < start+40 or frame[start] >> 4 != 4 or frame[start+9] != 6:
        return None
    ihl = (frame[start] & 15)*4
    total = struct.unpack_from('!H', frame, start+2)[0]
    tcp = start+ihl
    if (ihl < 20 or total < ihl+20 or start+total > len(frame) or
            struct.unpack_from('!H', frame, start+6)[0] & 0x3fff or
            frame[tcp+13] & 0x12 != 2):
        return None
    sport, dport, seq = struct.unpack_from('!HHI', frame, tcp)
    return (socket.inet_ntoa(frame[start+12:start+16]),
            socket.inet_ntoa(frame[start+16:start+20]), sport, dport, seq)


def assert_captures(root):
    root = Path(root)
    labels = ('endpoint-wg', 'inner-wg', 'inner-resource', 'resource',
              'outer-transit', 'inner-transit')
    seen = {label: {packet_id(link, frame) for link, frame in frames(root/(label+'.pcap'))}
            for label in labels}
    expected = {
        'wrong_port': (('endpoint-wg', 'inner-wg'), ('inner-resource', 'resource')),
        'wrong_resource': (('resource', 'inner-resource'), ('inner-wg', 'endpoint-wg')),
        'underlay': (('outer-transit', 'inner-transit'), ('inner-resource', 'resource', 'inner-wg')),
    }
    result = {}
    for name, (required, forbidden) in expected.items():
        identity = PROBES[name]
        if not all(identity in seen[label] for label in required) or any(
                identity in seen[label] for label in forbidden):
            raise EvidenceError('P0: negative probe packet boundary failed: '+name)
        result[name] = {'observed': list(required), 'absent': list(forbidden)}
    arp_replies = 0
    for link, frame in frames(root/'inner-resource.pcap'):
        if link != 1 or len(frame) < 42 or frame[12:14] != b'\x08\x06':
            continue
        arp = frame[14:42]
        if (arp[:8] == b'\x00\x01\x08\x00\x06\x04\x00\x02' and
                arp[14:18] == socket.inet_aton('10.80.0.2') and
                arp[24:28] == socket.inet_aton('10.80.0.1') and
                arp[8:14] == frame[6:12] and arp[18:24] == frame[:6]):
            arp_replies += 1
    if not arp_replies:
        raise EvidenceError('P0: scoped resource ARP resolution absent')
    result['scoped_arp_replies'] = arp_replies
    for label in ('endpoint-public-wire-egress', 'outer-public-wire-egress'):
        esp = 0
        for link, frame in frames(root/(label+'.pcap')):
            if link != 1 or len(frame) < 14:
                raise EvidenceError('P0: unexpected public capture link')
            if frame[12:14] == b'\x86\xdd':
                raise EvidenceError('P0: unexpected IPv6 public egress')
            if frame[12:14] != b'\x08\x00':
                continue
            if len(frame) < 34 or frame[23] != 50:
                raise EvidenceError('P0: non-ESP IPv4 public egress')
            esp += 1
        if not esp:
            raise EvidenceError('P0: missing ESP public egress')
        result[label] = {'esp_packets': esp, 'cleartext_ipv4_packets': 0}
    return result
