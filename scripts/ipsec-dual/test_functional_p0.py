"""Negative controls for P0 packet identities and acceptance requirements."""
from copy import deepcopy
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest

from continuous_evidence import EvidenceError
from functional_p0 import (PROBES, assert_captures, assert_negative_counts,
                           checksum, packet_id, syn_packet)
from grant_boundary_diagnostic import VERDICT_REASONS


def snapshot():
    auth = dict(epoch=7, deadline_ns=1000, peer='10.79.0.1', resource='10.80.0.2', port=8080)
    return {'controller_status': 'ATTESTED', 'admission_state': 'AUTHORIZED', 'boottime_ns': 100,
            'maps': {'authorization': {'value': auth},
                     'health': {'value': dict(auth, checked_ns=90, deadline_ns=200)}},
            'tc': {iface: {'attached': True, 'program_id': n}
                   for n, iface in enumerate(('wg-inner', 'resource'), 1)},
            'verdicts': {label: dict.fromkeys(VERDICT_REASONS, 0)
                         for label in ('wg_ingress', 'resource_ingress')},
            'interfaces': {}, 'nft_hooks': {'ipsec_dual': 'fixed', 'kernel_gate_v2_test': 'fixed'},
            'nft': {'ipsec_dual': [{'handle': 1, 'rule_kind': 'drop', 'verdicts': ['drop'],
                                   'counter': [{'packets': 0}]}], 'kernel_gate_v2_test': []}}


class P0Tests(unittest.TestCase):
    def test_probe_checksums_and_exact_identities(self):
        for identity in PROBES.values():
            packet = syn_packet(identity)
            self.assertEqual(identity, packet_id(101, packet))
            self.assertEqual(0, checksum(packet[:20]))
            pseudo = packet[12:20] + struct.pack('!BBH', 0, 6, 20)
            self.assertEqual(0, checksum(pseudo+packet[20:]))
            self.assertIsNone(packet_id(101, packet[:39]))

    def test_denial_requires_live_unchanged_authority_both_tc_counters_nft_and_echo(self):
        before = snapshot(); after = deepcopy(before)
        for label in ('wg_ingress', 'resource_ingress'):
            after['verdicts'][label]['scope_denied'] = 1
        after['nft']['ipsec_dual'][0]['counter'][0]['packets'] = 1
        rows = [{'delivered': True}]
        assert_negative_counts(before, after, rows)
        for label in ('wg_ingress', 'resource_ingress'):
            changed = deepcopy(after); changed['verdicts'][label]['scope_denied'] = 0
            with self.assertRaises(EvidenceError): assert_negative_counts(before, changed, rows)
        for edit in (
                lambda s: s['maps']['authorization']['value'].update(deadline_ns=1001),
                lambda s: s['maps']['health']['value'].update(deadline_ns=100),
                lambda s: s['tc']['wg-inner'].update(attached=False),
                lambda s: s['tc']['resource'].update(program_id=99),
                lambda s: s['nft_hooks'].update(ipsec_dual='changed'),
                lambda s: s['nft']['ipsec_dual'][0]['counter'][0].update(packets=0)):
            changed = deepcopy(after); edit(changed)
            with self.assertRaises(EvidenceError): assert_negative_counts(before, changed, rows)
        with self.assertRaises(EvidenceError): assert_negative_counts(before, after, [{'delivered': False}])
        timed = [{'delivered': True, 'attempt_ns': 1, 'verdict_ns': 2},
                 {'delivered': True, 'attempt_ns': 5, 'verdict_ns': 6}]
        assert_negative_counts(before, after, timed, (3, 4))
        with self.assertRaisesRegex(EvidenceError, 'before and after'):
            assert_negative_counts(before, after, timed[:1], (3, 4))

    def test_captures_require_injection_arrival_and_absence_after_enforcement(self):
        ethernet = bytes(12)+b'\x08\x00'
        source, dest = bytes.fromhex('020000000002'), bytes.fromhex('020000000001')
        arp = dest+source+b'\x08\x06'+b'\x00\x01\x08\x00\x06\x04\x00\x02'+source+socket.inet_aton('10.80.0.2')+dest+socket.inet_aton('10.80.0.1')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def write(label, packets, link=1):
                data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link)
                for packet in packets:
                    data += struct.pack('<IIII', 1, 0, len(packet), len(packet))+packet
                (root/(label+'.pcap')).write_bytes(data)
            for label in ('endpoint-wg', 'inner-wg'):
                write(label, [syn_packet(PROBES['wrong_port'])], 101)
            for label in ('inner-resource', 'resource'):
                write(label, [ethernet+syn_packet(PROBES['wrong_resource']), arp])
            for label in ('inner-transit', 'outer-transit'):
                write(label, [ethernet+syn_packet(PROBES['underlay'])])
            esp = bytearray(syn_packet(PROBES['underlay'])); esp[9] = 50
            for label in ('endpoint-public-wire-egress', 'outer-public-wire-egress'):
                write(label, [ethernet+esp])
            result = assert_captures(root)
            self.assertEqual(1, result['scoped_arp_replies'])
            write('resource', [ethernet+syn_packet(PROBES['wrong_resource']), arp,
                               ethernet+syn_packet(PROBES['underlay'])])
            with self.assertRaisesRegex(EvidenceError, 'underlay'):
                assert_captures(root)
            write('resource', [ethernet+syn_packet(PROBES['wrong_resource']), arp])
            write('inner-wg', [], 101)
            with self.assertRaisesRegex(EvidenceError, 'wrong_port'):
                assert_captures(root)


if __name__ == '__main__': unittest.main()
