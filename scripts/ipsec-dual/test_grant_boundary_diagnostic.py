"""Nonprivileged checks for the isolated, read-only grant probe."""
import json
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kernel_gate_publisher_v2 import AUTH, HEALTH, PEER, RESOURCE, PORT
from grant_boundary_diagnostic import (decode_map, sample, safe_failure, assert_grant,
                                       parse_tc, parse_route, assert_packet_boundary,
                                       decode_verdicts, parse_link, parse_forwarding,
                                       packet_deltas, VERDICT_REASONS, exact_forward_rule)
from native_aa_java_harness import Fixture
from isolated_enforcement import pkcs8, operation


class DiagnosticTests(unittest.TestCase):
    def test_observed_reverse_ct_membership_is_exactly_established(self):
        from copy import deepcopy
        from grant_boundary_diagnostic import nft_rule_kind
        # Normalized fields from both real nft JSON reverse rules. nft emits
        # membership for the conntrack state bitmask, equality for tuple/mark.
        expr = [
            {'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'resource'}},
            {'match': {'op': '==', 'left': {'meta': {'key': 'oifname'}}, 'right': 'wg-inner'}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '10.80.0.2'}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}}, 'right': '10.79.0.1'}},
            {'match': {'op': '==', 'left': {'payload': {'protocol': 'tcp', 'field': 'sport'}}, 'right': 8080}},
            {'match': {'op': '==', 'left': {'meta': {'key': 'mark'}}, 'right': 1511506142}},
            {'match': {'op': 'in', 'left': {'ct': {'key': 'state'}}, 'right': 'established'}},
            {'counter': {'packets': 73, 'bytes': 6954}}, {'accept': None}]
        for table in ('ipsec_dual', 'kernel_gate_v2_test'):
            self.assertEqual('reverse', nft_rule_kind(expr, table))
            for right in ('related', {'set': ['established', 'related']}, ['established']):
                changed = deepcopy(expr); changed[6]['match']['right'] = right
                self.assertEqual('unknown', nft_rule_kind(changed, table))
            changed = deepcopy(expr); changed[4]['match']['op'] = 'in'
            self.assertEqual('unknown', nft_rule_kind(changed, table))
            self.assertEqual('unknown', nft_rule_kind(expr[:6] + expr[7:], table))
            self.assertEqual('unknown', nft_rule_kind(expr[:5] + expr[6:], table))

    def test_nft_forward_ast_requires_exact_tuple_mark_and_interfaces(self):
        matches = [(('meta', 'iifname'), 'wg-inner'),
                   (('meta', 'oifname'), 'resource'),
                   (('payload:ip', 'saddr'), '10.79.0.1'),
                   (('payload:ip', 'daddr'), '10.80.0.2'),
                   (('payload:tcp', 'dport'), 8080),
                   (('meta', 'mark'), '0x5a17c0de')]
        def expression(item):
            (kind, field), right = item
            left = ({'meta': {'key': field}} if kind == 'meta'
                    else {'payload': {'protocol': kind.split(':')[1], 'field': field}})
            return {'match': {'op': '==', 'left': left, 'right': right}}
        expr = list(map(expression, matches))
        self.assertTrue(exact_forward_rule(expr + [{'counter': {'packets': 0}},
                                                    {'accept': None}]))
        self.assertFalse(exact_forward_rule(expr))
        self.assertFalse(exact_forward_rule(expr[:-1]))
        self.assertFalse(exact_forward_rule(expr + [{'accept': None}]))
        self.assertFalse(exact_forward_rule(expr + [expression((('meta', 'mark'),
                                                                 '0x5a17c0de'))]))
        self.assertFalse(exact_forward_rule(expr[:-1] + [expression((('meta', 'mark'), 0))]))
        self.assertFalse(exact_forward_rule(expr[:-1] + [expression((('meta', 'mark'),
                                                                  'token=SECRET'))]))

    def test_packet_deltas_bind_fixed_hooks_rules_and_interfaces(self):
        from copy import deepcopy
        tc = {reason: 0 for reason in VERDICT_REASONS}
        before = {'verdicts': {'wg_ingress': tc, 'resource_ingress': tc},
                  'nft': {'ipsec_dual': [{'handle': 7, 'counter': [{'packets': 0}],
                                         'verdicts': ['drop']}],
                          'kernel_gate_v2_test': [{'handle': 9, 'counter': [{'packets': 0}],
                                                   'verdicts': ['accept']}]},
                  'interfaces': {'inner_wg': {'name_matches': True, 'ifindex': 2,
                                               'rx_packets': 10, 'tx_packets': 0}}}
        after = deepcopy(before)
        after['verdicts']['wg_ingress'] = dict(tc, syn_matched=3, syn_dropped=3,
                                                 health_deadline_denied=3)
        after['nft']['ipsec_dual'][0]['counter'][0]['packets'] = 2
        after['interfaces']['inner_wg']['rx_packets'] = 13
        result = packet_deltas(before, after)
        self.assertEqual(3, result['tc']['wg_ingress']['health_deadline_denied'])
        self.assertEqual(2, result['nft']['ipsec_dual'][0]['packet_deltas'][0])
        self.assertEqual(3, result['interfaces']['inner_wg']['rx_packets'])
        changed = deepcopy(after)
        changed['nft']['ipsec_dual'][0]['handle'] = 8
        with self.assertRaises(ValueError): packet_deltas(before, changed)
        changed = deepcopy(after)
        changed['nft']['ipsec_dual'][0]['rule_kind'] = 'unknown'
        with self.assertRaises(ValueError): packet_deltas(before, changed)
        original = deepcopy(before)
        original['nft']['ipsec_dual'].append({'handle': 8, 'counter': [],
                                              'verdicts': ['drop'], 'rule_kind': 'drop'})
        reordered = deepcopy(original)
        reordered['nft']['ipsec_dual'].reverse()
        with self.assertRaises(ValueError): packet_deltas(original, reordered)
        changed = deepcopy(after)
        changed['verdicts']['wg_ingress']['syn_matched'] = -1
        with self.assertRaises(ValueError): packet_deltas(before, changed)

    def test_verdict_map_decode_rejects_missing_and_untrusted_values(self):
        rows = [{'key': list(struct.pack('<I', n)), 'value': list(struct.pack('<Q', n + 4))}
                for n in range(32)]
        result = decode_verdicts(rows)
        self.assertEqual(7, result['wg_ingress']['syn_matched'])
        self.assertEqual(23, result['resource_ingress']['syn_matched'])
        with self.assertRaises(ValueError): decode_verdicts(rows[:-1])
        with self.assertRaises(ValueError): decode_verdicts(rows[:-1] + [rows[0]])
        with self.assertRaises(ValueError):
            decode_verdicts(rows[:-1] + [dict(rows[-1], value=['token=SECRET'] * 8)])
        self.assertTrue(parse_forwarding('net.ipv4.ip_forward = 1'))
        self.assertFalse(parse_forwarding('net.ipv4.ip_forward = 0'))
        parsed = parse_link([{'ifname': 'resource', 'ifindex': 4,
                              'stats64': {'rx': {'packets': 9, 'secret': 'SECRET'},
                                          'tx': {'packets': 3}}}], 'resource')
        self.assertEqual(9, parsed['rx_packets'])
        self.assertNotIn('SECRET', json.dumps(parsed))

    def test_positive_packet_boundary_requires_same_tcp_syn_at_four_captures(self):
        import socket
        import tempfile
        from continuous_evidence import EvidenceError
        ip = (bytes([0x45, 0, 0, 40]) + bytes(4) + bytes([64, 6, 0, 0]) +
              socket.inet_aton('10.79.0.1') + socket.inet_aton('10.80.0.2'))
        tcp = struct.pack('!HHII', 42111, 8080, 12345, 0) + bytes([0x50, 0x02]) + bytes(6)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, linktype in (('endpoint-wg', 101), ('inner-wg', 101),
                                   ('inner-resource', 1), ('resource', 1)):
                frame = (bytes(12) + b'\x08\x00' if linktype == 1 else b'') + ip + tcp
                (root/(name + '.pcap')).write_bytes(
                    struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, linktype) +
                    struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame)
            self.assertEqual(1, assert_packet_boundary(root)['matched_syn_flows'])
            # A truncated declared IPv4 datagram cannot be counted as a SYN.
            frame = (bytes(12) + b'\x08\x00' +
                     ip[:2] + b'\x00\x14' + ip[4:] + tcp)
            (root/'resource.pcap').write_bytes(
                struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) +
                struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame)
            with self.assertRaises(EvidenceError):
                assert_packet_boundary(root)
            # A TCP data offset beyond the declared IP datagram is not a SYN.
            frame = bytes(12) + b'\x08\x00' + ip + tcp[:12] + b'\xf0' + tcp[13:]
            (root/'resource.pcap').write_bytes(
                struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) +
                struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame)
            with self.assertRaises(EvidenceError):
                assert_packet_boundary(root)
            (root/'resource.pcap').write_bytes(struct.pack('<IHHIIII',
                0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
            with self.assertRaises(EvidenceError):
                assert_packet_boundary(root)

    def test_tc_and_route_records_allowlist_fields_not_raw_payload(self):
        tc = parse_tc('filter protocol all pref 49152 bpf chain 0\n'
                      'filter protocol all pref 49152 bpf chain 0 handle 0x1 id 238440 '
                      'token=TOPSECRET')
        route = parse_route([{'dst': '10.80.0.2', 'dev': 'wg-inner',
                              'gateway': 'private-key=TOPSECRET'}], 'wg-inner')
        self.assertTrue(tc['attached'])
        self.assertEqual('wg-inner', route['selected_dev'])
        self.assertNotIn('TOPSECRET', json.dumps((tc, route)))

    def test_snapshot_does_not_copy_untrusted_program_name_or_nft_payload(self):
        keys = (Ed25519PrivateKey.generate() for _ in range(3))
        fixture = Fixture(dict(zip(('operatorPkcs8', 'nodePkcs8', 'supervisorPkcs8'),
                                   (pkcs8(key) for key in keys))))
        publisher = SimpleNamespace(current=None, auth_path='/auth', health_path='/health',
                                    pin_dir=Path('/pins'))
        def inner(args):
            if 'lookup' in args:
                size = AUTH.size if '/auth' in args else HEALTH.size
                return json.dumps({'value': [0] * size})
            if 'dump' in args:
                return json.dumps([{'key': list(struct.pack('<I', n)), 'value': [0]*8}
                                   for n in range(32)])
            if 'prog' in args:
                return json.dumps({'id': 1, 'name': 'token=TOPSECRET', 'type': 'classifier'})
            if args[0] == 'nft':
                return json.dumps({'nftables': [{'rule': {'handle': 3, 'expr': [
                    {'counter': {'packets': 1, 'bytes': 64,
                                 'secret': 'TOPSECRET'}}]}}]})
            if args[0] == 'ip':
                return json.dumps([{'ifname': 'resource', 'ifindex': 1,
                                    'stats64': {'rx': {'packets': 1}, 'tx': {'packets': 2}}}])
            if args[0] == 'sysctl':
                return 'net.ipv4.ip_forward = 1'
            return ''
        try:
            with patch('grant_boundary_diagnostic.command', return_value='[]'):
                result = sample(fixture, publisher, inner)
            self.assertNotIn('TOPSECRET', json.dumps(result))
        finally:
            fixture.close()

    def test_grant_checks_require_accepted_published_and_delivered(self):
        from continuous_evidence import EvidenceError
        start = {'monotonic_ns': 100, 'maps': {}}
        permit = {'epoch': 3, 'deadline_ns': 8000, 'peer': '10.79.0.1',
                  'resource': '10.80.0.2', 'port': 8080}
        after = {'monotonic_ns': 170, 'boottime_ns': 1000,
                 'inner_forwarding_enabled': True,
                 'controller_status': 'ATTESTED', 'admission_state': 'AUTHORIZED',
                 'generation': 2, 'original_deadline_ns': 8000,
                 'maps': {'authorization': {'value': permit},
                          'health': {'value': dict(permit, checked_ns=900,
                                                    deadline_ns=1200)}},
                 'tc': {'wg-inner': {'attached': True, 'program_id': 1},
                        'resource': {'attached': True, 'program_id': 2}},
                 'programs': {'wg_ingress': {'expected_name': True, 'classifier': True,
                                            'id': 1},
                              'resource_ingress': {'expected_name': True, 'classifier': True,
                                                   'id': 2}},
                 'nft_hooks': {'ipsec_dual': [{'hook_forward': True, 'priority': 0,
                                              'policy_drop': True}],
                               'kernel_gate_v2_test': [{'hook_forward': True,
                                                        'priority': 10, 'policy_drop': True}]},
                 'nft': {'ipsec_dual': [
                     {'handle': 10, 'verdicts': ['accept'], 'counter': [], 'rule_kind': 'transit_in'},
                     {'handle': 11, 'verdicts': ['accept'], 'counter': [], 'rule_kind': 'transit_out'},
                     {'handle': 1, 'verdicts': ['accept'], 'counter': [{'packets': 1}],
                      'expected_forward': True, 'rule_kind': 'forward'},
                     {'handle': 12, 'verdicts': ['accept'], 'counter': [{'packets': 0}],
                      'rule_kind': 'reverse'},
                     {'handle': 2, 'verdicts': ['drop'], 'counter': [{'packets': 0}],
                      'expected_forward': False, 'rule_kind': 'drop'}],
                         'kernel_gate_v2_test': [
                             {'handle': 3, 'verdicts': ['accept'], 'counter': [{'packets': 1}],
                              'expected_forward': True, 'rule_kind': 'forward'},
                             {'handle': 13, 'verdicts': ['accept'], 'counter': [{'packets': 0}],
                              'rule_kind': 'reverse'},
                             {'handle': 4, 'verdicts': ['drop'], 'counter': [{'packets': 0}],
                              'expected_forward': False, 'rule_kind': 'drop'}]}}
        report = {'issuance': {'java_aa_status': 'ATTESTED', 'generation': 2,
                               'original_deadline_ns': 8000},
                  'publish_returned': True,
                  'snapshots': [['pre', start], ['post-grant', after],
                                ['post-traffic', after]],
                  'packet_deltas': {'tc': {'wg_ingress': {'syn_matched': 1,
                                                         'syn_passed': 1, 'syn_dropped': 0}},
                                    'nft': {'ipsec_dual': [{'handle': 1, 'verdicts': ['accept'],
                                                           'packet_deltas': [1]}],
                                            'kernel_gate_v2_test': [{'handle': 3,
                                                                     'verdicts': ['accept'],
                                                                     'packet_deltas': [1]}]}},
                  'grant_event_ns': 150,
                  'attempts': [{'attempt_ns': 90, 'verdict_ns': 110, 'delivered': False},
                               {'attempt_ns': 180, 'verdict_ns': 195, 'delivered': True},
                               {'attempt_ns': 200, 'verdict_ns': 205, 'delivered': True}]}
        self.assertTrue(assert_grant(report))
        detached = dict(after, tc={'wg-inner': {'attached': False},
                                   'resource': {'attached': True}})
        with self.assertRaises(EvidenceError):
            assert_grant(dict(report, snapshots=[['post-grant', detached]]))
        wrong_program = dict(after, tc={'wg-inner': {'attached': True, 'program_id': 99},
                                        'resource': {'attached': True, 'program_id': 98}})
        with self.assertRaises(EvidenceError):
            assert_grant(dict(report, snapshots=[['post-grant', wrong_program]]))
        for broken in (dict(after, nft_hooks={'ipsec_dual': [{'hook_forward': True,
                       'priority': 0, 'policy_drop': False}]}),
                       dict(after, nft={'ipsec_dual': [], 'kernel_gate_v2_test': []})):
            with self.assertRaises(EvidenceError):
                assert_grant(dict(report, snapshots=[['post-grant', broken]]))
        extra = dict(after, nft={**after['nft'],
                                 'kernel_gate_v2_test': [
                                     {'handle': 8, 'verdicts': ['accept'],
                                      'counter': [], 'expected_forward': False},
                                     *after['nft']['kernel_gate_v2_test']]})
        with self.assertRaises(EvidenceError):
            assert_grant(dict(report, snapshots=[['post-grant', extra]]))
        with self.assertRaises(EvidenceError):
            assert_grant(dict(report, packet_deltas={'tc': {'wg_ingress': {
                'syn_matched': 0, 'syn_passed': 0, 'syn_dropped': 0}}, 'nft': {}}))
        for key, value in (('publish_returned', False), ('issuance', None)):
            failed = dict(report, **{key: value})
            with self.assertRaises(EvidenceError):
                assert_grant(failed)
        failed = dict(report, attempts=report['attempts'][:1])
        with self.assertRaises(EvidenceError):
            assert_grant(failed)

    def test_exception_preserves_partial_report_and_nonzero_result(self):
        import threading
        from unittest.mock import Mock
        from grant_boundary_diagnostic import run
        class Stream:
            def __init__(self, **kw): pass
            def start(self, root): pass
            def ready(self, delivered=False): pass
            def stop(self): return []
        class Captures:
            def __init__(self, *args, **kw): pass
            def start(self, root): pass
            def stop(self): raise RuntimeError('capture cleanup failed')
        with __import__('tempfile').TemporaryDirectory() as directory, \
                patch('grant_boundary_diagnostic.CaptureSet', Captures), \
                patch('grant_boundary_diagnostic.TrafficStream', Stream), \
                patch('grant_boundary_diagnostic.sample', return_value={'monotonic_ns': 1}):
            def grant(*args): raise RuntimeError('signed operation not committed in denied state')
            with self.assertRaisesRegex(__import__('continuous_evidence').EvidenceError,
                                        'signed operation not committed'):
                run(directory, object(), object(), SimpleNamespace(lock=threading.RLock()),
                    Mock(), Mock(), grant)
            record = json.loads((Path(directory)/'grant-diagnostic'/'diagnostic.json').read_text())
            self.assertEqual('signed operation not committed in denied state',
                             record['failure']['message'])
            self.assertEqual('RuntimeError', record['cleanup_failure']['type'])

    def test_report_write_failure_does_not_mask_original_grant_failure(self):
        import tempfile
        import threading
        from unittest.mock import Mock
        from continuous_evidence import EvidenceError
        from grant_boundary_diagnostic import run
        class Captures:
            def __init__(self, *args, **kw): pass
            def start(self, root): pass
            def stop(self): pass
        stream = Mock()
        stream.stop.return_value = []
        with tempfile.TemporaryDirectory() as directory, \
             patch('grant_boundary_diagnostic.CaptureSet', Captures), \
             patch('grant_boundary_diagnostic.TrafficStream', return_value=stream), \
             patch('grant_boundary_diagnostic.sample', return_value={}), \
             patch('pathlib.Path.write_text', side_effect=OSError('disk full private-key=SECRET')):
            def bad(*args): raise RuntimeError('signed operation not committed in denied state')
            with self.assertRaisesRegex(EvidenceError, 'signed operation not committed'):
                run(directory, object(), object(), SimpleNamespace(lock=threading.RLock()),
                    Mock(), Mock(), bad)

    def test_failure_trace_redacts_untrusted_exception_text(self):
        def fail():
            raise RuntimeError('secret private material')
        try:
            fail()
        except RuntimeError as exc:
            record = safe_failure(exc)
        self.assertEqual('RuntimeError', record['type'])
        self.assertEqual('redacted', record['message'])
        self.assertNotIn('secret', json.dumps(record))
        self.assertTrue(record['traceback'])
        self.assertNotIn('secret', json.dumps(safe_failure(RuntimeError('token=secret'))))

    def test_loader_failure_record_preserves_only_allowlisted_codes(self):
        safe = ('Kernel gate command failed: kernel_command_failed; stage=map_pinning; '
                'subject=auth_map; errno=EEXIST; reason=unknown')
        self.assertEqual(safe, safe_failure(RuntimeError(safe))['message'])
        self.assertEqual('redacted', safe_failure(RuntimeError(
            safe + ' token=SECRET'))['message'])
        self.assertEqual('redacted', safe_failure(RuntimeError(
            safe.replace('auth_map', 'private_key')))['message'])

    def test_pregrant_snapshot_does_not_quarantine_recoverable_authority(self):
        keys = (Ed25519PrivateKey.generate() for _ in range(3))
        fixture = Fixture(dict(zip(('operatorPkcs8', 'nodePkcs8', 'supervisorPkcs8'),
                                   (pkcs8(key) for key in keys))))
        publisher = SimpleNamespace(current=None, auth_path='/auth', health_path='/health',
                                    pin_dir=Path('/pins'))
        def inner(args):
            if 'lookup' in args:
                size = AUTH.size if '/auth' in args else HEALTH.size
                return json.dumps({'value': ['0x00'] * size})
            if 'dump' in args:
                return json.dumps([{'key': list(struct.pack('<I', n)), 'value': [0]*8}
                                   for n in range(32)])
            if 'prog' in args:
                return '{}'
            if args[0] == 'nft':
                return '{"nftables":[]}'
            if args[0] == 'ip':
                return '[{}]'
            if args[0] == 'sysctl':
                return 'net.ipv4.ip_forward = 1'
            return ''
        try:
            with patch('grant_boundary_diagnostic.command', return_value='[]'):
                snapshot = sample(fixture, publisher, inner)
            self.assertEqual('DENIED', snapshot['controller_status'])
            self.assertIsNotNone(fixture.controller.admission.pending,
                                 'snapshot must not clear the fresh signed challenge')
            self.assertEqual('DENIED', operation(fixture, 'RECOVER')['status'])
            self.assertEqual(1, fixture.controller.admission.generation)
        finally:
            fixture.close()

    def test_decodes_verified_map_bytes_and_original_deadline_without_secrets(self):
        auth = AUTH.pack(123, 987654321, PEER, RESOURCE, PORT, 0)
        health = HEALTH.pack(123, 987654300, 987654000, PEER, RESOURCE, PORT, 0)
        self.assertEqual(decode_map({'value': [f'0x{n:02x}' for n in auth]}, AUTH),
                         {'epoch': 123, 'deadline_ns': 987654321,
                          'peer': '10.79.0.1', 'resource': '10.80.0.2',
                          'port': 8080, 'reserved': 0})
        self.assertEqual(decode_map({'value': list(health)}, HEALTH)['checked_ns'], 987654000)
        with self.assertRaises(ValueError):
            decode_map({'value': [0]}, AUTH)


if __name__ == '__main__':
    unittest.main()
