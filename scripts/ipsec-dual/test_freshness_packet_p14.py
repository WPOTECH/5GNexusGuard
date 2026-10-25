"""Nonprivileged negative controls for the P1.4 packet driver's acceptance rules."""
from copy import deepcopy
import unittest
import json
import struct
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from continuous_evidence import EvidenceError
from freshness_packet_p14 import SCENARIOS, assert_live_baseline, observe_epoch_rejection, require_invalid_denied
from independent_kernel_p1 import Supervisor


class FreshnessPacketTests(unittest.TestCase):
    def test_invalid_authority_must_not_publish_or_advance_the_floor(self):
        before = dict(status='DENIED', generation=4, deadline_ns=None, until_ns=0)
        after = dict(before, published=False, admission_state='PENDING_FRESH_APPROVAL')
        def supervisor(reply):
            obj = Mock(); obj.ask.side_effect = [deepcopy(before), reply]; return obj
        self.assertEqual('DENIED', require_invalid_denied(supervisor(after), {'envelope': {}})['status'])
        for edit in ({'status': 'ATTESTED'}, {'published': True}, {'generation': 5}, {'deadline_ns': 100}):
            with self.assertRaises(EvidenceError):
                require_invalid_denied(supervisor(dict(after, **edit)), {'envelope': {}})

    def test_highwater_denial_may_retain_only_the_unchanged_nonusable_cached_deadline(self):
        before = dict(status='DENIED', generation=2, deadline_ns=100, until_ns=0)
        after = dict(before, published=False, admission_state='AUTHORIZED')
        def supervisor(reply):
            obj = Mock(); obj.ask.side_effect = [deepcopy(before), reply]; return obj
        require_invalid_denied(supervisor(after), {}, allow_cached_deadline=True)
        for edit in ({'deadline_ns': 101}, {'until_ns': 50}, {'published': True}):
            with self.assertRaises(EvidenceError):
                require_invalid_denied(supervisor(dict(after, **edit)), {}, allow_cached_deadline=True)

    def test_cleanup_reports_nonzero_exit_and_only_accepts_verified_test_kill(self):
        obj = Supervisor.__new__(Supervisor); obj.process = Mock(); obj.log = Mock()
        obj.process.stdin.closed = False; obj.process.poll.return_value = 1; obj.process.returncode = 1
        with self.assertRaisesRegex(EvidenceError, 'unexpected exit'): obj.close()
        obj.process.stdout.close.assert_called_once(); obj.log.close.assert_called_once()
        obj = Supervisor.__new__(Supervisor); obj.process = Mock(); obj.log = Mock()
        obj.process.stdin.closed = True; obj.process.poll.return_value = -9; obj.process.returncode = -9
        with self.assertRaises(EvidenceError): obj.close()
        obj._killed_by_test = True
        obj.close()

    def test_live_fault_baseline_rejects_expired_or_mismatched_state(self):
        auth = dict(epoch=7, deadline_ns=1000, peer='10.79.0.1', resource='10.80.0.2', port=8080)
        snapshot = {'maps': {'authorization': {'value': auth},
                             'health': {'value': dict(auth, checked_ns=100, deadline_ns=600)}}}
        state = dict(status='ATTESTED', published=True, revocation_uncertain=False, deadline_ns=1000)
        assert_live_baseline(snapshot, state, 1000, 200)
        for now in (99, 600, 1000):
            with self.assertRaises(EvidenceError): assert_live_baseline(snapshot, state, 1000, now)
        changed = deepcopy(snapshot); changed['maps']['health']['value']['epoch'] = 8
        with self.assertRaises(EvidenceError): assert_live_baseline(changed, state, 1000, 200)
        with self.assertRaises(EvidenceError): assert_live_baseline(snapshot, dict(state, published=False), 1000, 200)

    def test_epoch_counter_must_be_observed_before_health_expiry(self):
        rows = [{'key': list(struct.pack('<I', n)), 'value': list(struct.pack('<Q', 1 if n==6 else 0))} for n in range(32)]
        publisher = SimpleNamespace(pin_dir=Path('/sys/fs/bpf/test'))
        with patch('freshness_packet_p14.time.clock_gettime_ns', return_value=199):
            result = observe_epoch_rejection(publisher, lambda _: json.dumps(rows), 0, 200)
            self.assertEqual(1, result['counter'])
        with patch('freshness_packet_p14.time.clock_gettime_ns', return_value=200):
            with self.assertRaisesRegex(EvidenceError, 'before health expiry'):
                observe_epoch_rejection(publisher, lambda _: json.dumps(rows), 0, 200)

    def test_no_reboot_or_host_clock_category_exists(self):
        self.assertEqual(9, len(SCENARIOS))
        self.assertFalse(any('reboot' in name or 'host_clock' in name for name in SCENARIOS))


if __name__ == '__main__': unittest.main()
