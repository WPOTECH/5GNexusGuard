"""Nonprivileged wiring checks; packet acceptance needs separate scoped run."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import isolated_enforcement as runner


class WiringTests(unittest.TestCase):
    def test_cleanup_runs_all_actions_without_masking_primary_failure(self):
        calls = []
        def bad():
            calls.append('bad')
            raise RuntimeError('private-key=SECRET')
        def good(): calls.append('good')
        with self.assertRaisesRegex(ValueError, 'primary'):
            try:
                raise ValueError('primary')
            finally:
                runner.complete_cleanup((('ticker', bad), ('fixture', good)),
                                        __import__('sys').exc_info()[1])
        self.assertEqual(['bad', 'good'], calls)
        with self.assertRaisesRegex(RuntimeError, 'isolated cleanup failed'):
            runner.complete_cleanup((('ticker', bad), ('fixture', good)), None)

    def test_tunnel_log_diagnostics_emit_categories_not_secret_lines(self):
        raw = ('authentication failed private-key=TOPSECRET token=abc123\n'
               'timeout while sending signed payload=UNREDACTED\n'
               'failed no proposal chosen certificate=PEMCONTENT')
        events = runner.tunnel_error_events(raw, 'swanctl')
        self.assertIn('authentication_failed', events)
        self.assertIn('timeout', events)
        self.assertNotIn('TOPSECRET', json.dumps(events))
        self.assertNotIn('abc123', json.dumps(events))
        self.assertNotIn('UNREDACTED', json.dumps(events))
        self.assertNotIn('PEMCONTENT', json.dumps(events))

    def test_recover_trace_records_bindings_without_signature_or_nonce(self):
        from native_aa_java_harness import Fixture
        operator, node, supervisor = (Ed25519PrivateKey.generate() for _ in range(3))
        fixture = Fixture(dict(operatorPkcs8=runner.pkcs8(operator),
                               nodePkcs8=runner.pkcs8(node),
                               supervisorPkcs8=runner.pkcs8(supervisor)))
        try:
            trace = {}
            self.assertEqual('DENIED', runner.operation(fixture, 'RECOVER', trace=trace)['status'])
            self.assertEqual(1, trace['supplied_generation'])
            self.assertEqual(1, trace['committed_generation'])
            self.assertTrue(trace['signature_valid'])
            self.assertTrue(trace['challenge_bound'])
            self.assertTrue(trace['local_journal_commit_observed'])
            self.assertFalse(trace['external_recovery_floor_verified'])
            self.assertNotIn('nonce', json.dumps(trace).lower())
            self.assertNotIn('signature', json.dumps(trace).replace('signature_valid', ''))
        finally:
            fixture.close()

    def test_missing_challenge_reports_specific_recover_rejection(self):
        from native_aa_java_harness import Fixture
        operator, node, supervisor = (Ed25519PrivateKey.generate() for _ in range(3))
        fixture = Fixture(dict(operatorPkcs8=runner.pkcs8(operator),
                               nodePkcs8=runner.pkcs8(node),
                               supervisorPkcs8=runner.pkcs8(supervisor)))
        try:
            fixture.controller.admission.pending = None
            trace = {}
            with self.assertRaisesRegex(RuntimeError, 'not committed'):
                runner.operation(fixture, 'RECOVER', trace=trace)
            self.assertEqual('missing_pending_challenge', trace['rejection_reason'])
            self.assertEqual(0, trace['committed_generation'])
        finally:
            fixture.close()

    @unittest.skipUnless(os.environ.get('TEST_CLI_CLASSPATH'), 'compiled Java CLI classpath not mounted')
    def test_real_java_fixture_signed_recovery_aa(self):
        from native_aa_java_harness import Fixture
        operator, node, supervisor = (Ed25519PrivateKey.generate() for _ in range(3))
        fixture = Fixture(dict(operatorPkcs8=runner.pkcs8(operator),
                               nodePkcs8=runner.pkcs8(node),
                               supervisorPkcs8=runner.pkcs8(supervisor)))
        issuer = None
        try:
            issuer = runner.JavaIssuer(fixture, operator, node, os.environ['TEST_CLI_CLASSPATH'])
            result = runner.grant(fixture, issuer)
            self.assertEqual('ATTESTED', result['status'])
            self.assertLess(result['deadline_boottime_ns'],
                            __import__('time').clock_gettime_ns(__import__('time').CLOCK_BOOTTIME) + 3_000_000_000)
        finally:
            if issuer is not None: issuer.close()
            fixture.close()

    def test_grant_uses_signed_recovery_java_and_original_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            challenge = dict(bootId='b', sessionId='s', nonce='n')
            (root/'challenge.json').write_text(json.dumps(challenge))
            admission = SimpleNamespace(generation=0, deadline=None)
            controller = SimpleNamespace(admission=admission)
            class Fixture:
                operator = SimpleNamespace(sign=lambda payload: b'signed')
                scope = dict(serviceId='svc', clientNodeId='a'*64,
                             ownerNodeId='b'*64, resource='tcp:10.80.0.2:8080')
                def __init__(self):
                    self.root, self.controller, self.calls = root, controller, []
                def dispatch(self, item):
                    self.calls.append(item)
                    if item['action'] == 'operation':
                        admission.generation = item['operation']['generation']
                        return dict(status='DENIED')
                    admission.deadline = item['envelope']['payload']['deadlineBoottimeNs']
                    return dict(status='ATTESTED')
            class Issuer:
                def ask(self, item):
                    self.request = item
                    return dict(envelope=dict(payload=dict(deadlineBoottimeNs=123456789)))
            fixture, issuer = Fixture(), Issuer()
            with patch.object(runner, 'operation_bytes', return_value=b'op'):
                result = runner.grant(fixture, issuer)
            self.assertEqual(['operation', 'grant'], [c['action'] for c in fixture.calls])
            self.assertEqual('RECOVER', fixture.calls[0]['operation']['action'])
            self.assertEqual(2, issuer.request['generation'])
            self.assertEqual(2_999_000_000, issuer.request['lifetimeNs'])
            self.assertEqual(123456789, result['deadline_boottime_ns'])

    def test_passive_expiry_has_no_fault_or_revoke(self):
        class FakeCapture:
            def __init__(self, *args): self.started = False
            def start(self, path): self.started = True
            def stop(self): self.started = False
        class FakeStream:
            def __init__(self, **kwargs): pass
            def start(self, path): pass
            def ready(self): pass
            def stop(self):
                return [dict(attempt_ns=1, verdict_ns=2, delivered=True),
                        dict(attempt_ns=3, verdict_ns=4, delivered=False)]
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(runner, 'CaptureSet', FakeCapture), patch.object(runner, 'TrafficStream', FakeStream), patch.object(runner.time, 'monotonic_ns', return_value=2), patch.object(runner.time, 'sleep'):
                result = runner.observe_expiry(Path(directory), 55, 0)
            self.assertEqual(55, result['deadline_boottime_ns'])
            self.assertEqual(4, result['first_denied_verdict_ns'])
            self.assertTrue((Path(directory)/'expiry'/'summary.json').exists())

    def test_evidence_guard_refuses_unsafe_or_reused_paths(self):
        for path in ('relative', '/tmp/packets', '/lab/evidence/../repo'):
            with self.assertRaises(ValueError):
                runner.isolated_path(path)

    def test_aa_fault_does_not_force_reattest_and_keeps_original_deadline(self):
        from native_aa_java_harness import Fixture
        operator, node, supervisor = (Ed25519PrivateKey.generate() for _ in range(3))
        fixture = Fixture(dict(operatorPkcs8=runner.pkcs8(operator),
                               nodePkcs8=runner.pkcs8(node),
                               supervisorPkcs8=runner.pkcs8(supervisor)))
        try:
            before = fixture.controller.until_ns
            runner.revoke_aa_only(fixture)
            self.assertEqual(before, fixture.controller.until_ns)
        finally:
            fixture.close()

    def test_aa_outage_does_not_mutate_cached_controller_attestation(self):
        from native_aa_java_harness import Fixture
        operator, node, supervisor = (Ed25519PrivateKey.generate() for _ in range(3))
        fixture = Fixture(dict(operatorPkcs8=runner.pkcs8(operator),
                               nodePkcs8=runner.pkcs8(node),
                               supervisorPkcs8=runner.pkcs8(supervisor)))
        try:
            before = fixture.controller.until_ns
            runner.stop_aa_only(fixture)
            self.assertEqual(before, fixture.controller.until_ns)
            self.assertFalse(fixture.thread.is_alive())
        finally:
            fixture.close()

    def test_fault_scenarios_require_fresh_grant_and_never_renew(self):
        deadline = __import__('time').clock_gettime_ns(__import__('time').CLOCK_BOOTTIME) + 2_000_000_000
        controller = SimpleNamespace(admission=SimpleNamespace(generation=4, deadline=100),
                                     until_ns=90, step=lambda: 'DENIED')
        fixture = SimpleNamespace(controller=controller, aa_generation=1, aa_epoch=1,
                                  aa_revocation=0, transition=lambda action: None)
        ticker = SimpleNamespace(lock=__import__('threading').RLock(), check=lambda: None)
        events = []
        def fresh(*args):
            events.append('grant')
            controller.admission.generation += 2
            controller.admission.deadline = deadline
            return dict(status='ATTESTED', generation=controller.admission.generation,
                        deadline_boottime_ns=deadline)
        def fake_measure(root, name, hooks, *args, **kwargs):
            (Path(root)/name).mkdir()
            events.append('baseline')
            hooks[name]()
            events.append('fault')
            return dict(first_denied_verdict_ns=22, event_ns=10)
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(runner, 'guarded_grant', side_effect=fresh), \
             patch.object(runner, 'prepare_admission'), \
             patch.object(runner, 'measure', side_effect=fake_measure):
            runner.captured_fault(Path(directory), 'aa_revoke', fixture, object(), ticker,
                                  lambda: events.append('revoke'), wait_seconds=0)
        self.assertEqual(['grant', 'baseline', 'revoke', 'fault'], events)
        self.assertEqual(deadline, controller.admission.deadline)
        self.assertEqual(6, controller.admission.generation)

    def test_supervisor_failure_stops_heartbeat_without_zeroing_maps_in_hook(self):
        class Ticker:
            def __init__(self):
                self.stopped = __import__('threading').Event()
                self.thread = SimpleNamespace(join=lambda timeout: None, is_alive=lambda: False)
                self.publisher = SimpleNamespace(revoke=lambda: self.fail())
            def fail(self): raise AssertionError('hook must not revoke map')
        ticker = Ticker()
        runner.stop_ticker_for_failure(ticker)
        self.assertTrue(ticker.stopped.is_set())

    def test_restart_replay_rebinds_publisher_but_rejects_stale_grant(self):
        previous = SimpleNamespace(admission=SimpleNamespace(generation=2))
        current = SimpleNamespace(admission=SimpleNamespace(generation=2),
                                  session='new', step=lambda: 'DENIED')
        class Fixture:
            controller = previous
            def new_controller(self): return current
            def dispatch(self, item):
                self.item = item
                return dict(status='DENIED')
        fixture = Fixture()
        publisher = SimpleNamespace(controller=previous, tick=lambda: False)
        ticker = SimpleNamespace(lock=__import__('threading').RLock(), publisher=publisher)
        with tempfile.TemporaryDirectory() as directory:
            fixture.root = Path(directory)
            result = runner.restart_and_replay(fixture, ticker, {'payload': 'stale'})
        self.assertIs(publisher.controller, current)
        self.assertEqual('DENIED', result['replay_status'])
        self.assertEqual('grant', fixture.item['action'])

    def test_capture_supports_aa_revocation_restart_and_aa_outage(self):
        from continuous_evidence import FAULTS
        self.assertTrue({'aa_revoke', 'restart_replay', 'aa_outage'} <= FAULTS)

    def test_denial_budget_rejects_observed_supervisor_delay(self):
        with self.assertRaisesRegex(RuntimeError, 'denial budget'):
            runner.check_denial_budget('supervisor_death',
                                       dict(event_ns=1, first_denied_verdict_ns=1_100_000_002), 2)

    @unittest.skipUnless(os.environ.get('TEST_CLI_CLASSPATH'), 'compiled Java CLI classpath not mounted')
    def test_real_control_epochs_revoke_aa_restart_and_replay_without_forcing(self):
        from native_aa_java_harness import Fixture
        from threading import RLock
        operator, node, supervisor = (Ed25519PrivateKey.generate() for _ in range(3))
        fixture = Fixture(dict(operatorPkcs8=runner.pkcs8(operator),
                               nodePkcs8=runner.pkcs8(node),
                               supervisorPkcs8=runner.pkcs8(supervisor)))
        class Ticker:
            lock = RLock()
            publisher = SimpleNamespace(controller=fixture.controller, tick=lambda: False)
        ticker = Ticker()
        issuer = None
        try:
            issuer = runner.JavaIssuer(fixture, operator, node, os.environ['TEST_CLI_CLASSPATH'])
            runner.grant(fixture, issuer)
            self.assertEqual('DENIED', runner.operation(fixture, 'REVOKE')['status'])
            runner.prepare_admission(fixture, ticker)
            runner.grant(fixture, issuer)
            original_until = fixture.controller.until_ns
            runner.revoke_aa_only(fixture)
            self.assertEqual(original_until, fixture.controller.until_ns)
            runner.prepare_admission(fixture, ticker)
            runner.grant(fixture, issuer)
            stale = issuer.last_envelope
            outcome = runner.restart_and_replay(fixture, ticker, stale)
            self.assertEqual('DENIED', outcome['replay_status'])
            issuer.close()
            issuer = runner.JavaIssuer(fixture, operator, node, os.environ['TEST_CLI_CLASSPATH'])
            runner.prepare_admission(fixture, ticker)
            self.assertEqual('ATTESTED', runner.grant(fixture, issuer)['status'])
        finally:
            if issuer is not None: issuer.close()
            fixture.close()


if __name__ == '__main__':
    unittest.main()
