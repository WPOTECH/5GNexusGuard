"""P1.4 preparation: real Java/V2/mTLS-AA controls, no privileged packet claims.

Reboot tests change only the Controller boot-ID provider in this test process;
wall rollback changes only an injected Controller clock. No host clock/reboot,
network namespaces, BPF updates, or enforcement rules are touched.
"""
import base64
from copy import deepcopy
import json
import os
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from issuance_v2 import canonical, node_message
from isolated_enforcement import JavaIssuer, grant, operation, pkcs8
from native_aa_java_harness import Fixture
from native_control_v2 import atomic_private_write


class LocalWall:
    """Controller-local wall source; unrelated TLS/AA clocks remain real."""
    def __init__(self): self.offset = 0
    def __call__(self): return time.time()+self.offset


@unittest.skipUnless(os.environ.get('TEST_CLI_CLASSPATH'), 'compiled Java V2 CLI required')
class FreshnessP14Tests(unittest.TestCase):
    def setUp(self):
        operator, node, supervisor = (Ed25519PrivateKey.generate() for _ in range(3))
        self.fixture = Fixture(dict(operatorPkcs8=pkcs8(operator), nodePkcs8=pkcs8(node),
                                    supervisorPkcs8=pkcs8(supervisor)))
        self.issuer = JavaIssuer(self.fixture, operator, node, os.environ['TEST_CLI_CLASSPATH'])

    def tearDown(self):
        self.issuer.close(); self.fixture.close()

    def authorize(self):
        self.before_highwater = (self.fixture.root/'aa-highwater.json').read_bytes()
        result = grant(self.fixture, self.issuer)
        self.envelope = deepcopy(self.issuer.last_envelope)
        self.deadline = result['deadline_boottime_ns']
        self.assertEqual('ATTESTED', result['status'])
        return self.fixture.controller

    def submit(self, envelope):
        atomic_private_write(self.fixture.root/'inbox.json', json.dumps({'envelope': envelope}).encode())
        return self.fixture.controller.step()

    def resign(self, payload):
        message = canonical(payload); sig = self.fixture.operator.sign(message)
        return {'payload': payload, 'operatorSignature': base64.b64encode(sig).decode(),
                'nodeSignature': base64.b64encode(self.fixture.node.sign(node_message(message, sig))).decode()}

    def test_duplicate_issue_never_extends_original_deadline(self):
        c = self.authorize()
        generation = c.admission.generation
        for _ in range(3):
            self.assertEqual('ATTESTED', self.submit(self.envelope))
            self.assertEqual(self.deadline, c.admission.deadline)
            self.assertEqual(generation, c.admission.generation)

    def test_revoked_generation_cannot_restore_live_authority(self):
        self.authorize(); operation(self.fixture, 'REVOKE')
        self.assertEqual('DENIED', self.submit(self.envelope))
        self.assertIsNone(self.fixture.controller.admission.deadline)

    def test_stale_signed_generation_denied_after_fresh_recovery(self):
        c = self.authorize(); operation(self.fixture, 'REVOKE'); operation(self.fixture, 'RECOVER')
        challenge = json.loads((self.fixture.root/'challenge.json').read_text())
        payload = dict(self.envelope['payload'], nonce=challenge['nonce'], issuanceId=os.urandom(16).hex())
        self.assertEqual('DENIED', self.submit(self.resign(payload)))
        self.assertIsNone(c.admission.deadline)

    def test_supervisor_restart_cannot_restore_unexpired_old_envelope(self):
        old = self.authorize(); old_session = old.session
        self.fixture.controller = self.fixture.new_controller()
        self.assertNotEqual(old_session, self.fixture.controller.session)
        self.assertEqual('DENIED', self.submit(self.envelope))
        self.assertIsNone(self.fixture.controller.admission.deadline)

    def test_exporter_restart_does_not_reset_receiver_generation_floor(self):
        c = self.authorize(); operation(self.fixture, 'REVOKE'); operation(self.fixture, 'RECOVER')
        self.issuer.close()
        self.issuer = JavaIssuer(self.fixture, self.fixture.operator, self.fixture.node,
                                 os.environ['TEST_CLI_CLASSPATH'])
        challenge = json.loads((self.fixture.root/'challenge.json').read_text())
        stale = self.issuer.ask(dict(action='issue', challenge=challenge,
            generation=self.envelope['payload']['generation'],
            nowBoottimeNs=time.clock_gettime_ns(time.CLOCK_BOOTTIME),
            lifetimeNs=2_999_000_000))['envelope']
        floor = c.admission.generation
        self.assertEqual('DENIED', self.submit(stale))
        self.assertEqual(floor, c.admission.generation)
        self.assertIsNone(c.admission.deadline)

    def test_new_boot_identity_does_not_reactivate_prior_boot_authority(self):
        c = self.authorize(); old_boot = c.scope['bootId']
        new_boot = '123e4567-e89b-12d3-a456-426614174099'
        self.assertNotEqual(old_boot, new_boot)
        with patch('native_control_v2.boot_id', return_value=new_boot):
            self.fixture.controller = self.fixture.new_controller()
        self.assertEqual(new_boot, self.fixture.controller.scope['bootId'])
        self.assertEqual('DENIED', self.submit(self.envelope))
        self.assertIsNone(self.fixture.controller.admission.deadline)
        self.assertEqual(old_boot, c.scope['bootId'])

    def test_boot_binding_is_rejected_even_with_current_nonce_and_generation(self):
        operation(self.fixture, 'RECOVER')
        c = self.fixture.controller
        challenge = json.loads((self.fixture.root/'challenge.json').read_text())
        envelope = self.issuer.ask(dict(action='issue', challenge=challenge,
            generation=c.admission.generation+1, nowBoottimeNs=time.clock_gettime_ns(time.CLOCK_BOOTTIME),
            lifetimeNs=2_999_000_000))['envelope']
        payload = dict(envelope['payload'], bootId='123e4567-e89b-12d3-a456-426614174099')
        self.assertNotEqual(c.scope['bootId'], payload['bootId'])
        floor = c.admission.generation
        self.assertEqual('DENIED', self.submit(self.resign(payload)))
        self.assertEqual(floor, c.admission.generation)
        self.assertIsNone(c.admission.deadline)
        # Same live nonce/generation and genuine Java approval work with the
        # expected boot ID; session freshness cannot mask the negative control.
        self.assertEqual('ATTESTED', self.submit(envelope))

    def test_missing_highwater_denies_live_and_restarted_supervisor(self):
        c = self.authorize(); (self.fixture.root/'aa-highwater.json').unlink()
        self.assertEqual('DENIED', c.step())
        with self.assertRaisesRegex(ValueError, 'missing AA highwater'):
            self.fixture.new_controller()

    def test_rolled_back_highwater_denies_live_and_old_replay_after_restart(self):
        c = self.authorize()
        atomic_private_write(self.fixture.root/'aa-highwater.json', self.before_highwater)
        self.assertEqual('DENIED', c.step())
        self.fixture.controller = self.fixture.new_controller()
        self.assertEqual('DENIED', self.submit(self.envelope))
        self.assertIsNone(self.fixture.controller.admission.deadline)

    def test_whole_local_state_rollback_does_not_reactivate_old_grant(self):
        operation(self.fixture, 'RECOVER')
        saved_journal = (self.fixture.root/'admission.journal').read_bytes()
        saved_floor = (self.fixture.root/'aa-highwater.json').read_bytes()
        c = self.fixture.controller
        challenge = json.loads((self.fixture.root/'challenge.json').read_text())
        envelope = self.issuer.ask(dict(action='issue', challenge=challenge,
            generation=c.admission.generation+1, nowBoottimeNs=time.clock_gettime_ns(time.CLOCK_BOOTTIME),
            lifetimeNs=2_999_000_000))['envelope']
        self.assertEqual('ATTESTED', self.submit(envelope))
        atomic_private_write(self.fixture.root/'admission.journal', saved_journal)
        atomic_private_write(self.fixture.root/'aa-highwater.json', saved_floor)
        self.assertEqual('DENIED', c.step())
        self.fixture.controller = self.fixture.new_controller()
        self.assertEqual('DENIED', self.submit(envelope))
        self.assertIsNone(self.fixture.controller.admission.deadline)

    def test_wall_rollback_recovery_requires_new_session_and_fresh_signed_authority(self):
        c = self.fixture.controller; wall = LocalWall(); c.wall_time = wall
        self.authorize(); old_session = c.session
        wall.offset = -60
        self.assertEqual('DENIED', c.step())
        wall.offset = 0
        self.assertEqual('DENIED', c.step())
        self.fixture.controller = self.fixture.new_controller()
        self.assertNotEqual(old_session, self.fixture.controller.session)
        self.assertEqual('DENIED', self.submit(self.envelope))
        self.issuer.close()
        self.issuer = JavaIssuer(self.fixture, self.fixture.operator, self.fixture.node,
                                 os.environ['TEST_CLI_CLASSPATH'])
        self.assertEqual('ATTESTED', grant(self.fixture, self.issuer)['status'])

    def test_wall_clock_rollback_quarantines_without_touching_aa_or_host_clock(self):
        c = self.fixture.controller; wall = LocalWall(); c.wall_time = wall
        aa_clock = time.time
        # Replace this module binding only, never attributes on the shared time
        # module: old code's direct wall reads also see the regression, while
        # AA TLS/certificate threads and CLOCK_BOOTTIME remain unchanged.
        proxy = SimpleNamespace(time=wall, clock_gettime_ns=time.clock_gettime_ns,
                                CLOCK_BOOTTIME=time.CLOCK_BOOTTIME)
        with patch('native_control_v2.time', proxy):
            self.authorize()
            wall.offset = -60
            self.assertEqual('DENIED', c.step())
            wall.offset = 0
            self.assertEqual('DENIED', c.step(), 'clock quarantine must not revive the cached authority')
        self.assertIs(time.time, aa_clock)
        self.assertTrue(self.fixture.thread.is_alive())
        self.assertEqual(0, c.until_ns)


if __name__ == '__main__': unittest.main()
