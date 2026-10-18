"""Disconnected admission tests: synthetic keys, no packet gate or production state."""
import base64
import os
from pathlib import Path
import tempfile
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from admission_v2 import Admission, challenge_bytes, operation_bytes
from issuance_v2 import canonical, node_message


def pub(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'journal'
        self.op, self.node, self.supervisor = (Ed25519PrivateKey.generate() for _ in range(3))
        self.boot = '123e4567-e89b-12d3-a456-426614174000'
        self.scope = dict(serviceId='svc', clientNodeId='a'*64, ownerNodeId=pub(self.node).hex(),
                          bootId=self.boot, resource='tcp:10.80.0.2:8080')
        self.now = 1_000_000_000

    def admission(self, boot=None):
        return Admission(self.path, pub(self.op), pub(self.node), pub(self.supervisor),
                         dict(self.scope, bootId=boot or self.boot), 'session-1')

    def challenge(self, a):
        return a.challenge(self.supervisor.sign, max(self.now, a.last_now or 0))

    def envelope(self, challenge, generation=1, issuance='d'*32):
        p = dict(version=2, transport='IKEV2_ESP_WIREGUARD', **self.scope,
                 nonce=challenge['nonce'], generation=generation,
                 issuedBoottimeNs=self.now, deadlineBoottimeNs=self.now+2_000_000_000,
                 issuanceId=issuance, issuerId=pub(self.op).hex())
        m = canonical(p)
        approval = self.op.sign(m)
        return dict(payload=p, operatorSignature=base64.b64encode(approval).decode(),
                    nodeSignature=base64.b64encode(self.node.sign(node_message(m, approval))).decode())

    def approve(self, a, action='RECOVER'):
        c = self.challenge(a)
        op = dict(action=action, bootId=self.boot, sessionId='session-1', nonce=c['nonce'],
                  generation=a.generation + 1, serviceId='svc', clientNodeId='a'*64,
                  ownerNodeId=pub(self.node).hex(), resource=self.scope['resource'])
        return a.apply_operation(op, self.op.sign(operation_bytes(op)), max(self.now, a.last_now or 0))

    def test_malformed_unsigned_input_does_not_crash_admission(self):
        a = self.admission(); self.approve(a)
        self.challenge(a)
        self.assertIsNone(a.accept({'payload': {'issuanceId': []}}, self.now))
        self.assertEqual('PENDING_FRESH_APPROVAL', a.state(self.now))

    def test_world_writable_journal_parent_rejects_recovery(self):
        os.chmod(self.path.parent, 0o777)
        a = self.admission()
        self.assertFalse(self.approve(a))
        self.assertEqual('DENIED', a.state(self.now))
        self.assertFalse(self.path.exists())

    def test_short_journal_write_never_transitions_to_pending_or_authorized(self):
        from unittest.mock import patch
        a = self.admission()
        c = self.challenge(a)
        op = dict(action='RECOVER', bootId=self.boot, sessionId='session-1', nonce=c['nonce'],
                  generation=1, serviceId='svc', clientNodeId='a'*64,
                  ownerNodeId=pub(self.node).hex(), resource=self.scope['resource'])
        with patch('admission_v2.os.write', return_value=0):
            self.assertFalse(a.apply_operation(op, self.op.sign(operation_bytes(op)), self.now))
        self.assertEqual('DENIED', a.state(self.now))

    def test_missing_state_requires_signed_recovery_then_new_allow(self):
        a = self.admission()
        self.assertEqual('DENIED', a.state(self.now))
        c = self.challenge(a)
        self.assertIsNone(a.accept(self.envelope(c), self.now))
        self.assertFalse(a.apply_operation(dict(action='RECOVER'), b'0'*64, self.now))
        self.assertTrue(self.approve(a))
        self.assertEqual('PENDING_FRESH_APPROVAL', a.state(self.now))
        c = self.challenge(a)
        self.assertEqual(self.now+2_000_000_000, a.accept(self.envelope(c, 2), self.now+1))
        self.assertEqual('AUTHORIZED', a.state(self.now+1))
        self.assertEqual('EXPIRED', a.state(self.now+2_000_000_000))

    def test_restart_quarantines_and_rejects_old_approval(self):
        a = self.admission(); self.approve(a)
        c = self.challenge(a); envelope = self.envelope(c, 2)
        self.assertIsNotNone(a.accept(envelope, self.now+1))
        b = self.admission()
        self.assertEqual('DENIED', b.state(self.now+1))
        self.assertIsNone(b.accept(envelope, self.now+1))
        self.assertTrue(self.approve(b))
        self.assertEqual('PENDING_FRESH_APPROVAL', b.state(self.now+1))
        self.assertIsNone(b.accept(envelope, self.now+1))

    def test_revoke_is_signed_separate_and_replay_rejected(self):
        a = self.admission(); self.approve(a)
        c = self.challenge(a); self.assertIsNotNone(a.accept(self.envelope(c, 2), self.now+1))
        c = self.challenge(a)
        op = dict(action='REVOKE', bootId=self.boot, sessionId='session-1', nonce=c['nonce'],
                  generation=3, serviceId='svc', clientNodeId='a'*64,
                  ownerNodeId=pub(self.node).hex(), resource=self.scope['resource'])
        sig = self.op.sign(operation_bytes(op))
        self.assertFalse(a.apply_operation(dict(op, action='ALLOW'), sig, self.now+1))
        self.assertTrue(a.apply_operation(op, sig, self.now+1))
        self.assertEqual('REVOKED', a.state(self.now+1))
        self.assertFalse(a.apply_operation(op, sig, self.now+1))
        self.assertTrue(self.approve(a))
        self.assertEqual('PENDING_FRESH_APPROVAL', a.state(self.now+1))
        b = self.admission(); self.assertFalse(b.apply_operation(op, sig, self.now+1))

    def test_tamper_loss_reboot_and_clock_rollback_quarantine(self):
        a = self.admission(); self.approve(a)
        c = self.challenge(a); self.assertIsNotNone(a.accept(self.envelope(c, 2), self.now+1))
        self.assertEqual('DENIED', self.admission('123e4567-e89b-12d3-a456-426614174001').state(self.now+1))
        self.assertEqual('DENIED', a.state(self.now-1))
        self.path.write_bytes(self.path.read_bytes()[:-4] + b'xxxx')
        damaged = self.admission()
        self.assertEqual('DENIED', damaged.state(self.now+1))
        self.assertTrue(self.approve(damaged))
        self.assertEqual('PENDING_FRESH_APPROVAL', damaged.state(self.now+1))
        self.assertTrue(list(self.path.parent.glob('journal.corrupt-*')))
        self.path.unlink()
        self.assertEqual('DENIED', self.admission().state(self.now+1))

    def test_whole_journal_rollback_never_reactivates_a_grant(self):
        a = self.admission(); self.approve(a)
        old_snapshot = self.path.read_bytes()
        c = self.challenge(a); grant = self.envelope(c, 2)
        self.assertIsNotNone(a.accept(grant, self.now + 1))
        self.path.write_bytes(old_snapshot)  # internally consistent but older history
        self.assertEqual('DENIED', a.state(self.now + 1))
        self.assertIsNone(a.accept(grant, self.now + 1))
        restarted = self.admission()
        self.assertEqual('DENIED', restarted.state(self.now + 1))
        self.assertIsNone(restarted.accept(grant, self.now + 1))

    def test_live_journal_reseal_does_not_keep_grant_active(self):
        import hashlib
        import json
        a = self.admission(); self.approve(a)
        c = self.challenge(a); self.assertIsNotNone(a.accept(self.envelope(c, 2), self.now+1))
        lines = self.path.read_text().splitlines()
        event = json.loads(lines[-1]); event['event']['generation'] = 9
        body = json.dumps(event['event'], sort_keys=True, separators=(',', ':')).encode()
        event['digest'] = hashlib.sha256(event['previous'].encode() + body).hexdigest()
        lines[-1] = json.dumps(event, sort_keys=True, separators=(',', ':'))
        self.path.write_text('\n'.join(lines) + '\n')
        self.assertEqual('DENIED', a.state(self.now+1))

    def test_forgery_scope_generation_duplicate_and_delay(self):
        a = self.admission(); self.approve(a)
        c = self.challenge(a); e = self.envelope(c, 2)
        forged = dict(e, operatorSignature=base64.b64encode(self.node.sign(canonical(e['payload']))).decode())
        self.assertIsNone(a.accept(forged, self.now+1))
        self.assertIsNone(a.accept(self.envelope(c, 1), self.now+1))
        self.assertIsNone(a.accept(dict(e, payload=dict(e['payload'], serviceId='other')), self.now+1))
        self.assertIsNotNone(a.accept(e, self.now+1))
        c = self.challenge(a)
        self.assertIsNone(a.accept(self.envelope(c, 3), self.now+1))  # same issuance ID
        self.assertIsNone(a.accept(self.envelope(c, 3, 'e'*32), self.now+3_000_000_000))


if __name__ == '__main__':
    unittest.main()
