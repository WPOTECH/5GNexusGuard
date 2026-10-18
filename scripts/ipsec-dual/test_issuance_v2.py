"""Standalone authorization protocol tests; no network or host firewall changes."""
import base64
import copy
import time
import unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from issuance_v2 import canonical, node_message, verify, ChallengeVerifier


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class IssuanceTests(unittest.TestCase):
    def setUp(self):
        self.operator = Ed25519PrivateKey.generate()
        self.node = Ed25519PrivateKey.generate()
        self.now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        self.scope = dict(serviceId='svc', clientNodeId='a' * 64, ownerNodeId=public(self.node).hex(),
                          bootId='123e4567-e89b-12d3-a456-426614174000', resource='tcp:10.80.0.2:8080')
        self.nonce = 'c' * 32
        self.payload = dict(version=2, transport='IKEV2_ESP_WIREGUARD', **self.scope,
                            nonce=self.nonce, generation=7, issuedBoottimeNs=self.now,
                            deadlineBoottimeNs=self.now + 2_000_000_000,
                            issuanceId='d' * 32, issuerId=public(self.operator).hex())
        self.envelope = self.sign()

    def sign(self):
        payload = canonical(self.payload)
        operator_sig = self.operator.sign(payload)
        return dict(payload=copy.deepcopy(self.payload),
                    operatorSignature=base64.b64encode(operator_sig).decode(),
                    nodeSignature=base64.b64encode(self.node.sign(node_message(payload, operator_sig))).decode())

    def check(self, envelope=None, **kwargs):
        return verify(envelope or self.envelope, public(self.operator), public(self.node),
                      self.scope, self.nonce, 6, kwargs.get('now_ns', self.now + 1_000_000))

    def test_claiming_an_unrelated_owner_key_is_denied(self):
        payload = dict(self.payload, ownerNodeId='b' * 64)
        message = canonical(payload)
        approval = self.operator.sign(message)
        envelope = dict(payload=payload, operatorSignature=base64.b64encode(approval).decode(),
                        nodeSignature=base64.b64encode(self.node.sign(node_message(message, approval))).decode())
        scope = dict(self.scope, ownerNodeId='b' * 64)
        self.assertIsNone(verify(envelope, public(self.operator), public(self.node), scope,
                                 self.nonce, 6, self.now + 1_000_000))

    def test_operator_and_node_pins_must_be_distinct(self):
        payload = dict(self.payload, ownerNodeId=public(self.node).hex(), issuerId=public(self.node).hex())
        message = canonical(payload)
        approval = self.node.sign(message)
        envelope = dict(payload=payload, operatorSignature=base64.b64encode(approval).decode(),
                        nodeSignature=base64.b64encode(self.node.sign(node_message(message, approval))).decode())
        scope = dict(self.scope, ownerNodeId=public(self.node).hex())
        self.assertIsNone(verify(envelope, public(self.node), public(self.node), scope,
                                 self.nonce, 6, self.now + 1_000_000))
        with self.assertRaises(ValueError):
            ChallengeVerifier(public(self.node), public(self.node), scope, 6)

    def test_valid_both_signatures_and_fixed_deadline(self):
        self.assertEqual(self.payload['deadlineBoottimeNs'], self.check())
        self.assertEqual(self.payload['deadlineBoottimeNs'], self.check(now_ns=self.now + 1_500_000_000))

    def test_forged_and_altered_payload_denied(self):
        altered = copy.deepcopy(self.envelope)
        altered['payload']['generation'] += 1
        self.assertIsNone(self.check(altered))
        forged = copy.deepcopy(self.envelope)
        forged['operatorSignature'] = base64.b64encode(self.node.sign(canonical(self.payload))).decode()
        self.assertIsNone(self.check(forged))
        forged = copy.deepcopy(self.envelope)
        forged['nodeSignature'] = forged['operatorSignature']
        self.assertIsNone(self.check(forged))

    def test_replay_wrong_scope_reboot_expired_and_delayed(self):
        for change in ({'nonce': 'd' * 32}, {'bootId': '123e4567-e89b-12d3-a456-426614174001'},
                       {'serviceId': 'other'}, {'clientNodeId': 'd' * 64}, {'ownerNodeId': 'd' * 64}):
            scope = dict(self.scope)
            nonce = change.pop('nonce', self.nonce)
            scope.update(change)
            self.assertIsNone(verify(self.envelope, public(self.operator), public(self.node),
                                     scope, nonce, 6, self.now + 1_000_000))
        self.assertIsNone(verify(self.envelope, public(self.operator), public(self.node),
                                 self.scope, self.nonce, 7, self.now + 1_000_000))
        self.assertIsNone(self.check(now_ns=self.payload['deadlineBoottimeNs']))
        self.assertIsNone(self.check(now_ns=self.now + 4_000_000_000))

    def test_duplicate_issuance_id_rejected_even_with_new_nonce_and_generation(self):
        verifier = ChallengeVerifier(public(self.operator), public(self.node), self.scope, 6)
        verifier.challenge(self.nonce)
        self.assertEqual(self.payload['deadlineBoottimeNs'], verifier.accept(self.envelope, self.now + 1_000_000))
        self.payload['nonce'] = 'e' * 32
        self.payload['generation'] = 8
        duplicate_id = self.sign()
        verifier.challenge('e' * 32)
        self.assertIsNone(verifier.accept(duplicate_id, self.now + 1_000_000))

    def test_restart_requires_new_challenge_and_consumes_once(self):
        verifier = ChallengeVerifier(public(self.operator), public(self.node), self.scope, 6)
        verifier.challenge(self.nonce)
        self.assertEqual(self.payload['deadlineBoottimeNs'], verifier.accept(self.envelope, self.now + 1_000_000))
        self.assertIsNone(verifier.accept(self.envelope, self.now + 1_000_000))
        restarted = ChallengeVerifier(public(self.operator), public(self.node), self.scope, 6)
        self.assertIsNone(restarted.accept(self.envelope, self.now + 1_000_000))
        restarted.challenge('d' * 32)
        self.assertIsNone(restarted.accept(self.envelope, self.now + 1_000_000))

    def test_operator_entry_point_never_promotes_legacy_or_standalone_envelope(self):
        from native import renew_authorization
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        args = SimpleNamespace(lease=None, ledger_uid=1, service='svc', client='a' * 64, owner='b' * 64)
        topology = Mock()
        legacy = dict(version=2, transport='IKEV2_ESP_WIREGUARD', allowed=True,
                      serviceId='svc', clientNodeId=args.client, ownerNodeId=args.owner,
                      expiresAtMs=time.time_ns() // 1_000_000 + 2000)
        for record in (legacy, self.envelope):
            with patch('native.read_lease', return_value=record):
                renew_authorization(topology, args, True)
                topology.authorize.assert_called_with(0)

    def test_canonical_cross_language_fixture(self):
        payload = dict(self.payload, issuedBoottimeNs=1_000_000_000, deadlineBoottimeNs=2_000_000_000)
        expected = ('DEFENDERLINK-NATIVE-ISSUANCE-V2\nversion=2\ntransport=IKEV2_ESP_WIREGUARD\n'
                    'serviceId=svc\nclientNodeId=' + 'a' * 64 + '\nownerNodeId=' + self.scope['ownerNodeId']
                    + '\nbootId=123e4567-e89b-12d3-a456-426614174000\nnonce=' + 'c' * 32
                    + '\ngeneration=7\nissuedBoottimeNs=1000000000\ndeadlineBoottimeNs=2000000000'
                    + '\nresource=tcp:10.80.0.2:8080\nissuanceId=' + 'd' * 32
                    + '\nissuerId=' + str(self.payload['issuerId']) + '\n')
        self.assertEqual(expected.encode('ascii'), canonical(payload))

    def test_canonical_refuses_unknown_or_invalid_fields(self):
        for change in ({'extra': 1}, {'generation': True}, {'deadlineBoottimeNs': self.now},
                       {'nonce': 'xyz'}, {'serviceId': 'svc\nforged'}, {'issuedBoottimeNs': self.now + 3_000_000_000}):
            payload = dict(self.payload, **change)
            with self.assertRaises(ValueError):
                canonical(payload)
