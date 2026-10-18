"""Isolated supervisor control-plane tests; no namespaces or packet authorization."""
import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from admission_v2 import operation_bytes
from test_admission_v2 import pub, AdmissionTests
from test_authorization_aa_v2 import AATest
from issuance_v2 import canonical, node_message


class ControlTests(AdmissionTests):
    def setUp(self):
        super().setUp()
        self.private = Path(self.temp.name)
        os.chmod(self.private, 0o700)

    def controller(self, request=None):
        from native_control_v2 import Controller
        return Controller(self.private, {k:self.scope[k] for k in
                          ('serviceId','clientNodeId','ownerNodeId','resource')}, pub(self.op), pub(self.node),
                          self.supervisor, 'https://127.0.0.1:1/v2/authorization/attest',
                          str(self.private/'ca'), str(self.private/'node.crt'),
                          str(self.private/'node.key'), pub(Ed25519PrivateKey.generate()),
                          request_attestation=request)

    def test_fresh_session_boot_and_denial_when_aa_unavailable(self):
        from native_control_v2 import boot_id
        c = self.controller(request=lambda *a: False)
        self.assertEqual(boot_id(), c.admission.scope['bootId'])
        self.assertEqual('DENIED', c.step())
        self.assertNotEqual(c.session, self.controller().session)
        self.assertEqual('DENIED', self.controller().step())

    def test_private_spool_rejects_symlink_and_world_readable_file(self):
        c = self.controller(request=lambda *a: False)
        target = self.private/'outside'
        target.write_text('{}')
        (self.private/'inbox.json').symlink_to(target)
        self.assertEqual('DENIED', c.step())
        (self.private/'inbox.json').unlink()
        (self.private/'inbox.json').write_text('{}')
        os.chmod(self.private/'inbox.json', 0o644)
        self.assertEqual('DENIED', c.step())

    def test_mismatched_node_pin_and_scope_refused_at_start(self):
        from native_control_v2 import Controller
        with self.assertRaises(ValueError):
            Controller(self.private, dict(self.scope, ownerNodeId='f'*64), pub(self.op), pub(self.node),
                self.supervisor, 'https://127.0.0.1:1/v2/authorization/attest',
                'ca', 'cert', 'key', pub(Ed25519PrivateKey.generate()))

    def test_supervisor_operator_path_never_enables_packets_on_failure(self):
        import native
        class Topology:
            credentials = object()
            def __init__(self): self.calls = []
            def authorize(self, value): self.calls.append(value)
        t = Topology()
        with patch.object(native, 'control_step', side_effect=RuntimeError('offline')):
            native.renew_authorization(t, object(), True)
        self.assertEqual([0], t.calls)


class IntegratedControlTests(unittest.TestCase):
    start = AATest.start
    stop = AATest.stop
    post = AATest.post
    request = AATest.request
    transition = AATest.transition
    def setUp(self):
        AATest.setUp(self)
        self.operator = Ed25519PrivateKey.generate()
        self.supervisor = Ed25519PrivateKey.generate()
        os.chmod(self.root, 0o700)
        self.scope_data = dict(serviceId='svc', clientNodeId='a'*64,
                               ownerNodeId=self.node_id, resource='tcp:10.80.0.2:8080')
        from native_control_v2 import aa_scope_for
        self.scope = aa_scope_for(self.scope_data)
        self.start()
        self.assertEqual(200, self.transition()[0])

    def controller(self):
        from native_control_v2 import Controller
        return Controller(self.root, self.scope_data, pub(self.operator), bytes.fromhex(self.node_id),
            self.supervisor, f'https://127.0.0.1:{self.server.server_port}/v2/authorization/attest',
            str(self.root/'ca.pem'), str(self.root/'node.pem'), str(self.root/'node.key'),
            pub(self.signer))

    def submit(self, data):
        from native_control_v2 import atomic_private_write
        atomic_private_write(self.root/'inbox.json', json.dumps(data).encode())

    def recover(self, controller):
        challenge = json.loads((self.root/'challenge.json').read_text())
        op = dict(action='RECOVER', **{k: challenge[k] for k in
                   ('bootId', 'sessionId', 'nonce', 'serviceId', 'clientNodeId', 'ownerNodeId', 'resource')},
                  generation=controller.admission.generation+1)
        self.submit(dict(operation=op, signature=base64.b64encode(
            self.operator.sign(operation_bytes(op))).decode()))
        self.assertEqual('DENIED', controller.step())

    def approve(self, controller):
        challenge = json.loads((self.root/'challenge.json').read_text())
        now = __import__('time').clock_gettime_ns(__import__('time').CLOCK_BOOTTIME)
        p = dict(version=2, transport='IKEV2_ESP_WIREGUARD', **controller.scope,
                 nonce=challenge['nonce'], generation=controller.admission.generation+1,
                 issuedBoottimeNs=now-1000000, deadlineBoottimeNs=now+2_000_000_000,
                 issuanceId=os.urandom(16).hex(), issuerId=pub(self.operator).hex())
        msg = canonical(p)
        op_sig = self.operator.sign(msg)
        envelope = dict(payload=p, operatorSignature=base64.b64encode(op_sig).decode(),
            nodeSignature=base64.b64encode(self.keys['node'].sign(node_message(msg, op_sig))).decode())
        self.submit(dict(envelope=envelope))
        return controller.step(), envelope

    def test_aa_scope_binds_client_owner_service_and_resource(self):
        from native_control_v2 import aa_scope_for
        baseline = aa_scope_for(self.scope_data)
        self.assertEqual(len(baseline), 64)
        for name, replacement in (('serviceId', 'other.service'),
                                  ('clientNodeId', 'f'*64),
                                  ('ownerNodeId', 'e'*64),
                                  ('resource', 'tcp:10.80.0.3:8080')):
            altered = dict(self.scope_data, **{name: replacement})
            self.assertNotEqual(baseline, aa_scope_for(altered))
        self.assertEqual(self.controller().aa_scope, baseline)

    def test_reconnect_uses_fresh_aa_challenge_and_does_not_extend_original_grant(self):
        c = self.controller()
        self.recover(c)
        self.assertEqual('ATTESTED', self.approve(c)[0])
        original_deadline = c.admission.deadline
        original_floor = c.floors
        c.until_ns = 0  # A bounded AA response expired; original V2 grant remains live.
        self.assertEqual('ATTESTED', c.step())
        self.assertEqual(original_deadline, c.admission.deadline)
        self.assertEqual(original_floor, c.floors)

    def test_real_mtls_aa_requires_local_recovery_and_approval_then_restart_denies(self):
        c = self.controller()
        self.assertEqual('DENIED', c.step())
        self.recover(c)
        self.assertEqual('ATTESTED', self.approve(c)[0])
        self.assertEqual('ATTESTED', c.step())
        self.assertEqual('DENIED', self.controller().step())
        self.assertEqual((1, 0, 1), c.floors)

    def test_aa_restart_quarantine_then_operator_recovery_requires_new_attestation(self):
        c = self.controller()
        self.recover(c)
        self.assertEqual('ATTESTED', self.approve(c)[0])
        original_deadline = c.admission.deadline
        self.stop()
        self.start()
        c.url = f'https://127.0.0.1:{self.server.server_port}/v2/authorization/attest'
        c.until_ns = 0
        self.assertEqual('DENIED', c.step())
        self.assertEqual(200, self.transition(generation=1, epoch=2, action='recover')[0])
        self.assertEqual('DENIED', c.step())
        self.assertEqual(200, self.transition(generation=2, epoch=3)[0])
        self.assertEqual('ATTESTED', c.step())
        self.assertEqual(original_deadline, c.admission.deadline)
        self.assertEqual((2, 0, 3), c.floors)

    def test_negative_control_aa_revoke_does_not_instantly_cancel_delivered_attestation(self):
        c = self.controller()
        self.recover(c)
        self.assertEqual('ATTESTED', self.approve(c)[0])
        self.assertEqual(200, self.transition(generation=1, revocation=1, epoch=2, action='revoke')[0])
        self.assertEqual('ATTESTED', c.step())  # Existing signed response remains locally live.
        c.until_ns = 0  # The next mandatory re-attestation learns the revocation.
        self.assertEqual('DENIED', c.step())

    def test_negative_control_aa_outage_does_not_instantly_cancel_delivered_attestation(self):
        c = self.controller()
        self.recover(c)
        self.assertEqual('ATTESTED', self.approve(c)[0])
        self.stop()
        self.assertEqual('ATTESTED', c.step())  # No synchronous AA health check yet.
        c.until_ns = 0
        self.assertEqual('DENIED', c.step())

    def test_aa_unavailability_denies_even_with_valid_local_approval(self):
        c = self.controller()
        self.recover(c)
        self.stop()
        self.assertEqual('DENIED', self.approve(c)[0])

    def test_short_aa_attestation_expiry_is_not_extended_by_supervisor(self):
        c = self.controller()
        self.recover(c)
        original = c.request_attestation
        def shortened(*args):
            verifier = args[-1]
            result = original(*args)
            if result:
                verifier.accepted_expires_at_ms = int(__import__('time').time()*1000) + 1
            return result
        c.request_attestation = shortened
        self.assertEqual('DENIED', self.approve(c)[0])
        self.assertLessEqual(c.until_ms, int(__import__('time').time()*1000))
        self.assertEqual('DENIED', c.step())

    def test_aa_floor_ahead_quarantines_and_replay_cannot_restore(self):
        c = self.controller()
        self.recover(c)
        self.assertEqual('ATTESTED', self.approve(c)[0])
        self.assertEqual(200, self.transition(generation=2, epoch=2)[0])
        restarted = self.controller()
        self.assertEqual('DENIED', restarted.step())
        self.assertEqual((1, 0, 1), restarted.floors)

    def test_highwater_tamper_immediately_denies_in_process(self):
        c = self.controller()
        self.recover(c)
        self.assertEqual('ATTESTED', self.approve(c)[0])
        (self.root/'aa-highwater.json').write_text('{}')
        self.assertEqual('DENIED', c.step())
