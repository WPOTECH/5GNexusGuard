"""Ephemeral PKI and loopback-only authorization authority tests."""
import base64
import ipaddress
import http.client
import json
import os
from pathlib import Path
import ssl
import socket
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID

from authorization_aa_v2 import Authority, AuthorityServer, AttestationVerifier, canonical, request_attestation


def certificate(key, name, issuer_key=None, issuer_cert=None, ca=False):
    issuer_key = issuer_key or key
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(issuer_cert.subject if issuer_cert else subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
            key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    if name == 'server':
        builder = builder.add_extension(x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([
            x509.oid.ExtendedKeyUsageOID.SERVER_AUTH, x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    return builder.sign(issuer_key, algorithm=None)


def pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


class AATest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        ca_key = ed25519.Ed25519PrivateKey.generate()
        ca = certificate(ca_key, 'test-ca', ca=True)
        (self.root / 'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
        self.keys = {}
        self.certs = {}
        for role in ('server', 'node', 'operator', 'rogue'):
            key = ed25519.Ed25519PrivateKey.generate()
            cert = certificate(key, role, ca_key, ca)
            self.keys[role] = key
            self.certs[role] = cert
            (self.root / f'{role}.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            (self.root / f'{role}.key').write_bytes(pem_key(key))
        self.signer = ed25519.Ed25519PrivateKey.generate()
        self.node_id = self.keys['node'].public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.scope = 'service.example'
        self.server = None
        self.authority = None

    def start(self, max_workers=32, max_issuances=100000, operator_key_pin=None):
        self.authority = Authority(self.root / 'state.sqlite', self.signer,
                                   {self.node_id: self.certs['node'].fingerprint(hashes.SHA256()).hex()},
                                   self.certs['operator'].fingerprint(hashes.SHA256()).hex(),
                                   operator_key_pin=operator_key_pin, max_issuances=max_issuances)
        self.server = AuthorityServer(('127.0.0.1', 0), self.authority,
                                      str(self.root / 'server.pem'), str(self.root / 'server.key'),
                                      str(self.root / 'ca.pem'), max_workers=max_workers)
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.server = None
        if self.authority:
            self.authority.close()
            self.authority = None

    def post(self, role, path, payload):
        ctx = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        if role:
            ctx.load_cert_chain(str(self.root / f'{role}.pem'), str(self.root / f'{role}.key'))
        ctx.check_hostname = False  # Test-only loopback; production client must verify hostname.
        conn = http.client.HTTPSConnection('127.0.0.1', self.server.server_port, context=ctx, timeout=3)
        try:
            conn.request('POST', path, json.dumps(payload).encode(), {'Content-Type': 'application/json'})
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def request(self, challenge='a' * 32, observed=0, boot='b' * 32, session='c' * 32):
        return dict(version=2, nodeId=self.node_id, scope=self.scope, challenge=challenge,
                    bootId=boot, sessionId=session, lastObservedGeneration=observed)

    def transition(self, generation=1, revocation=0, epoch=1, action='authorize'):
        return self.post('operator', '/v2/authorization/transition', dict(version=2, nodeId=self.node_id,
            scope=self.scope, generation=generation, revocation=revocation, epoch=epoch, action=action))

    def test_concurrent_verifier_accepts_issuance_only_once(self):
        self.start()
        self.assertEqual(self.transition()[0], 200)
        request = self.request()
        status, envelope = self.post('node', '/v2/authorization/attest', request)
        self.assertEqual(status, 200)
        pin = self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        verifier = AttestationVerifier(pin, self.node_id, self.scope)
        verifier.challenge(request)
        real_key = verifier.key
        barrier = threading.Barrier(2)
        class ConcurrentKey:
            def verify(self, signature, message):
                try:
                    barrier.wait(timeout=0.5)
                except threading.BrokenBarrierError:
                    pass
                return real_key.verify(signature, message)
        verifier.key = ConcurrentKey()
        results = []
        workers = [threading.Thread(target=lambda: results.append(verifier.accept(envelope))) for _ in range(2)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(sorted(results), [False, True])

    def test_attestation_requires_operator_authorization_and_verifies_pinned_signature(self):
        self.start()
        req = self.request()
        self.assertEqual(self.post('node', '/v2/authorization/attest', req)[0], 403)
        self.assertEqual(self.transition()[0], 200)
        verifier = AttestationVerifier(self.signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw), self.node_id, self.scope)
        verifier.challenge(req)
        status, envelope = self.post('node', '/v2/authorization/attest', req)
        self.assertEqual(status, 200)
        self.assertTrue(verifier.accept(envelope))
        self.assertEqual(envelope['payload']['generation'], 1)
        self.assertFalse(verifier.accept(envelope))
        self.assertEqual(self.post('node', '/v2/authorization/attest', req)[0], 409)

    def test_restart_quarantines_and_requires_recovery_then_fresh_authorization(self):
        self.start()
        self.assertEqual(self.transition()[0], 200)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request())[0], 200)
        self.stop()
        self.start()
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request('d' * 32))[0], 503)
        self.assertEqual(self.transition(generation=1, epoch=2)[0], 503)
        self.assertEqual(self.transition(generation=1, epoch=1, action='recover')[0], 409)
        self.assertEqual(self.transition(generation=1, epoch=2, action='recover')[0], 200)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request('d' * 32))[0], 403)
        self.assertEqual(self.transition(generation=2, epoch=3)[0], 200)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request('d' * 32, observed=2))[0], 200)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request())[0], 409)

    def test_monotonic_transitions_revocation_and_old_generation(self):
        self.start()
        self.assertEqual(self.transition()[0], 200)
        self.assertEqual(self.transition()[0], 409)
        self.assertEqual(self.transition(generation=1, revocation=1, epoch=2, action='revoke')[0], 200)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request())[0], 403)
        self.assertEqual(self.transition(generation=2, revocation=0, epoch=3)[0], 409)
        self.assertEqual(self.transition(generation=2, revocation=1, epoch=3)[0], 200)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request(observed=3))[0], 409)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request('e' * 32, observed=2))[0], 503)

    def test_mtls_role_pins_and_missing_or_untrusted_client(self):
        self.start()
        self.assertEqual(self.post('node', '/v2/authorization/transition', dict(version=2, nodeId=self.node_id,
            scope=self.scope, generation=1, revocation=0, epoch=1, action='authorize'))[0], 403)
        self.assertEqual(self.post('rogue', '/v2/authorization/attest', self.request())[0], 403)
        self.assertEqual(self.post('operator', '/v2/authorization/attest', self.request())[0], 403)
        self.assertEqual(self.transition()[0], 200)
        with self.assertRaises((ssl.SSLError, OSError, http.client.RemoteDisconnected)):
            self.post(None, '/v2/authorization/attest', self.request())
        other_ca = certificate(ed25519.Ed25519PrivateKey.generate(), 'untrusted', ca=True)
        rogue_key = ed25519.Ed25519PrivateKey.generate()
        (self.root / 'untrusted.pem').write_bytes(certificate(rogue_key, 'untrusted-client',
            ed25519.Ed25519PrivateKey.generate(), other_ca).public_bytes(serialization.Encoding.PEM))
        # A cert not chaining to trusted CA is refused by TLS before HTTP authorization.
        ctx = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        ctx.check_hostname = False
        (self.root / 'untrusted.key').write_bytes(pem_key(rogue_key))
        ctx.load_cert_chain(str(self.root / 'untrusted.pem'), str(self.root / 'untrusted.key'))
        conn = http.client.HTTPSConnection('127.0.0.1', self.server.server_port, context=ctx, timeout=3)
        with self.assertRaises((ssl.SSLError, OSError, http.client.RemoteDisconnected)):
            conn.request('POST', '/v2/authorization/attest', b'{}', {'Content-Type': 'application/json'})
            conn.getresponse()
        conn.close()

    def test_verifier_rejects_binding_tamper_wrong_pin_expiry_and_replay(self):
        self.start()
        self.assertEqual(self.transition()[0], 200)
        req = self.request()
        status, envelope = self.post('node', '/v2/authorization/attest', req)
        self.assertEqual(status, 200)
        pin = self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        verifier = AttestationVerifier(pin, self.node_id, self.scope)
        verifier.challenge(req)
        for field, value in [('scope', 'other'), ('bootId', 'f' * 32),
                             ('sessionId', 'f' * 32), ('challenge', 'f' * 32),
                             ('epoch', 2), ('generation', 2), ('revocation', 2)]:
            forged = json.loads(json.dumps(envelope))
            forged['payload'][field] = value
            self.assertFalse(verifier.accept(forged), field)
        self.assertFalse(verifier.accept(envelope, now_ms=envelope['payload']['expiresAtMs']))
        self.assertFalse(verifier.accept({'payload': envelope['payload'], 'signature': 'bad'}))
        wrong = AttestationVerifier(self.keys['rogue'].public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw), self.node_id, self.scope)
        wrong.challenge(req)
        self.assertFalse(wrong.accept(envelope))
        self.assertTrue(verifier.accept(envelope))
        verifier.challenge(self.request(observed=1))
        self.assertFalse(verifier.accept(envelope))

    def test_persistent_issuance_quota_refuses_without_consuming_challenge(self):
        self.start(max_issuances=1)
        self.assertEqual(self.transition()[0], 200)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request())[0], 200)
        status, _ = self.post('node', '/v2/authorization/attest', self.request('d' * 32))
        self.assertEqual(status, 503)
        self.assertFalse(self.authority.quarantined)
        self.assertEqual(self.authority.db.execute('SELECT COUNT(*) FROM challenges').fetchone(), (1,))
        self.assertEqual(self.authority.db.execute('SELECT COUNT(*) FROM issuances').fetchone(), (1,))
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request())[0], 409)
        self.stop()
        self.start(max_issuances=1)
        self.assertEqual(self.transition(generation=1, epoch=2, action='recover')[0], 200)
        self.assertEqual(self.transition(generation=2, epoch=3)[0], 200)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request('e' * 32))[0], 503)
        self.assertEqual(self.authority.db.execute('SELECT COUNT(*) FROM challenges').fetchone(), (1,))

    def test_issuance_records_are_durable_and_revoked_on_transition(self):
        self.start()
        self.transition()
        first = self.post('node', '/v2/authorization/attest', self.request())[1]['payload']
        self.assertEqual(self.transition(generation=1, revocation=1, epoch=2, action='revoke')[0], 200)
        row = self.authority.db.execute('SELECT valid FROM issuances WHERE id=?', (first['issuanceId'],)).fetchone()
        self.assertEqual(row, (0,))
        self.stop()
        self.start()
        self.assertEqual(self.authority.db.execute('SELECT COUNT(*) FROM challenges').fetchone(), (1,))
        self.assertEqual(self.authority.db.execute('SELECT revocation FROM scopes').fetchone(), (1,))
        self.assertEqual(self.authority.db.execute('SELECT valid FROM issuances WHERE id=?', (first['issuanceId'],)).fetchone(), (0,))
    def test_recovery_cannot_clear_later_durability_quarantine(self):
        self.start()
        self.assertEqual(self.transition()[0], 200)
        self.stop()
        self.start()
        first_committed = threading.Event()
        release_first = threading.Event()
        original_commit = self.authority._commit
        original_sync = self.authority._sync
        commit_count = 0
        def controlled_commit(change):
            nonlocal commit_count
            commit_count += 1
            if commit_count == 2:
                self.authority._sync = lambda: (_ for _ in ()).throw(OSError('sync failed'))
            result = original_commit(change)
            if commit_count == 1:
                first_committed.set()
                release_first.wait(2)
            return result
        self.authority._commit = controlled_commit
        outcomes = []
        def first():
            try:
                outcomes.append(('first', self.transition(generation=1, epoch=2, action='recover')[0]))
            except Exception as exc:
                outcomes.append(('first-error', type(exc).__name__))
        def second():
            try:
                outcomes.append(('second', self.transition(generation=1, epoch=3, action='recover')[0]))
            except Exception as exc:
                outcomes.append(('second-error', type(exc).__name__))
        one = threading.Thread(target=first)
        two = threading.Thread(target=second)
        one.start()
        try:
            self.assertTrue(first_committed.wait(2))
            two.start()
            two.join(timeout=0.5)
        finally:
            release_first.set()
            one.join(timeout=3)
            two.join(timeout=3)
            self.authority._commit = original_commit
            self.authority._sync = original_sync
        self.assertIn(('first', 200), outcomes)
        self.assertIn(('second', 503) if ('second', 503) in outcomes else ('second', 409), outcomes)
        if ('second', 409) in outcomes:
            # Serialized recovery rejects the second request; prove a later sync
            # failure still quarantines without being undone by the first request.
            self.authority._sync = lambda: (_ for _ in ()).throw(OSError('sync failed'))
            try:
                self.assertEqual(self.transition(generation=2, epoch=4)[0], 503)
            finally:
                self.authority._sync = original_sync
        self.assertTrue(self.authority.quarantined)
        self.assertEqual(self.transition(generation=2, epoch=5)[0], 503)

    def test_fsync_failure_quarantines_without_acknowledgment(self):
        self.start()
        original = self.authority._sync
        self.authority._sync = lambda: (_ for _ in ()).throw(OSError('disk sync failed'))
        self.assertEqual(self.transition()[0], 503)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request())[0], 503)
        self.authority._sync = original
        self.assertEqual(self.transition(generation=1, epoch=2)[0], 503)

    def test_symlinked_state_parent_is_refused(self):
        real = self.root / 'real-state'
        real.mkdir(mode=0o700)
        alias = self.root / 'state-link'
        alias.symlink_to(real, target_is_directory=True)
        with self.assertRaises(ValueError):
            Authority(alias / 'state.sqlite', self.signer,
                {self.node_id: self.certs['node'].fingerprint(hashes.SHA256()).hex()},
                self.certs['operator'].fingerprint(hashes.SHA256()).hex())

    def test_database_file_is_private_at_creation_before_sqlite_uses_it(self):
        from unittest.mock import patch
        import authorization_aa_v2 as aa
        real_connect = aa.sqlite3.connect
        observed = []
        def checked_connect(path, **kwargs):
            connection = real_connect(path, **kwargs)
            observed.append(Path(path).stat().st_mode & 0o777)
            return connection
        old_umask = os.umask(0o022)
        try:
            with patch.object(aa.sqlite3, 'connect', side_effect=checked_connect):
                authority = Authority(self.root / 'new-state.sqlite', self.signer,
                    {self.node_id: self.certs['node'].fingerprint(hashes.SHA256()).hex()},
                    self.certs['operator'].fingerprint(hashes.SHA256()).hex())
                authority.close()
        finally:
            os.umask(old_umask)
        self.assertEqual(observed, [0o600])

    def test_private_database_mode_and_request_identity_mismatch(self):
        self.start()
        self.assertEqual((self.root / 'state.sqlite').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.transition()[0], 200)
        other_id = self.keys['rogue'].public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        forged = self.request()
        forged['nodeId'] = other_id
        self.assertEqual(self.post('node', '/v2/authorization/attest', forged)[0], 403)
        forged = self.request()
        forged['scope'] = 'other'
        self.assertEqual(self.post('node', '/v2/authorization/attest', forged)[0], 403)
    def test_client_uses_explicit_mtls_trust_and_response_pin(self):
        self.start()
        self.assertEqual(self.transition()[0], 200)
        req = self.request()
        pin = self.signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        verifier = AttestationVerifier(pin, self.node_id, self.scope)
        url = f'https://127.0.0.1:{self.server.server_port}/v2/authorization/attest'
        self.assertTrue(request_attestation(url, str(self.root / 'ca.pem'),
            str(self.root / 'node.pem'), str(self.root / 'node.key'), req, verifier))
        repeat = self.request(observed=1)
        self.assertFalse(request_attestation(url, str(self.root / 'ca.pem'),
            str(self.root / 'node.pem'), str(self.root / 'node.key'), repeat, verifier))
        with self.assertRaises(ValueError):
            request_attestation(url.replace('https:', 'http:'), str(self.root / 'ca.pem'),
                str(self.root / 'node.pem'), str(self.root / 'node.key'), req, verifier)
    def test_recovering_one_scope_cannot_restore_other_scope_after_restart(self):
        self.start()
        self.assertEqual(self.transition()[0], 200)
        first_scope = self.scope
        self.scope = 'second.example'
        self.assertEqual(self.transition(generation=1, epoch=1)[0], 200)
        self.stop()
        self.start()
        self.scope = first_scope
        self.assertEqual(self.transition(generation=1, epoch=2, action='recover')[0], 200)
        self.assertEqual(self.transition(generation=2, epoch=3)[0], 503)
        self.scope = 'second.example'
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request('d' * 32))[0], 503)
        self.assertEqual(self.transition(generation=1, epoch=2, action='recover')[0], 200)
        self.assertEqual(self.transition(generation=2, epoch=3)[0], 200)
    def test_silent_tcp_peer_cannot_block_other_tls_clients(self):
        self.start()
        silent = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2)
        self.addCleanup(silent.close)
        started = time.monotonic()
        self.assertEqual(self.transition()[0], 200)
        self.assertLess(time.monotonic() - started, 2)

    def test_worker_cap_refuses_silent_peer_without_spawning_and_releases_on_disconnect(self):
        self.start(max_workers=1)
        silent = socket.create_connection(('127.0.0.1', self.server.server_port), timeout=2)
        self.addCleanup(silent.close)
        deadline = time.monotonic() + 2
        while self.server.active_workers != 1 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.server.active_workers, 1)
        with self.assertRaises((ssl.SSLError, OSError, http.client.RemoteDisconnected)):
            self.transition()
        self.assertEqual(self.server.active_workers, 1)
        silent.close()
        deadline = time.monotonic() + 2
        while self.server.active_workers and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.server.active_workers, 0)
        self.assertEqual(self.transition()[0], 200)

    def test_header_trickle_cannot_hold_only_worker_past_deadline(self):
        self.start(max_workers=1)
        ctx = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        ctx.load_cert_chain(str(self.root / 'rogue.pem'), str(self.root / 'rogue.key'))
        with ctx.wrap_socket(socket.create_connection(('127.0.0.1', self.server.server_port), timeout=3),
                             server_hostname='127.0.0.1') as client:
            client.sendall(b'POST /v2/authorization/transition HTTP/1.1\r\n')
            client.sendall(b'Host: 127.0.0.1\r\n')
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                time.sleep(0.4)
                try:
                    client.sendall(b'X-Padding: x\r\n')
                except OSError:
                    break
            deadline = time.monotonic() + 1
            while self.server.active_workers and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(self.server.active_workers, 0)
        self.assertEqual(self.transition()[0], 200)

    def test_incomplete_authenticated_body_times_out_without_transition(self):
        self.start()
        ctx = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        ctx.load_cert_chain(str(self.root / 'operator.pem'), str(self.root / 'operator.key'))
        with ctx.wrap_socket(socket.create_connection(('127.0.0.1', self.server.server_port), timeout=3),
                             server_hostname='127.0.0.1') as client:
            client.settimeout(4)
            client.sendall(b'POST /v2/authorization/transition HTTP/1.1\r\n'
                           b'Host: 127.0.0.1\r\nContent-Type: application/json\r\n'
                           b'Content-Length: 100\r\n\r\n{}')
            try:
                reply = client.recv(4096)
            except socket.timeout:
                self.fail('authenticated incomplete body held a worker indefinitely')
            self.assertIn(b'HTTP/1.0 408', reply)
        self.assertEqual(self.authority.db.execute('SELECT COUNT(*) FROM scopes').fetchone(), (0,))
        self.assertEqual(self.transition()[0], 200)

    def test_empty_database_restart_requires_operator_rebootstrap(self):
        self.start()
        self.stop()
        self.start()
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request())[0], 503)
        self.assertEqual(self.transition()[0], 503)
        self.assertEqual(self.transition(generation=1, epoch=0, action='recover')[0], 400)
        self.assertEqual(self.transition(generation=1, epoch=1, action='recover')[0], 200)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request())[0], 403)
        self.assertEqual(self.transition(generation=2, epoch=2)[0], 200)

    def test_empty_scopes_with_issuance_history_cannot_rebootstrap(self):
        self.start()
        self.assertEqual(self.transition()[0], 200)
        self.assertEqual(self.post('node', '/v2/authorization/attest', self.request())[0], 200)
        self.stop()
        import sqlite3
        with sqlite3.connect(self.root / 'state.sqlite') as db:
            db.execute('DELETE FROM scopes')  # Simulated DB rollback/tamper, not an AA operation.
        self.start()
        self.assertEqual(self.transition(generation=1, epoch=1, action='recover')[0], 409)
        self.assertEqual(self.transition()[0], 503)

    def test_empty_scopes_after_prior_transition_cannot_rebootstrap(self):
        self.start()
        self.assertEqual(self.transition()[0], 200)
        self.stop()
        import sqlite3
        with sqlite3.connect(self.root / 'state.sqlite') as db:
            db.execute('DELETE FROM scopes')
        self.start()
        self.assertEqual(self.transition(generation=1, epoch=1, action='recover')[0], 409)

    def test_rollback_to_empty_database_does_not_look_pristine(self):
        self.start()
        self.stop()
        pristine = (self.root / 'state.sqlite').read_bytes()
        self.start()
        self.assertEqual(self.transition(generation=1, epoch=1, action='recover')[0], 200)
        self.assertEqual(self.transition(generation=2, epoch=2)[0], 200)
        self.stop()
        (self.root / 'state.sqlite').write_bytes(pristine)  # DB-only rollback, no AA deletion.
        self.start()
        self.assertEqual(self.transition(generation=1, epoch=1, action='recover')[0], 409)
        self.assertEqual(self.transition()[0], 503)

    def test_missing_history_marker_cannot_reenable_bootstrap(self):
        self.start()
        self.stop()
        pristine = (self.root / 'state.sqlite').read_bytes()
        self.start()
        self.assertEqual(self.transition(generation=1, epoch=1, action='recover')[0], 200)
        self.stop()
        (self.root / 'state.sqlite').write_bytes(pristine)
        (self.root / 'state.sqlite.used').unlink()  # Simulated local marker loss.
        self.start()
        self.assertEqual(self.transition(generation=1, epoch=1, action='recover')[0], 409)

    def test_distinct_operator_certificate_reusing_node_key_cannot_transition(self):
        ca_key = ed25519.Ed25519PrivateKey.generate()
        ca = certificate(ca_key, 'second-ca', ca=True)
        # A second valid client certificate has a distinct DER fingerprint but the same public key.
        reused = certificate(self.keys['node'], 'operator', ca_key, ca)
        self.assertNotEqual(reused.fingerprint(hashes.SHA256()), self.certs['node'].fingerprint(hashes.SHA256()))
        (self.root / 'operator.pem').write_bytes(reused.public_bytes(serialization.Encoding.PEM))
        (self.root / 'operator.key').write_bytes(pem_key(self.keys['node']))
        # Trust both valid certificate chains for this local test.
        with (self.root / 'ca.pem').open('ab') as out:
            out.write(ca.public_bytes(serialization.Encoding.PEM))
        self.certs['operator'] = reused
        self.start()
        self.assertEqual(self.transition()[0], 403)
        self.assertEqual(self.authority.db.execute('SELECT COUNT(*) FROM scopes').fetchone(), (0,))

    def test_configured_operator_public_key_pin_accepts_matching_cert(self):
        operator_id = self.keys['operator'].public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.start(operator_key_pin=operator_id)
        self.assertEqual(self.transition()[0], 200)

    def test_configured_operator_public_key_pin_rejects_valid_cert_with_wrong_key(self):
        rogue_id = self.keys['rogue'].public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.start(operator_key_pin=rogue_id)
        self.assertEqual(self.transition()[0], 403)
        self.assertEqual(self.authority.db.execute('SELECT COUNT(*) FROM scopes').fetchone(), (0,))

    def test_explicit_operator_key_pin_refuses_node_identity_before_database_creation(self):
        with self.assertRaises(ValueError):
            Authority(self.root / 'bad-operator-key.sqlite', self.signer,
                {self.node_id: self.certs['node'].fingerprint(hashes.SHA256()).hex()},
                self.certs['operator'].fingerprint(hashes.SHA256()).hex(),
                operator_key_pin=self.node_id)
        self.assertFalse((self.root / 'bad-operator-key.sqlite').exists())

    def test_operator_pin_must_not_equal_node_client_pin(self):
        pin = self.certs['node'].fingerprint(hashes.SHA256()).hex()
        with self.assertRaises(ValueError):
            Authority(self.root / 'same-role.sqlite', self.signer, {self.node_id: pin}, pin)
        self.assertFalse((self.root / 'same-role.sqlite').exists())

    def test_signing_key_must_not_equal_node_client_key(self):
        with self.assertRaises(ValueError):
            Authority(self.root / 'other.sqlite', self.keys['node'],
                {self.node_id: self.certs['node'].fingerprint(hashes.SHA256()).hex()},
                self.certs['operator'].fingerprint(hashes.SHA256()).hex())


if __name__ == '__main__':
    unittest.main()
