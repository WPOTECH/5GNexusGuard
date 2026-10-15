import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from config import profile, provision_lab, provision_operator


class ProfileTests(unittest.TestCase):
    def test_selectors_reverse_and_certificate_authentication_is_mandatory(self):
        endpoint = profile()
        gateway = profile('192.0.2.2', '192.0.2.1', 'gateway.test', 'endpoint.test', True)
        self.assertIn('local_ts = 10.77.0.1/32[17/51821]', endpoint)
        self.assertIn('remote_ts = 10.77.0.1/32[17/51821]', gateway)
        self.assertEqual(endpoint.count('auth = pubkey'), 2)
        self.assertIn('version = 2', endpoint)
        self.assertIn('esp_proposals = aes256gcm16-ecp384', endpoint)
        self.assertNotIn('0.0.0.0/0', endpoint)
        for value in ('gateway.test\n auth = psk', '*', '', 'x }'):
            with self.assertRaises(ValueError):
                profile(remote_id=value)
        with self.assertRaises(ValueError):
            profile(remote='::1')

    def test_real_certificates_have_distinct_keys_and_only_test_ca_trust(self):
        with tempfile.TemporaryDirectory(prefix='dl-cert-unit-') as directory:
            state = Path(directory)
            previous = os.umask(0o077)
            try:
                provision_lab(state)
            finally:
                os.umask(previous)
            self.assertFalse((state / 'ca/ca.key').exists())
            keys = []
            for role, identity in (('e', 'endpoint.test'), ('o', 'gateway.test')):
                cert = state / role / 'x509/identity.pem'
                subprocess.run(['openssl', 'verify', '-CAfile', str(state / 'ca/ca.pem'),
                                '-verify_hostname', identity, str(cert)], check=True, capture_output=True)
                wrong = subprocess.run(['openssl', 'verify', '-CAfile', str(state / 'ca/ca.pem'),
                                        '-verify_hostname', 'wrong.test', str(cert)], capture_output=True)
                self.assertNotEqual(wrong.returncode, 0)
                key = state / role / 'private/identity.pem'
                self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                keys.append(key.read_bytes())
            self.assertNotEqual(*keys)

    def test_operator_credentials_are_explicit_and_protected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            source.chmod(0o755)
            with self.assertRaises(ValueError):
                provision_operator(source / 'unused', source)

    def test_refuses_credentials_in_checkout(self):
        with self.assertRaises(ValueError):
            provision_lab(Path(__file__).resolve().parent)
