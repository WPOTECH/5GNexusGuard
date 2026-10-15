import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from native import remaining_ms, read_lease, ns_sysctl


class NamespaceSetupTests(unittest.TestCase):
    def test_sysctl_uses_private_mount_namespace_and_named_network_namespace(self):
        for role, forwarding in [('e', False), ('o', True), ('i', True), ('r', False)]:
            with patch('native.command') as run:
                ns_sysctl(role, forwarding)
            args = run.call_args.args
            self.assertEqual(args[:7], ('ip', 'netns', 'exec', 'dlip-' + role,
                                        'unshare', '-m', 'sh'))
            self.assertEqual(args[7], '-c')
            self.assertIn('mount -t proc proc /proc && sysctl -qw', args[8])
            self.assertIn('net.ipv4.ip_forward=' + ('1' if forwarding else '0'), args[8])
            self.assertIn('net.ipv4.conf.all.rp_filter=0', args[8])


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.lease = dict(version=2, transport='IKEV2_ESP_WIREGUARD', serviceId='svc', clientNodeId='client', ownerNodeId='owner',
                          allowed=True, expiresAtMs=4000)

    def remaining(self, lease):
        return remaining_ms(lease, 'svc', 'client', 'owner', 1000)

    def test_allow_and_expiry(self):
        self.assertEqual(3000, self.remaining(self.lease))
        for deadline in (1000, 999, 4001, True, '4000', None):
            self.assertEqual(0, self.remaining(dict(self.lease, expiresAtMs=deadline)))

    def test_denial_mismatch_and_malformed(self):
        for key, value in [('allowed', False), ('allowed', 'true'), ('version', True),
                           ('version', 1), ('transport', 'WIREGUARD_WIREGUARD'), ('serviceId', 'other'), ('clientNodeId', 'other'),
                           ('ownerNodeId', 'other')]:
            self.assertEqual(0, self.remaining(dict(self.lease, **{key: value})))
        for value in (None, [], {}, 'bad'):
            self.assertEqual(0, self.remaining(value))

    def test_protected_file_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).resolve()
            path = directory / 'lease.json'
            path.write_text(json.dumps(self.lease))
            path.chmod(0o600)
            self.assertEqual(self.lease, read_lease(path, os.getuid()))
            path.chmod(0o644)
            with self.assertRaises(ValueError): read_lease(path, os.getuid())
            path.chmod(0o600)
            with self.assertRaises(ValueError): read_lease(path, os.getuid() + 1)
            link = directory / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError): read_lease(link, os.getuid())
            directory.chmod(0o755)
            with self.assertRaises(ValueError): read_lease(path, os.getuid())


if __name__ == '__main__':
    unittest.main()
