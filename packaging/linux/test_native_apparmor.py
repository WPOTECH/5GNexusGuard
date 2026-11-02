import os
from pathlib import Path
import tempfile
import unittest
from native_apparmor import include


@unittest.skipUnless(os.getuid()==0,'run policy tests in isolated root container')
class PolicyTests(unittest.TestCase):
    def test_preserves_operator_content_and_includes_only_once(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'local';path.write_text('# existing operator policy\n');path.chmod(0o600)
            line='#include if exists <local/5gnexusguard-native-charon>'
            include(path,line);include(path,line)
            self.assertTrue(path.read_text().startswith('# existing operator policy\n'))
            self.assertEqual(1,path.read_text().splitlines().count(line))
            self.assertEqual(0o600,path.stat().st_mode&0o777)
    def test_link_cannot_redirect_policy_append(self):
        with tempfile.TemporaryDirectory() as directory:
            target=Path(directory)/'target';target.write_text('untouched')
            link=Path(directory)/'link';link.symlink_to(target)
            with self.assertRaises(OSError):include(link,'anything')
            self.assertEqual('untouched',target.read_text())
