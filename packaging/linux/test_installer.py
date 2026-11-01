"""Installer command regression; run as root only inside an isolated container/VM.

All package tools are private stubs. No package, service or network operation runs.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.geteuid() == 0, 'installer requires root; use isolated test container')
class InstallerTests(unittest.TestCase):
    def test_offline_archive_avoids_apt_path_failure_and_preserves_failed_preflight(self):
        installer = Path(__file__).resolve().parents[2] / 'install.sh'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / 'local product.deb'
            package.write_bytes(b'private stub archive')
            calls = root / 'calls.jsonl'
            stub = '''#!/usr/bin/python3
import json,os,pathlib,sys
name=pathlib.Path(sys.argv[0]).name
with open(os.environ['P2_INSTALL_CALLS'],'a') as f:f.write(json.dumps([name,*sys.argv[1:]])+'\\n')
if name=='dpkg-deb':print('defenderlink-mesh')
if name=='apt-get':sys.exit(100)
if name=='dpkg' and '--no-act' in sys.argv:sys.exit(int(os.environ.get('P2_PREFLIGHT_EXIT','0')))
'''
            for name in ('dpkg-deb', 'dpkg', 'apt-get'):
                tool = root / name
                tool.write_text(stub)
                tool.chmod(0o755)
            env = dict(os.environ, PATH=str(root)+':'+os.environ['PATH'], P2_INSTALL_CALLS=str(calls))
            result = subprocess.run(['bash', str(installer), '--package', str(package)],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual([
                ['dpkg-deb', '-f', str(package), 'Package'],
                ['dpkg', '--no-act', '--install', str(package)],
                ['dpkg', '--install', str(package)],
            ], [json.loads(line) for line in calls.read_text().splitlines()])
            calls.unlink()
            env['P2_PREFLIGHT_EXIT'] = '7'
            failed = subprocess.run(['bash', str(installer), '--package', str(package)],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(7, failed.returncode)
            self.assertEqual(2, len(calls.read_text().splitlines()))


if __name__ == '__main__':
    unittest.main()
