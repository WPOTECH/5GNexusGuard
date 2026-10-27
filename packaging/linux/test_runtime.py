"""Nonprivileged deployment negative controls; no service/network operations."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('linux_runtime',Path(__file__).with_name('runtime.py'))
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.path=self.root/'node.json';self.write(runtime.DEFAULT)
    def tearDown(self):self.temp.cleanup()
    def write(self,value):
        self.path.write_text(json.dumps(value));self.path.chmod(0o644)
    def test_standard_default_and_explicit_native_no_fallback(self):
        cfg=runtime.read_config(self.path)
        cmd=runtime.java_command(cfg,Path('/opt/defenderlink/lib/defenderlink-mesh.jar'))
        self.assertIn('-Dmesh.access.mode=STANDARD',cmd)
        self.assertIn('-Dmesh.tunnel.config-dir=/etc/wireguard/defenderlink',cmd)
        cfg['mode']='DUAL_TUNNEL'
        with self.assertRaisesRegex(ValueError,'not yet qualified'):runtime.java_command(cfg,Path('/unused'))
    def test_invalid_or_production_configuration_denies(self):
        for edit in ({'mode':'STANDARD '},{'mode':'TYPO'},{'production_admission':True},
                     {'http_port':True},{'http_port':22},{'public_endpoint':'bad:51820'},
                     {'heap_mib':99999},{'version':True},{'unreviewed_option':'anything'}):
            with self.subTest(edit=edit):
                self.write(dict(runtime.DEFAULT,**edit))
                with self.assertRaises((ValueError,TypeError)):runtime.read_config(self.path)
    def test_duplicate_config_and_link_are_rejected(self):
        self.path.write_text('{"version":1,"version":1}')
        with self.assertRaisesRegex(ValueError,'duplicate'):runtime.read_config(self.path)
        self.path.unlink();other=self.root/'other';other.write_text(json.dumps(runtime.DEFAULT))
        self.path.symlink_to(other)
        with self.assertRaises(ValueError):runtime.read_config(self.path)
    def test_shared_config_and_runtime_paths_are_rejected(self):
        self.path.chmod(0o666)
        with self.assertRaises(ValueError):runtime.read_config(self.path)
        private=self.root/'state';private.mkdir(mode=0o700);runtime.check_directory(private)
        private.chmod(0o755)
        with self.assertRaises(ValueError):runtime.check_directory(private)
        link=self.root/'linked';link.symlink_to(self.root)
        with self.assertRaises(ValueError):runtime.check_directory(link)
    def test_unspecified_api_bind_uses_local_management_destination(self):
        self.assertEqual('http://127.0.0.1:8443/api/status',runtime.api_url(dict(runtime.DEFAULT,http_host='0.0.0.0'),'status'))
        self.assertEqual('http://[::1]:8443/api/status',runtime.api_url(dict(runtime.DEFAULT,http_host='::'),'status'))


if __name__=='__main__':unittest.main()
