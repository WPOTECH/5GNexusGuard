"""Deny-default installed-profile checks; no real VM/network operations."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts/ipsec-dual'))
spec=importlib.util.spec_from_file_location('installed_native',Path(__file__).with_name('native_runtime.py'))
runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)


class NativeRuntimeTests(unittest.TestCase):
    def test_explicit_profile_requires_isolation_and_never_enables_production(self):
        from native_control_v2 import boot_id
        with tempfile.TemporaryDirectory() as directory:
            config=Path(directory)/'deployment.json'
            cfg=dict(version=1,profile='DISPOSABLE_VM',production_admission=False,boot_id=boot_id(),
                service='svc',client='a'*64,owner='b'*64,operator_key='c'*64,supervisor_key='d'*64,
                credentials='/private/credentials',aa={},control={})
            def write(value):config.write_text(json.dumps(value));config.chmod(0o600)
            write(cfg)
            with patch.object(runtime,'CONFIG',config),patch.object(runtime.os,'geteuid',return_value=0),patch.object(runtime.subprocess,'check_output',side_effect=['kvm\n','[{"ifname":"lo"}]']):
                self.assertEqual(cfg,runtime.configuration())
            for edit in ({'production_admission':True},{'boot_id':'old'},{'version':True},{'profile':'PRODUCTION'}):
                write(dict(cfg,**edit))
                with patch.object(runtime,'CONFIG',config),self.assertRaises(ValueError):runtime.configuration()
            write(cfg)
            with patch.object(runtime,'CONFIG',config),patch.object(runtime.os,'geteuid',return_value=0),patch.object(runtime.subprocess,'check_output',side_effect=['kvm\n','[{"ifname":"lo"},{"ifname":"eth0"}]']),self.assertRaises(ValueError):runtime.configuration()
            with patch.object(runtime,'CONFIG',config),patch.object(runtime.os,'geteuid',return_value=0),patch.object(runtime.subprocess,'check_output',return_value='none\n'),self.assertRaises(ValueError):runtime.configuration()

    def test_installed_runtime_does_not_import_development_traffic_or_signing_fixture(self):
        import ast
        tree=ast.parse(Path(runtime.__file__).read_text())
        imports={node.module for node in ast.walk(tree) if isinstance(node,ast.ImportFrom)}
        self.assertFalse(imports & {'isolated_enforcement','functional_p0','native_aa_java_harness','integration'})


if __name__=='__main__':unittest.main()
