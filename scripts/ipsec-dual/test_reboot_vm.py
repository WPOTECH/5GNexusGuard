"""Offline negative acceptance checks; never launch or reboot a VM."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock, patch
from reboot_vm.run_guest import Control, configured_network, qualification_complete
from reboot_vm.guest_agent import write_json


class RebootVmTests(unittest.TestCase):
    def test_guest_export_survives_short_device_writes(self):
        class ShortWriter:
            def __init__(self):self.data=bytearray()
            def write(self,data):
                size=min(7,len(data));self.data.extend(data[:size]);return size
        output=ShortWriter();item={'evidence_tar_base64':'x'*100_000}
        write_json(output,item)
        self.assertEqual(item,json.loads(output.data))
        closed=Mock();closed.write.return_value=0
        with self.assertRaises(OSError):write_json(closed,item)

    def test_pass_requires_evidence_cleanup_shutdown_and_host_preservation(self):
        good=dict(packet_checks='PASS',evidence_exported=True,guest_stopped=True,
                  qemu_exit_code=0,host_network_unchanged=True,after={'cleanup':'PASS'})
        self.assertTrue(qualification_complete(good))
        for field in good:
            bad=deepcopy(good);del bad[field]
            self.assertFalse(qualification_complete(bad),field)
        for edit in ({'evidence_exported':False},{'shutdown_error':'TimeoutError'},
                     {'qemu_exit_code':-9},{'after':{'cleanup':'FAIL'}},
                     {'host_network_unchanged':False},{'packet_checks':'FAIL'}):
            self.assertFalse(qualification_complete(dict(good,**edit)))

    def test_saved_network_comparison_retains_real_configuration_changes(self):
        base=dict(boot_id='boot',routes='[]',rules='[]',vms='unchanged',links='[]',
                  addresses=json.dumps([{'ifname':'eth0','addr_info':[{
                      'local':'192.0.2.1','valid_life_time':100,'preferred_life_time':50}]}]))
        elapsed=deepcopy(base);rows=json.loads(elapsed['addresses'])
        rows[0]['addr_info'][0]['valid_life_time']=99
        elapsed['addresses']=json.dumps(rows)
        self.assertEqual(configured_network(base),configured_network(elapsed))
        rows[0]['addr_info'][0]['local']='192.0.2.2';elapsed['addresses']=json.dumps(rows)
        self.assertNotEqual(configured_network(base),configured_network(elapsed))
        for field in ('boot_id','routes','rules','vms'):
            changed=dict(base);changed[field]='different'
            self.assertNotEqual(configured_network(base),configured_network(changed))

    def test_control_rejects_foreign_lab_and_guest_errors(self):
        for reply in ({'lab_id':'foreign'},{'error':'wrong disk'}):
            obj=Control(Path('/unused'),'ours');obj.socket=Mock()
            obj.socket.recv.return_value=(json.dumps(reply)+'\n').encode()
            with patch('reboot_vm.run_guest.select.select',return_value=([obj.socket],[],[])):
                with self.assertRaises(RuntimeError):obj.ask('status')

    def test_vm_launcher_requires_approval_before_reading_lab_or_launching(self):
        result=subprocess.run([sys.executable,str(Path(__file__).parent/'reboot_vm/run_guest.py'),
                               '--directory','/nonexistent-reboot-lab'],capture_output=True,text=True)
        self.assertEqual(2,result.returncode)
        self.assertIn('explicit operator approval required',result.stderr)


if __name__=='__main__':unittest.main()
