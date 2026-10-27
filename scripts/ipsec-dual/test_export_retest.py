"""Offline export integrity checks; no VM or Docker operations."""
import hashlib
import io
import tarfile
import unittest
from reboot_vm.export_retest import verify_export, export_complete


class ExportRetestTests(unittest.TestCase):
    def test_export_pass_requires_evidence_shutdown_and_host_configuration(self):
        good=dict(export='PASS',matched_original_artifacts=81,guest_stopped=True,
                  qemu_exit_code=0,host_configuration_unchanged=True,
                  raw_host_snapshots_equal=False)
        self.assertTrue(export_complete(good))
        for edit in ({'matched_original_artifacts':0},{'host_configuration_unchanged':False},
                     {'guest_stopped':False},{'qemu_exit_code':-9},{'shutdown_error':'failed'}):
            self.assertFalse(export_complete(dict(good,**edit)))
        for field in ('matched_original_artifacts','host_configuration_unchanged','guest_stopped','qemu_exit_code','export'):
            missing=dict(good);missing.pop(field)
            self.assertFalse(export_complete(missing),field)

    def archive(self,files):
        memory=io.BytesIO()
        with tarfile.open(fileobj=memory,mode='w:gz') as out:
            for name,data in files:
                item=tarfile.TarInfo(name);item.size=len(data);out.addfile(item,io.BytesIO(data))
        return memory.getvalue()
    def test_export_requires_original_packet_artifact_bytes(self):
        key='evidence/packet/resource.pcap';payload=b'private-test-capture'
        expected={key:hashlib.sha256(payload).hexdigest()}
        self.assertEqual(1,verify_export(self.archive([(key,payload)]),expected))
        with self.assertRaises(ValueError):verify_export(self.archive([(key,b'changed')]),expected)
        with self.assertRaises(KeyError):verify_export(self.archive([]),expected)
    def test_duplicate_and_escaping_paths_are_rejected_without_extracting(self):
        for files in ([('../outside',b'x')],[('/outside',b'x')],[('evidence/a',b'x'),('evidence/a',b'x')]):
            with self.assertRaises(ValueError):verify_export(self.archive(files),{})
    def test_only_two_boot_log_hashes_may_change(self):
        expected={'evidence/dockerd.local.log':'old','evidence/guest-agent.local.log':'old'}
        self.assertEqual(0,verify_export(self.archive([]),expected))
        expected['evidence/packet/summary.local.json']='old'
        with self.assertRaises(KeyError):verify_export(self.archive([]),expected)


if __name__=='__main__':unittest.main()
