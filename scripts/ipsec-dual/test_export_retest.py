"""Offline export integrity checks; no VM or Docker operations."""
import hashlib
import io
import tarfile
import unittest
from reboot_vm.export_retest import verify_export


class ExportRetestTests(unittest.TestCase):
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
