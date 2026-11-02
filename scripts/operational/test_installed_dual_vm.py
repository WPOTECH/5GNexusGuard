"""Offline acceptance negatives; never boot a VM or invoke network operations."""
import copy
import unittest
from run_installed_dual_vm import qualification


class InstalledVmAcceptanceTests(unittest.TestCase):
    def test_traffic_alone_cannot_replace_revocation_captures_or_baseline_cleanup(self):
        required=('persisted live Java identity','mTLS node key matches actual Java identity',
            'authorized installed nested TCP','direct underlay physical bypass denial',
            'established and new TCP denied after signed disconnect','revocation denial before original expiry',
            'old TCP denied after installed service stop','owned namespaces and pins removed',
            'restart stays denied before fresh operator recovery','fresh authority restores installed protected TCP')
        checks={key:'PASS' for key in required}
        checks.update({'clean capture boundary-'+str(i):'PASS' for i in range(14)})
        result=dict(qemu_exit_code=0,guest_stopped=True,host_configuration_unchanged=True,baseline_disk_unchanged=True,
            guest_result=dict(status='PASS',checks=checks,namespaces_after='',pins_after=False,
                              packet_counts={'initial':{},'recovery-':{}}))
        self.assertTrue(qualification(result))
        for edit in ({'guest_stopped':False},{'host_configuration_unchanged':False},{'baseline_disk_unchanged':False}):
            self.assertFalse(qualification(dict(result,**edit)))
        for key in ('direct underlay physical bypass denial','established and new TCP denied after signed disconnect','clean capture boundary-0'):
            missing=copy.deepcopy(result);missing['guest_result']['checks'].pop(key)
            self.assertFalse(qualification(missing))
        leftover=copy.deepcopy(result);leftover['guest_result']['pins_after']=True
        self.assertFalse(qualification(leftover))


if __name__=='__main__':unittest.main()
