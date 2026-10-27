"""Offline negative acceptance controls, never run JVMs or packet operations."""
import unittest
from standard_evidence import qualification_complete,residual_denial


class StandardEvidenceTests(unittest.TestCase):
    def test_positive_only_report_cannot_pass_complete_standard_qualification(self):
        positive={'discovery_registration':'PASS','authorized_traffic':'PASS',
                  'interface_ownership':'PASS','disconnect':'PASS',
                  'owned_processes_stopped':True,'cleanup':[{'status':'PASS'}]*2}
        self.assertFalse(qualification_complete(positive))
        full=dict(positive,authorization_denial='PASS',residual_forwarding='DENIED',packet_evidence='PASS')
        self.assertTrue(qualification_complete(full))
        for field in ('authorization_denial','residual_forwarding','packet_evidence','interface_ownership','owned_processes_stopped','cleanup'):
            missing=dict(full);missing.pop(field)
            self.assertFalse(qualification_complete(missing),field)
        self.assertFalse(qualification_complete(dict(full,cleanup=[{'status':'FAIL'}]*2)))

    def test_existing_and_new_post_disconnect_delivery_are_mandatory_negative_probes(self):
        rows=[dict(attempt_ns=10,verdict_ns=20,delivered=True),
              dict(attempt_ns=25,verdict_ns=35,delivered=True),
              dict(attempt_ns=40,verdict_ns=50,delivered=False)]
        result=residual_denial(rows,30)
        self.assertEqual(35,result['last_success_ns'])
        self.assertEqual(40,result['first_denied_attempt_ns'])
        with self.assertRaises(ValueError):residual_denial(rows[:2],30)
        with self.assertRaises(ValueError):residual_denial(rows+[dict(attempt_ns=60,verdict_ns=70,delivered=True)],30)
        with self.assertRaises(ValueError):residual_denial([dict(attempt_ns=40,verdict_ns=50,delivered=False)],30)


if __name__=='__main__':unittest.main()
