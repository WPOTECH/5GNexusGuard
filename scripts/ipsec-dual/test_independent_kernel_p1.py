"""Negative acceptance controls for the separate-supervisor packet experiment."""
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from continuous_evidence import EvidenceError
from independent_kernel_p1 import Supervisor, assert_hooks, retained_deadlines


def snapshot():
    auth = {'epoch': 7, 'deadline_ns': 1000, 'peer': '10.79.0.1', 'resource': '10.80.0.2', 'port': 8080}
    return {'maps': {'authorization': {'value': auth},
                     'health': {'value': dict(auth, checked_ns=100, deadline_ns=600)}},
            'tc': {'wg-inner': {'attached': True, 'program_id': 1},
                   'resource': {'attached': True, 'program_id': 2}},
            'programs': {'wg_ingress': {'id': 1, 'classifier': True},
                         'resource_ingress': {'id': 2, 'classifier': True}},
            'nft_hooks': {'ipsec_dual': [{'hook': 'forward', 'policy': 'drop', 'prio': 0}],
                          'kernel_gate_v2_test': [{'hook': 'forward', 'policy': 'drop', 'prio': 10}]},
            'nft': {'ipsec_dual': [{'rule_kind': k} for k in
                                  ('transit_in', 'transit_out', 'forward', 'reverse', 'drop')],
                    'kernel_gate_v2_test': [{'rule_kind': k} for k in ('forward', 'reverse', 'drop')]}}


class IndependentKernelTests(unittest.TestCase):
    def test_dead_maps_cannot_pass_as_independent_kernel_enforcement(self):
        before = snapshot(); retained = deepcopy(before); final = deepcopy(before)
        retained_deadlines(before, retained, final)
        for label in ('authorization', 'health'):
            changed = deepcopy(final); changed['maps'][label]['value']['epoch'] = 0
            with self.assertRaises(EvidenceError): retained_deadlines(before, retained, changed)
            changed = deepcopy(final); changed['maps'][label]['value']['deadline_ns'] += 1
            with self.assertRaises(EvidenceError): retained_deadlines(before, retained, changed)
        changed = deepcopy(retained); changed['maps']['health']['value']['epoch'] += 1
        with self.assertRaises(EvidenceError): retained_deadlines(before, changed, changed)

    def test_tc_nft_handoff_requires_actual_ids_and_exact_interlocks(self):
        good = snapshot(); assert_hooks(good)
        for edit in (
                lambda s: s['tc']['resource'].update(attached=False),
                lambda s: s['tc']['wg-inner'].update(program_id=99),
                lambda s: s['nft_hooks']['ipsec_dual'][0].update(policy='accept'),
                lambda s: s['nft_hooks']['kernel_gate_v2_test'][0].update(prio=0),
                lambda s: s['nft']['kernel_gate_v2_test'][1].update(rule_kind='unknown')):
            changed = deepcopy(good); edit(changed)
            with self.assertRaises(EvidenceError): assert_hooks(changed)

    def test_supervisor_kill_refuses_wrong_process_start_identity(self):
        instance = Supervisor.__new__(Supervisor)
        instance.process = Mock(pid=123); instance.process.poll.return_value = None
        instance.initial = {'pid': 123}; instance.start = 11
        with patch('independent_kernel_p1.FreshHealth._start', return_value=12):
            with self.assertRaisesRegex(EvidenceError, 'identity mismatch'): instance.kill()
        instance.process.kill.assert_not_called()


if __name__ == '__main__': unittest.main()
