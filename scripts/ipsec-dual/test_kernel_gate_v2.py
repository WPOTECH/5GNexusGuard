"""Unprivileged contract/fault tests; these are NOT protected-packet evidence."""
import importlib.util
from pathlib import Path
import unittest

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('kernel_gate_v2', HERE / 'kernel_gate_v2.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class GateContract(unittest.TestCase):
    def setUp(self):
        self.g = gate.Gate(boot='boot-A', peer='10.79.0.1', resource='10.80.0.2',
                           port=8080, health_window_ns=500_000_000)

    def test_default_deny_and_independent_interlock_when_detached(self):
        self.assertFalse(self.g.permits(1, '10.79.0.1', '10.80.0.2', 8080))
        self.g.admit('boot-A', 'epoch-A', 3_000_000_000, 1)
        self.g.heartbeat('boot-A', 'epoch-A', 1)
        self.assertTrue(self.g.permits(1, '10.79.0.1', '10.80.0.2', 8080))
        self.g.attached = False
        self.assertFalse(self.g.permits(2, '10.79.0.1', '10.80.0.2', 8080))
        rules = gate.nft_interlock()
        self.assertIn('policy drop', rules)
        self.assertIn('meta mark', rules)
        self.assertNotIn('@authorized', rules)
        self.assertNotIn('meta time', rules)

    def test_auth_deadline_immutable_and_nonextending_at_boundary(self):
        self.g.admit('boot-A', 'epoch-A', 3_000_000_000, 1)
        self.g.heartbeat('boot-A', 'epoch-A', 2_999_999_999)
        self.assertTrue(self.g.permits(2_999_999_999, '10.79.0.1', '10.80.0.2', 8080))
        self.assertFalse(self.g.permits(3_000_000_000, '10.79.0.1', '10.80.0.2', 8080))
        with self.assertRaises(ValueError):
            self.g.admit('boot-A', 'epoch-A', 6_000_000_000, 2)

    def test_health_expires_independently_and_refresh_is_bounded(self):
        self.g.admit('boot-A', 'epoch-A', 3_000_000_000, 1)
        self.g.heartbeat('boot-A', 'epoch-A', 100)
        self.assertTrue(self.g.permits(500_000_099, '10.79.0.1', '10.80.0.2', 8080))
        self.assertFalse(self.g.permits(500_000_100, '10.79.0.1', '10.80.0.2', 8080))
        with self.assertRaises(ValueError):
            self.g.heartbeat('boot-A', 'epoch-A', 500_000_100)
        self.assertFalse(self.g.permits(500_000_101, '10.79.0.1', '10.80.0.2', 8080))

    def test_wrong_boot_epoch_peer_resource_port_and_reverse(self):
        self.g.admit('boot-A', 'epoch-A', 3_000_000_000, 1)
        for boot, epoch in [('boot-B', 'epoch-A'), ('boot-A', 'epoch-B')]:
            with self.assertRaises(ValueError):
                self.g.heartbeat(boot, epoch, 2)
        self.g.heartbeat('boot-A', 'epoch-A', 2)
        for peer, resource, port in [('10.79.0.3', '10.80.0.2', 8080),
                                     ('10.79.0.1', '10.80.0.3', 8080),
                                     ('10.79.0.1', '10.80.0.2', 8081)]:
            self.assertFalse(self.g.permits(2, peer, resource, port))
        self.assertFalse(self.g.permits(2, '10.80.0.2', '10.79.0.1', 8080))

    def test_no_stale_reinstall_restart_or_unverified_refresh(self):
        self.g.admit('boot-A', 'epoch-A', 1000, 1)
        with self.assertRaises(ValueError):
            self.g.heartbeat('boot-A', 'epoch-A', 1000)
        with self.assertRaises(ValueError):
            self.g.admit('boot-A', 'epoch-B', 900, 1)
        fresh = gate.Gate(boot='boot-A', peer='10.79.0.1', resource='10.80.0.2', port=8080)
        self.assertFalse(fresh.permits(1, '10.79.0.1', '10.80.0.2', 8080))
        with self.assertRaises(ValueError):
            fresh.heartbeat('boot-A', 'epoch-A', 1)

    def test_tc_source_has_boottime_and_separate_epoch_maps(self):
        source = (HERE / 'kernel_gate_v2.bpf.c').read_text()
        self.assertIn('bpf_ktime_get_boot_ns()', source)
        self.assertIn('SEC("tc/wg_ingress")', source)
        self.assertIn('SEC("tc/resource_ingress")', source)
        self.assertIn('auth_map', source)
        self.assertIn('health_map', source)
        self.assertIn('health->epoch != auth->epoch', source)
        self.assertIn('health->checked_ns', source)
        self.assertIn('500000000ULL', source)

    def test_resource_ingress_allows_only_bound_resource_arp_reply(self):
        # trial-x: nine authorized SYNs passed TC and both nft chains, but
        # the sole resource-ingress TC invocation dropped the ARP reply.
        # Source-level regression only; a fresh packet run must prove delivery.
        source = (HERE / 'kernel_gate_v2.bpf.c').read_text()
        self.assertIn('ETH_P_ARP', source)
        self.assertIn('ARPOP_REPLY', source)
        self.assertIn('arp->ar_sip != bpf_htonl(RESOURCE)', source)
        self.assertIn('arp->ar_tip != bpf_htonl(0x0a500001U)', source)
        self.assertIn('arp->ar_hln != ETH_ALEN', source)
        self.assertIn('arp->ar_pln != 4', source)
        self.assertIn('ARP_REPLY_PASSED', source)
        self.assertIn('skb->mark = 0', source)

    def test_cleanup_recognizes_only_owned_diagnostic_pin(self):
        runner = (HERE / 'isolated_enforcement.py').read_text()
        self.assertIn("'maps': {'auth_map', 'health_map', 'verdict_map'}", runner)
        self.assertIn("raise RuntimeError('unexpected bpffs pin; manual cleanup required')", runner)

    def test_production_deny_only_not_changed(self):
        native = (HERE / 'native.py').read_text()
        control = (HERE / 'native_control_v2.py').read_text()
        self.assertIn('topology.authorize(0)', native)
        self.assertIn('informational only; never opens packet ACLs', control)
        self.assertNotIn('kernel_gate_v2', native + control)


if __name__ == '__main__':
    unittest.main()
