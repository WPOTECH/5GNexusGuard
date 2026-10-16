import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from native import remaining_ms, read_lease, ns_sysctl


class NamespaceSetupTests(unittest.TestCase):
    def test_sysctl_uses_private_mount_namespace_and_named_network_namespace(self):
        for role, forwarding in [('e', False), ('o', True), ('i', True), ('r', False)]:
            with patch('native.command') as run:
                ns_sysctl(role, forwarding)
            args = run.call_args.args
            self.assertEqual(args[:7], ('ip', 'netns', 'exec', 'dlip-' + role,
                                        'unshare', '-m', 'sh'))
            self.assertEqual(args[7], '-c')
            self.assertIn('mount -t proc proc /proc && sysctl -qw', args[8])
            self.assertIn('net.ipv4.ip_forward=' + ('1' if forwarding else '0'), args[8])
            self.assertIn('net.ipv4.conf.all.rp_filter=0', args[8])


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.lease = dict(version=2, transport='IKEV2_ESP_WIREGUARD', serviceId='svc', clientNodeId='client', ownerNodeId='owner',
                          allowed=True, expiresAtMs=4000)

    def remaining(self, lease):
        return remaining_ms(lease, 'svc', 'client', 'owner', 1000)

    def test_allow_and_expiry(self):
        self.assertEqual(3000, self.remaining(self.lease))
        for deadline in (1000, 999, 4001, True, '4000', None):
            self.assertEqual(0, self.remaining(dict(self.lease, expiresAtMs=deadline)))

    def test_denial_mismatch_and_malformed(self):
        for key, value in [('allowed', False), ('allowed', 'true'), ('version', True),
                           ('version', 1), ('transport', 'WIREGUARD_WIREGUARD'), ('serviceId', 'other'), ('clientNodeId', 'other'),
                           ('ownerNodeId', 'other')]:
            self.assertEqual(0, self.remaining(dict(self.lease, **{key: value})))
        for value in (None, [], {}, 'bad'):
            self.assertEqual(0, self.remaining(value))

    def test_protected_file_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp).resolve()
            path = directory / 'lease.json'
            path.write_text(json.dumps(self.lease))
            path.chmod(0o600)
            self.assertEqual(self.lease, read_lease(path, os.getuid()))
            path.chmod(0o644)
            with self.assertRaises(ValueError): read_lease(path, os.getuid())
            path.chmod(0o600)
            with self.assertRaises(ValueError): read_lease(path, os.getuid() + 1)
            link = directory / 'link'; link.symlink_to(path)
            with self.assertRaises(OSError): read_lease(link, os.getuid())
            directory.chmod(0o755)
            with self.assertRaises(ValueError): read_lease(path, os.getuid())



class RecoveryTests(unittest.TestCase):
    def topology(self):
        from native import Topology
        from unittest.mock import Mock
        topology = Topology(Path('/unused'))
        topology.daemon_roles = {role: Mock(poll=lambda: None) for role in ('e', 'o')}
        return topology

    def test_command_failure_and_timeout_do_not_disclose_output_or_arguments(self):
        import subprocess
        from native import command
        from unittest.mock import Mock
        for outcome in (Mock(returncode=1, stderr='PRIVATE SECRET', stdout='PRIVATE SECRET'),
                        subprocess.TimeoutExpired(['PRIVATE SECRET'], 10, output='PRIVATE SECRET')):
            with patch('native.subprocess.run', **({'side_effect': outcome} if isinstance(outcome, Exception)
                                                   else {'return_value': outcome})):
                with self.assertRaises(RuntimeError) as error:
                    command('swanctl', 'PRIVATE SECRET')
                self.assertNotIn('SECRET', str(error.exception))

    def test_dead_daemon_cannot_reuse_surviving_sa(self):
        topology = self.topology()
        topology.daemon_roles['o'].poll = lambda: 9
        with patch.object(topology, 'swan') as swan:
            self.assertFalse(topology.ipsec_ready())
            swan.assert_not_called()

    def test_exact_selectors_still_required(self):
        topology = self.topology()
        good = ('hybrid: #1, ESTABLISHED, IKEv2, 0123456789abcdef_i fedcba9876543210_r\n'
                'inner-transport: #1, reqid 42, INSTALLED, TUNNEL, ESP: '
                'local  10.77.0.1/32[17/51821] remote 10.78.0.2/32[17/51821]')
        gateway = good.replace('local  10.77.0.1/32[17/51821] remote 10.78.0.2/32[17/51821]',
                               'local  10.78.0.2/32[17/51821] remote 10.77.0.1/32[17/51821]')
        for status, expected in [(good, True), (good.replace('/32', '/24'), False),
                                 (good.replace('51821', '51820'), False), ('', False)]:
            with patch.object(topology, 'swan', side_effect=lambda role, *args: status if role == 'e' else gateway):
                self.assertEqual(expected, topology.ipsec_ready())

    def test_ipsec_ready_requires_matching_gateway_child(self):
        topology = self.topology()
        endpoint = ('hybrid: #1, ESTABLISHED, IKEv2, 0123456789abcdef_i fedcba9876543210_r\n'
                    'inner-transport: #1, reqid 42, INSTALLED, TUNNEL, ESP: '
                    'local  10.77.0.1/32[17/51821] remote 10.78.0.2/32[17/51821]')
        gateway = ('hybrid: #1, ESTABLISHED, IKEv2, 0123456789abcdef_i fedcba9876543210_r*\n'
                   'inner-transport: #1, reqid 42, INSTALLED, TUNNEL, ESP: '
                   'local  10.78.0.2/32[17/51821] remote 10.77.0.1/32[17/51821]')
        with patch.object(topology, 'swan', side_effect=lambda role, *args: endpoint if role == 'e' else ''):
            self.assertFalse(topology.ipsec_ready())
        with patch.object(topology, 'swan', side_effect=lambda role, *args: endpoint if role == 'e' else gateway.replace('fedcba9876543210', 'aaaaaaaaaaaaaaaa')):
            self.assertFalse(topology.ipsec_ready())
        with patch.object(topology, 'swan', side_effect=lambda role, *args: endpoint if role == 'e' else gateway):
            self.assertTrue(topology.ipsec_ready())

    def test_ipsec_ready_does_not_mix_child_selectors(self):
        topology = self.topology()
        header = 'hybrid: #1, ESTABLISHED, IKEv2, 0123456789abcdef_i fedcba9876543210_r\n'
        def status(local, remote):
            return (header + 'inner-transport: #1, reqid 42, INSTALLED, TUNNEL, ESP:\n'
                    '    local  10.77.0.1/32[17/9999]\n    remote 10.78.0.2/32[17/9999]\n'
                    'other-child: #2, reqid 42, INSTALLED, TUNNEL, ESP:\n'
                    '    local  ' + local + '\n    remote ' + remote)
        endpoint = status('10.77.0.1/32[17/51821]', '10.78.0.2/32[17/51821]')
        gateway = status('10.78.0.2/32[17/51821]', '10.77.0.1/32[17/51821]')
        with patch.object(topology, 'swan', side_effect=lambda role, *args: endpoint if role == 'e' else gateway):
            self.assertFalse(topology.ipsec_ready())

    def test_recovery_revokes_before_restarting_and_never_restarts_live_peer(self):
        topology = self.topology()
        topology.daemon_roles['o'].poll = lambda: 9
        calls = []
        with patch.object(topology, 'authorize', side_effect=lambda n: calls.append(('deny', n))), \
             patch.object(topology, 'start_daemon', side_effect=lambda r: calls.append(('start', r))), \
             patch.object(topology, 'swan', side_effect=lambda *a: calls.append(a) or ''):
            topology.recover_ipsec()
        self.assertEqual(calls[:2], [('deny', 0), ('start', 'o')])
        self.assertEqual(calls[-1], ('e', '--initiate', '--child', 'inner-transport', '--timeout', '3'))

    def test_recovery_refuses_termination_failure_on_surviving_peer(self):
        topology = self.topology()
        topology.daemon_roles['o'].poll = lambda: 9
        calls = []
        def swan(role, *args):
            calls.append((role,) + args)
            if '--list-sas' in args:
                return 'hybrid: #1'
            if role == 'e' and '--terminate' in args:
                raise RuntimeError('failed')
            return ''
        with patch.object(topology, 'authorize'), patch.object(topology, 'start_daemon'), \
             patch.object(topology, 'swan', side_effect=swan):
            with self.assertRaises(RuntimeError):
                topology.recover_ipsec()
        self.assertFalse(any('--initiate' in call for call in calls))

    def test_restart_failure_stays_revoked(self):
        topology = self.topology()
        topology.daemon_roles['e'].poll = lambda: 9
        with patch.object(topology, 'authorize') as authorize, \
             patch.object(topology, 'start_daemon', side_effect=RuntimeError), \
             patch.object(topology, 'swan') as swan:
            with self.assertRaises(RuntimeError): topology.recover_ipsec()
        authorize.assert_called_once_with(0)
        swan.assert_not_called()

    def test_start_refuses_live_process(self):
        topology = self.topology()
        with patch('native.subprocess.Popen') as popen:
            with self.assertRaises(RuntimeError): topology.start_daemon('e')
            with self.assertRaises(ValueError): topology.start_daemon('r')
        popen.assert_not_called()

    def test_start_removes_stale_socket_and_reloads_existing_configuration(self):
        from unittest.mock import Mock
        topology = self.topology()
        with tempfile.TemporaryDirectory() as tmp:
            topology.state = Path(tmp)
            directory = topology.state / 'e'
            directory.mkdir()
            (directory / 'vici').touch()
            topology.daemon_roles['e'].poll = lambda: 9
            child = Mock(poll=lambda: None)
            with patch('native.subprocess.Popen', return_value=child), patch.object(topology, 'swan') as swan:
                topology.start_daemon('e')
            self.assertFalse((directory / 'vici').exists())
            self.assertIs(topology.daemon_roles['e'], child)
            swan.assert_called_once_with('e', '--load-all', '--file', str(directory / 'swanctl.conf'))

    def test_unloaded_daemon_is_killed_after_bounded_retries(self):
        from unittest.mock import Mock
        topology = self.topology()
        with tempfile.TemporaryDirectory() as tmp:
            topology.state = Path(tmp)
            (topology.state / 'e').mkdir()
            topology.daemon_roles['e'].poll = lambda: 9
            child = Mock(poll=lambda: None)
            with patch('native.subprocess.Popen', return_value=child), \
                 patch.object(topology, 'swan', side_effect=RuntimeError) as swan, patch('native.time.sleep'):
                with self.assertRaises(RuntimeError): topology.start_daemon('e')
            self.assertEqual(swan.call_count, 5)
            child.kill.assert_called_once()
            child.wait.assert_called_once_with(timeout=3)

    def test_routes_replace_wrong_existing_routes_and_report_failure(self):
        topology = self.topology()
        with patch('native.ns', return_value='wrong route') as ns:
            self.assertTrue(topology.reconcile_routes())
        self.assertEqual(len(ns.call_args_list), 5)
        for call in ns.call_args_list:
            self.assertEqual(call.args[1:4], ('ip', 'route', 'replace'))
            self.assertTrue(call.args[4].endswith('/32'))
        with patch('native.ns', side_effect=RuntimeError):
            self.assertFalse(topology.reconcile_routes())

    def test_authorization_samples_time_after_read_and_denies_unready(self):
        from native import renew_authorization
        from types import SimpleNamespace
        from unittest.mock import Mock
        args = SimpleNamespace(lease=Path('/unused'), ledger_uid=1, service='svc', client='client', owner='owner')
        lease = dict(version=2, transport='IKEV2_ESP_WIREGUARD', allowed=True, serviceId='svc',
                     clientNodeId='client', ownerNodeId='owner', expiresAtMs=2000)
        topology = Mock()
        events = []
        with patch('native.read_lease', side_effect=lambda *a: events.append('read') or lease) as read, \
             patch('native.time.time_ns', side_effect=lambda: events.append('time') or 2100000000):
            renew_authorization(topology, args, True)
            topology.authorize.assert_called_with(0)
            self.assertEqual(events, ['read', 'time'])
            read.reset_mock()
            renew_authorization(topology, args, False)
            read.assert_not_called()

    def test_authorization_binds_to_absolute_packet_time_not_delayed_install(self):
        from native import Topology
        topology = Topology(Path('/unused'))
        with patch('native.time.time_ns', return_value=1000000000000), patch('native.ns') as ns:
            topology.authorize(3000, deadline_ms=1002999)
        rule = ns.call_args.kwargs['data']
        self.assertIn('meta time < 1002', rule)
        self.assertIn('timeout 2999ms', rule)
        # Reconciliation uses the original deadline, not a fresh three seconds.
        with patch('native.time.time_ns', return_value=1001000000000), patch('native.ns') as ns:
            topology.authorize(3000, deadline_ms=1002999)
        self.assertIn('meta time < 1002', ns.call_args.kwargs['data'])
        self.assertIn('timeout 1999ms', ns.call_args.kwargs['data'])
        # A new supervisor object cannot replay the already-expired record.
        topology = Topology(Path('/unused-after-restart'))
        with patch('native.time.time_ns', return_value=1003000000000), patch('native.ns') as ns:
            topology.authorize(3000, deadline_ms=1002999)
        self.assertNotIn('add element', ns.call_args.kwargs['data'])
        self.assertNotIn('meta time <', ns.call_args.kwargs['data'])

    def test_firewall_counters_do_not_duplicate_or_relax_verdicts(self):
        from native import firewall
        with patch('native.ns') as ns:
            firewall('i', 'ip saddr 10.1.1.1 accept', 'counter accept', 'counter drop')
        rules = ns.call_args.kwargs['data']
        self.assertIn('ip saddr 10.1.1.1 counter accept', rules)
        self.assertNotIn('counter counter', rules)
        self.assertEqual(rules.count('policy drop'), 3)


class FaultEvidenceTests(unittest.TestCase):
    def test_observations_never_request_key_bearing_state(self):
        from integration import observe
        from unittest.mock import Mock
        topology = Mock()
        topology.swan.return_value = 'counter metadata'
        topology.daemon_roles = {r: Mock(poll=lambda: None) for r in ('e', 'o')}
        with tempfile.TemporaryDirectory() as tmp, patch('integration.ns', return_value='metadata') as ns:
            observe(topology, Path(tmp))
            self.assertEqual(len(list(Path(tmp).glob('*'))), 12)
        self.assertFalse(any('state' in call.args for call in ns.call_args_list))
        self.assertEqual(topology.swan.call_count, 2)

    def test_fault_baseline_failure_and_recovery_have_continuous_envelope(self):
        from integration import run_fault
        from unittest.mock import Mock
        phases = []
        topology = Mock()
        topology.ipsec_ready.return_value = True
        inject, restore = Mock(), Mock()
        def phase(t, evidence, label, action, expected):
            phases.append((label, expected))
            action()
        with patch('integration.capture_phase', side_effect=phase), patch('integration.probe', return_value=True):
            run_fault(topology, Path('/unused'), 'fault', inject, restore)
        self.assertEqual(phases, [('fault-continuous', None), ('fault-baseline', True),
                                  ('fault-fault', False), ('fault-recovery', True)])
        inject.assert_called_once()
        restore.assert_called_once()

    def test_failed_injection_still_runs_recovery(self):
        from integration import run_fault
        from unittest.mock import Mock
        topology = Mock()
        restore = Mock()
        def phase(t, evidence, label, action, expected): action()
        with patch('integration.capture_phase', side_effect=phase), patch('integration.probe', return_value=True):
            with self.assertRaises(ValueError):
                run_fault(topology, Path('/unused'), 'fault', Mock(side_effect=ValueError), restore)
        restore.assert_called_once()

    def test_capture_start_failure_stops_all_children_and_never_passes(self):
        from integration import capture_phase
        from unittest.mock import Mock
        children = [Mock(poll=lambda: 1) for _ in range(7)]
        with tempfile.TemporaryDirectory() as tmp, \
             patch('integration.process', side_effect=children), patch('integration.stop') as stop, \
             patch('integration.observe') as observe, patch('integration.check') as check:
            with self.assertRaises(AssertionError):
                capture_phase(Mock(), Path(tmp), 'fault', Mock(), False)
        self.assertEqual(stop.call_count, 7)
        observe.assert_not_called()
        check.assert_not_called()

    def test_capture_validation_rejects_leak_loss_and_missing_positive_evidence(self):
        from integration import capture_phase
        from unittest.mock import Mock
        for scenario in ('valid', 'leak', 'dropped', 'ten-dropped', 'empty-positive', 'denied-resource'):
            children = []
            def process(role, *args, **kwargs):
                path = Path(args[args.index('-w') + 1])
                payload = b'native-dual-packet-evidence' if path.stem == 'resource' else b''
                if scenario == 'leak' and path.stem == 'endpoint-public':
                    payload += b'native-dual-packet-evidence'
                if scenario == 'empty-positive': payload = b''
                path.write_bytes(b'0' * 24 + payload)
                kwargs['stderr'].write('listening on interface\n' +
                    ('10 packets dropped by kernel\n' if scenario == 'ten-dropped' else
                     '1 packets dropped by kernel\n' if scenario == 'dropped' else '0 packets dropped by kernel\n'))
                kwargs['stderr'].flush()
                child = Mock(poll=lambda: None, returncode=0)
                children.append(child)
                return child
            def command(*args):
                return '' if 'not' in args[-1] or args[-1] == 'ip6' or scenario == 'empty-positive' else 'encrypted metadata'
            with tempfile.TemporaryDirectory() as tmp, patch('integration.process', side_effect=process), \
                 patch('integration.stop') as stop, patch('integration.observe'), \
                 patch('integration.time.sleep'), patch('integration.command', side_effect=command) as command_mock, \
                 patch('integration.probe', return_value=scenario != 'denied-resource'), patch('builtins.print'):
                if scenario == 'valid':
                    capture_phase(Mock(), Path(tmp), 'baseline', Mock(), True)
                    self.assertTrue(any('wire-egress' in str(call.args) and 'ip6' in str(call.args)
                                        for call in command_mock.call_args_list))
                else:
                    with self.assertRaises(AssertionError):
                        capture_phase(Mock(), Path(tmp), 'phase', Mock(), scenario != 'denied-resource')
                self.assertEqual(stop.call_count, 7)

    def test_recovery_retry_budget_is_finite(self):
        from integration import run_fault
        from unittest.mock import Mock
        topology = Mock()
        topology.ipsec_ready.return_value = False
        topology.recover_ipsec.side_effect = RuntimeError
        def phase(t, evidence, label, action, expected): action()
        with patch('integration.capture_phase', side_effect=phase), patch('integration.time.sleep'):
            with self.assertRaisesRegex(AssertionError, 'bounded recovery exhausted'):
                run_fault(topology, Path('/unused'), 'fault', Mock(), Mock())
        self.assertEqual(topology.recover_ipsec.call_count, 8)


if __name__ == '__main__':
    unittest.main()
