"""Unprivileged publisher tests; subprocess and Controller are boundary mocks."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('kernel_gate_publisher_v2', HERE/'kernel_gate_publisher_v2.py')
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)

class Admission:
    deadline = 2_900_000_000
    generation = 7
    def state(self, now): return 'AUTHORIZED'

class Controller:
    scope = {'bootId':'boot-A'}
    session = 'session-A'
    approval_nonce = 'nonce-A'
    floors = (7, 1, 2)
    admission = Admission()
    until_ns = 2_800_000_000
    until_ms = 9999999999999
    def step(self): return 'ATTESTED'

class FakeIO:
    def __init__(self): self.commands = []; self.maps = {}; self.fail = None
    def __call__(self, args, *, input=None):
        self.commands.append((tuple(args), input))
        if self.fail and self.fail in args: raise RuntimeError('injected failure')
        if args[:4] == ['nft', '-j', 'list', 'chain']:
            return json.dumps({'nftables':[{'chain':{'family':'inet','table':'ipsec_dual',
                'name':'forward','hook':'forward','policy':'drop'}}]})
        if args[:3] == ['bpftool', '-j', 'map']:
            path = args[5]
            return json.dumps({'value':list(self.maps.get(path, bytes(32)))})
        if args[:3] == ['bpftool', 'map', 'update']:
            self.maps[args[4]] = bytes(int(x,16) for x in args[13:])
        return ''

class PublisherTests(unittest.TestCase):
    def test_structured_conflicting_verifier_and_permission_evidence_is_ambiguous(self):
        raw = ("libbpf: prog 'wg_ingress': failed to load: Operation not permitted\n"
               "libbpf: verifier log: invalid mem access 'scalar' private-key=SECRET")
        failure = subprocess.CalledProcessError(255, ['bpftool', 'prog', 'loadall'],
                                                output='trace', stderr=raw)
        with mock.patch.object(pub.subprocess, 'run', side_effect=failure):
            with self.assertRaises(RuntimeError) as caught:
                pub.command(['bpftool', 'prog', 'loadall', '/private/SECRET',
                             '/sys/fs/bpf/pin/progs', 'type', 'classifier',
                             'pinmaps', '/sys/fs/bpf/pin/maps'])
        data = caught.exception.diagnostic
        self.assertEqual(('bpftool', 'prog loadall', 255),
                         (data['failing_executable'], data['failing_operation'], data['exit_code']))
        self.assertEqual('ambiguous', data['category'])
        self.assertEqual('invalid_mem_access', data['explicit_verifier_evidence'])
        self.assertEqual('EPERM', data['permission_error_evidence'])
        self.assertEqual([], data['map_pinning_evidence'])
        self.assertEqual(len(raw.encode()), data['stderr_bytes'])
        self.assertEqual(len(b'trace'), data['stdout_bytes'])
        self.assertFalse(data['stderr_truncated'])
        self.assertIn('invalid_mem_access', data['diagnostic_tokens'])
        self.assertNotIn('SECRET', str(caught.exception))
        self.assertNotIn('SECRET', str(data))

    def test_late_failing_operation_controls_attribution_not_earlier_verifier(self):
        raw = ("libbpf: prog 'wg_ingress': failed to load: -22\n"
               "invalid mem access 'scalar'\n" + "libbpf: debug line\n"*240 +
               "libbpf: map 'auth_map': failed to pin: File exists private-key=SECRET")
        data = pub._loadall_diagnostic(raw, bounded=True, exit_code=255)
        self.assertEqual('map_pinning', data['stage'])
        self.assertEqual('auth_map', data['subject'])
        self.assertEqual('EEXIST', data['errno'])
        self.assertEqual('map_pin_failure', data['category'])
        self.assertEqual('invalid_mem_access', data['explicit_verifier_evidence'])
        self.assertEqual(['pinning_failed'], data['map_pinning_evidence'])
        self.assertNotIn('SECRET', str(data))

    def test_stderr_failing_pin_not_overwritten_by_generic_stdout_failure(self):
        data = pub._loadall_diagnostic(
            "libbpf: map 'health_map': failed to pin: File exists",
            'Error: failed to load object file', exit_code=255)
        self.assertEqual('map_pinning', data['stage'])
        self.assertEqual('health_map', data['subject'])
        self.assertEqual('map_pin_failure', data['category'])

    def test_generic_summary_after_pin_does_not_erase_failing_map(self):
        data = pub._loadall_diagnostic(
            "libbpf: map 'auth_map': failed to pin: File exists\nError: failed to load object file")
        self.assertEqual(('map_pin_failure', 'auth_map', 'EEXIST'),
                         (data['category'], data['subject'], data['errno']))
        self.assertIn('pinning_failed', data['map_pinning_evidence'])

    def test_generic_pin_summary_after_named_pin_keeps_named_failure(self):
        data = pub._loadall_diagnostic(
            "libbpf: map 'auth_map': failed to pin: File exists\nError: failed to pin maps")
        self.assertEqual(('map_pin_failure', 'auth_map', 'EEXIST'),
                         (data['category'], data['subject'], data['errno']))

    def test_later_distinct_program_pin_failure_supersedes_named_map(self):
        data = pub._loadall_diagnostic(
            "libbpf: map 'auth_map': failed to pin: File exists\n"
            "Error: failed to pin program: No such file or directory")
        self.assertEqual(('program_pin_failure', 'unknown', 'ENOENT'),
                         (data['category'], data['subject'], data['errno']))

    def test_symbolic_permission_and_verifier_are_ambiguous(self):
        data = pub._loadall_diagnostic(
            "libbpf: prog 'wg_ingress': failed to load: EPERM\ninvalid mem access 'scalar'")
        self.assertEqual('ambiguous', data['category'])
        self.assertEqual('EPERM', data['permission_error_evidence'])
        self.assertEqual('invalid_mem_access', data['explicit_verifier_evidence'])

    def test_map_abi_and_permission_conflict_is_retained_as_ambiguous(self):
        data = pub._loadall_diagnostic('map ABI mismatch\nOperation not permitted')
        self.assertEqual('ambiguous', data['category'])
        self.assertEqual('EPERM', data['permission_error_evidence'])
        self.assertIn('map_abi_mismatch', data['map_pinning_evidence'])

    def test_one_map_zero_failure_still_denies_by_mismatched_epoch(self):
        for blocked in ('authorization', 'health'):
            with self.subTest(blocked=blocked):
                io = FakeIO()
                gate = pub.Publisher(Controller(), io, '/sys/fs/bpf/isolated-gate',
                    'wg-test', 'resource-test', now=lambda: 1_000_000_000, health=lambda: True)
                gate.install()
                self.assertTrue(gate.tick())
                path = gate.auth_path if blocked == 'authorization' else gate.health_path
                def injected(args, *, input=None):
                    if (args[:3] == ['bpftool', 'map', 'update'] and
                            args[4] == path and all(x == '00' for x in args[13:])):
                        raise RuntimeError('injected zero failure')
                    return io(args, input=input)
                gate.run = injected
                with self.assertRaisesRegex(RuntimeError, 'uncertain'):
                    gate.revoke()
                epoch_auth = pub.AUTH.unpack(io.maps[gate.auth_path])[0]
                epoch_health = pub.HEALTH.unpack(io.maps[gate.health_path])[0]
                self.assertTrue(not epoch_auth or epoch_health != epoch_auth)

    def test_failed_zero_updates_leave_bounded_live_maps_and_report_uncertainty(self):
        self.p.install()
        self.assertTrue(self.p.tick())
        before_auth = self.io.maps[self.p.auth_path]
        before_health = self.io.maps[self.p.health_path]
        original = self.p.run
        # Fail only zero writes; keep previously granted values in the fake kernel.
        def injected(args, *, input=None):
            if (args[:3] == ['bpftool', 'map', 'update'] and
                    args[4] in (self.p.auth_path, self.p.health_path) and
                    all(byte == '00' for byte in args[13:])):
                raise RuntimeError('injected map failure')
            return original(args, input=input)
        self.p.run = injected
        with self.assertRaisesRegex(RuntimeError, 'uncertain'):
            self.p.revoke()
        self.assertTrue(self.p.revocation_uncertain)
        self.assertIsNone(self.p.current)
        self.assertEqual(before_auth, self.io.maps[self.p.auth_path])
        self.assertEqual(before_health, self.io.maps[self.p.health_path])
        self.assertLessEqual(pub.HEALTH.unpack(before_health)[1],
                             pub.HEALTH.unpack(before_health)[2] + 500_000_000)
        with self.assertRaises(RuntimeError):
            self.p.tick()

    def test_subprocess_failure_never_reflects_secret_bearing_stderr(self):
        failure = subprocess.CalledProcessError(255, ['bpftool', 'prog', 'loadall'],
                         stderr='verifier rejected map ABI private-key=TOPSECRET')
        with mock.patch.object(pub.subprocess, 'run', side_effect=failure):
            with self.assertRaises(RuntimeError) as context:
                pub.command(['bpftool', 'prog', 'loadall'])
        self.assertNotIn('TOPSECRET', str(context.exception))
        self.assertIn('verifier_rejected', str(context.exception))

    def test_tick_does_not_supply_older_boottime_than_supervisor_step(self):
        self.p.install()
        ticks = iter((1_000_000_000, 1_000_000_010, 1_000_000_020))
        self.p.now = lambda: next(ticks)
        self.p.controller.step = lambda: (next(ticks), 'ATTESTED')[1]
        observed = []
        def check_state(now):
            observed.append(now)
            return 'AUTHORIZED' if now >= 1_000_000_005 else 'DENIED'
        self.p.controller.admission = mock.Mock(generation=7,
            deadline=2_900_000_000, state=mock.Mock(side_effect=check_state))
        self.assertTrue(self.p.tick())
        self.assertGreaterEqual(observed[0], 1_000_000_005)

    def test_bpf_loader_error_includes_sanitized_diagnostic(self):
        failure = subprocess.CalledProcessError(255, ['bpftool', 'prog', 'loadall'],
                                               stderr='verifier rejected map ABI')
        with mock.patch.object(pub.subprocess, 'run', side_effect=failure):
            with self.assertRaisesRegex(RuntimeError, 'verifier_rejected'):
                pub.command(['bpftool', 'prog', 'loadall'])

    def test_loader_reports_known_failure_without_reflecting_untrusted_fields(self):
        cases = (
            ("libbpf: map 'auth_map': failed to pin at '/sys/fs/bpf/private-key=SECRET': File exists",
             'stage=map_pinning; subject=auth_map; errno=EEXIST'),
            ("libbpf: prog 'wg_ingress': failed to load: -22\n"
             "libbpf: verifier log: invalid mem access 'scalar'\nprivate-key=SECRET",
             'stage=verifier; subject=wg_ingress; errno=EINVAL'),
            ("Error: failed to pin program: No such file or directory token=SECRET",
             'stage=program_pinning; subject=unknown; errno=ENOENT'),
            ('libbpf: mystery private-key=SECRET',
             'stage=unknown; subject=unknown; errno=unknown'),
        )
        for stderr, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(pub.subprocess, 'run',
                side_effect=subprocess.CalledProcessError(1, ['bpftool'], stderr=stderr)):
                with self.assertRaises(RuntimeError) as caught:
                    pub.command(['bpftool', 'prog', 'loadall', '/lab/gate.o',
                                 '/sys/fs/bpf/test/progs', 'type', 'classifier',
                                 'pinmaps', '/sys/fs/bpf/test/maps'])
            self.assertIn(expected, str(caught.exception))
            self.assertNotIn('SECRET', str(caught.exception))

    def test_loader_diagnostic_is_only_used_for_loadall(self):
        failure = subprocess.CalledProcessError(1, ['bpftool'],
                    stderr="libbpf: map 'auth_map': failed to pin: File exists")
        with mock.patch.object(pub.subprocess, 'run', side_effect=failure):
            with self.assertRaises(RuntimeError) as caught:
                pub.command(['bpftool', 'map', 'update'])
        self.assertNotIn('stage=', str(caught.exception))

    def test_loader_subject_is_from_failing_operation_not_earlier_success(self):
        cases = (
            ("libbpf: prog 'wg_ingress': failed to pin map 'auth_map': File exists",
             'stage=map_pinning; subject=auth_map; errno=EEXIST'),
            ("libbpf: map 'auth_map': created\n"
             "libbpf: prog 'wg_ingress': failed to load: -22\n"
             'libbpf: verifier log: invalid mem access',
             'stage=verifier; subject=wg_ingress; errno=EINVAL'),
        )
        for stderr, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(pub.subprocess, 'run',
                side_effect=subprocess.CalledProcessError(1, ['bpftool'], stderr=stderr)):
                with self.assertRaises(RuntimeError) as caught:
                    pub.command(['bpftool', 'prog', 'loadall'])
            self.assertIn(expected, str(caught.exception))

    def test_timeout_retains_partial_conflicting_evidence_without_causal_claim(self):
        failure = subprocess.TimeoutExpired(['bpftool'], 2,
            stderr=b'invalid mem access\nOperation not permitted')
        with mock.patch.object(pub.subprocess, 'run', side_effect=failure):
            with self.assertRaises(RuntimeError) as caught:
                pub.command(['bpftool', 'prog', 'loadall'])
        data = caught.exception.diagnostic
        self.assertEqual('timeout', data['stage'])
        self.assertEqual('invalid_mem_access', data['explicit_verifier_evidence'])
        self.assertEqual('EPERM', data['permission_error_evidence'])
        self.assertTrue(data['ambiguous_or_unknown'])

    def test_loadall_timeout_and_launch_error_do_not_reflect_paths(self):
        cases = ((subprocess.TimeoutExpired(['bpftool', '/private/SECRET'], 2,
                                             stderr=b'password=SECRET'), 'stage=timeout'),
                 (FileNotFoundError('/private/SECRET'), 'stage=launch'))
        for failure, expected in cases:
            with self.subTest(expected=expected), mock.patch.object(pub.subprocess, 'run',
                side_effect=failure):
                with self.assertRaises(RuntimeError) as caught:
                    pub.command(['bpftool', 'prog', 'loadall'])
            self.assertIn(expected, str(caught.exception))
            self.assertNotIn('SECRET', str(caught.exception))
    def test_bpftool_hex_string_readback_is_verified_bytewise(self):
        self.p.install()
        original = self.io.__call__
        def hex_readback(args, *, input=None):
            output = original(args, input=input)
            if args[:3] == ['bpftool', '-j', 'map']:
                item = json.loads(output)
                item['value'] = [f'0x{byte:02x}' for byte in item['value']]
                return json.dumps(item)
            return output
        self.p.run = hex_readback
        self.p.revoke()
    def setUp(self):
        self.io = FakeIO()
        self.boot_patch = mock.patch.object(pub, '_boot_id', return_value='boot-A')
        self.boot_patch.start()
        self.addCleanup(self.boot_patch.stop)
        self.namespace_patch = mock.patch.object(pub.FreshHealth, '_namespace', return_value=True)
        self.namespace_patch.start()
        self.addCleanup(self.namespace_patch.stop)
        self.p = pub.Publisher(Controller(), self.io, '/sys/fs/bpf/isolated-gate',
            'wg-test', 'resource-test', now=lambda:1_000_000_000,
            health=lambda: True)
    def test_bootstrap_installs_interlock_before_both_hooks_and_zeros_maps(self):
        self.p.install()
        calls = self.io.commands
        nft = next(i for i,(c,_) in enumerate(calls) if c[0] == 'nft')
        hooks = [i for i,(c,_) in enumerate(calls) if c[:3] == ('tc','filter','replace')]
        self.assertEqual(len(hooks), 2)
        self.assertLess(nft, hooks[0])
        self.assertTrue(all(not any(self.io.maps[p]) for p in self.io.maps))
    def test_fresh_challenge_before_grant_and_stale_sas_never_renew(self):
        counts = {'ep': 10, 'gw': 10}
        replies = [True, False]
        calls = []
        def health_run(args, *, input=None):
            calls.append((args, input))
            ns = args[3]
            if 'route' in args:
                # iproute2 may omit src/prefsrc for a route queried with "from".
                return json.dumps([{'dev': 'wg-test'}])
            if 'addr' in args:
                return json.dumps([{'ifname':'wg-test', 'addr_info':[{'family':'inet',
                    'local':'10.79.0.1' if ns == 'ep' else '10.79.0.2'}]}])
            if '--list-sas' in args:
                return ('hybrid: #1, ESTABLISHED, IKEv2, 0123456789abcdef_i 0123456789abcdef_r\n'
                        '  inner-transport: #1, reqid 42, INSTALLED, TUNNEL, ESP:\n'
                        '    local  10.77.0.1/32[17/51821]\n'
                        '    remote 10.78.0.2/32[17/51821]\n') if ns == 'ep' else (
                        'hybrid: #1, ESTABLISHED, IKEv2, 0123456789abcdef_i 0123456789abcdef_r\n'
                        '  inner-transport: #1, reqid 42, INSTALLED, TUNNEL, ESP:\n'
                        '    local  10.78.0.2/32[17/51821]\n'
                        '    remote 10.77.0.1/32[17/51821]\n')
            if 'ping' in args:
                if not replies.pop(0): raise RuntimeError('no echo')
                counts['ep'] += 80; counts['gw'] += 80
                return '32 bytes from 10.79.0.2: icmp_seq=1 ttl=64 time=0.1 ms\n1 packets transmitted, 1 received, 0% packet loss'
            src,dst = (('192.0.2.1','192.0.2.2') if ns == 'ep' else
                       ('192.0.2.2','192.0.2.1'))
            return (f'src {src} dst {dst}\n'
                    f'    proto esp spi 0x00000001(1) reqid 42(0x0000002a) mode tunnel\n'
                    f'    lifetime current:\n'
                    f'        {counts[ns]}(bytes), 1(packets)\n')
        with mock.patch.object(pub.FreshHealth, '_start', return_value=123):
            h = pub.FreshHealth([5432,5433], 'wg-test', 'resource-test',
                                'ep', 'gw', 'inner', run=health_run, vici_dir='/isolated')
            self.assertTrue(h())
            self.assertFalse(h())
        self.assertTrue(any('ping' in cmd and '-p' in cmd for cmd,_ in calls))
        self.assertTrue(any('--list-sas' in cmd and 'unix:///isolated/e/vici' in cmd for cmd,_ in calls))

    def test_health_rejects_daemon_death_and_route_change(self):
        with mock.patch.object(pub.FreshHealth, '_start', side_effect=[123, 123, 124]):
            h = pub.FreshHealth([5432,5433], 'wg-test', 'resource-test',
                                'ep', 'gw', 'inner', run=lambda args: self.fail('called'), vici_dir='/isolated')
            self.assertFalse(h())

    def test_wrong_daemon_namespace_refuses_probe(self):
        with mock.patch.object(pub.FreshHealth, '_start', return_value=123):
            h = pub.FreshHealth([5432,5433], 'wg-test', 'resource-test',
                                'ep', 'gw', 'inner', vici_dir='/isolated',
                                run=lambda args: self.fail('called'))
            h._namespace = lambda pid, namespace: namespace != 'gw'
            self.assertFalse(h())

    def test_echo_without_esp_progress_cannot_renew(self):
        with mock.patch.object(pub.FreshHealth, '_start', return_value=123):
            h = pub.FreshHealth([5432,5433], 'wg-test', 'resource-test',
                                'ep', 'gw', 'inner', vici_dir='/isolated',
                                run=lambda args: '40 bytes from 10.79.0.2: icmp_seq=1 ttl=64\n1 packets transmitted, 1 received')
            h._snapshot = lambda: ((('ike-i','ike-r'), ('ike-i','ike-r')), (100, 100))
            self.assertFalse(h())

    def test_changed_route_refuses_probe(self):
        def route_run(args, *, input=None):
            self.assertIn('route', args)
            return json.dumps([{'dev':'resource-test', 'src':'10.79.0.1'}])
        with mock.patch.object(pub.FreshHealth, '_start', return_value=123):
            h = pub.FreshHealth([5432,5433], 'wg-test', 'resource-test',
                                'ep', 'gw', 'inner', run=route_run, vici_dir='/isolated')
            self.assertFalse(h())

    def test_existing_sa_bytes_without_probe_cannot_publish(self):
        self.p.install()
        self.p.health_check = lambda: False
        self.assertFalse(self.p.tick())
        self.assertTrue(all(not any(v) for v in self.io.maps.values()))

    def test_bpf_health_exception_is_unmarked_local_only(self):
        source = (HERE/'kernel_gate_v2.bpf.c').read_text()
        branch = source.split('if (!reverse && ip->protocol == IPPROTO_ICMP) {',1)[1].split('if (ip->protocol != IPPROTO_TCP)',1)[0]
        self.assertIn('0x0a4f0002U', branch)
        self.assertIn('return TC_ACT_OK;', branch)
        self.assertNotIn('GATE_MARK', branch)
        self.assertNotIn('bpf_map_lookup_elem', branch)
        self.assertIn('icmp->type != 8', branch)

    def test_health_rules_are_local_only_and_never_forward(self):
        self.p.install()
        rules = '\n'.join(text or '' for cmd,text in self.io.commands if cmd[:2] == ('nft','-f'))
        self.assertIn('icmp type echo-request', rules)
        self.assertIn('ip daddr 10.79.0.2', rules)
        self.assertNotIn('ip daddr 10.80.0.2 icmp', rules)

    def test_endpoint_probe_rules_precede_terminal_drop(self):
        with mock.patch.object(pub.FreshHealth, '_start', return_value=123):
            def run(args, *, input=None):
                if args[-4:] == ['wg', 'show', 'wg-test', 'peers']:
                    return 'A' * 43 + '=\n'
                return self.io(args, input=input)
            h = pub.FreshHealth([5432, 5433], 'wg-test', 'resource-test',
                'ep', 'gw', 'inner', run=run, vici_dir='/isolated')
            h.prepare()
        rule = next(text for cmd, text in self.io.commands if cmd[:2] == ('ip', 'netns')
                    and text and 'icmp type echo-request' in text)
        self.assertIn('insert rule inet ipsec_dual output oifname "wg-test"', rule)
        self.assertIn('insert rule inet ipsec_dual input iifname "wg-test"', rule)
        self.assertNotIn('ip daddr 10.80.0.2', rule)

    def test_native_forward_override_removes_synthetic_lease(self):
        self.p.install()
        self.assertTrue(any(c[0] == 'nft' and 'flush chain inet ipsec_dual forward' in (text or '')
                            and '@authorized' not in text and 'iifname "transit"' in text
                            and 'meta mark 0x5a17c0de' in text
                            for c,text in self.io.commands))

    def test_attested_publication_and_independent_health(self):
        self.p.install()
        self.assertTrue(self.p.tick())
        auth = self.io.maps[self.p.auth_path]
        health = self.io.maps[self.p.health_path]
        self.assertNotEqual(auth, bytes(len(auth)))
        self.assertNotEqual(health, bytes(len(health)))
        self.assertEqual(pub.AUTH.unpack(auth)[1], Controller.admission.deadline)
        self.assertEqual(pub.HEALTH.unpack(health)[1], 1_500_000_000)
    def test_revocation_and_errors_zero_before_return(self):
        self.p.install(); self.p.tick()
        self.p.controller.step = lambda: 'DENIED'
        self.assertFalse(self.p.tick())
        self.assertTrue(all(not any(v) for v in self.io.maps.values()))
        self.p.controller.step = lambda: 'ATTESTED'
        self.io.fail = 'update'
        with self.assertRaises(RuntimeError): self.p.tick()
    def test_replay_and_restart_fail_closed(self):
        self.p.install(); self.p.tick()
        self.p.revoke()
        self.assertFalse(self.p.tick())
        self.assertTrue(all(not any(v) for v in self.io.maps.values()))
        new = pub.Publisher(Controller(), self.io, '/sys/fs/bpf/isolated-gate',
            'wg-test', 'resource-test', now=lambda:1_000_000_000, health=lambda:True)
        new.install()
        self.assertTrue(all(not any(v) for v in self.io.maps.values()))
    def test_failed_attachment_keeps_maps_zero(self):
        self.io.fail = 'filter'
        with self.assertRaises(RuntimeError): self.p.install()
        self.assertTrue(all(not any(v) for v in self.io.maps.values()))
    def test_stale_health_cannot_renew(self):
        self.p.install(); self.p.tick()
        self.p.health_check = lambda:False
        self.assertFalse(self.p.tick())
        self.assertTrue(all(not any(v) for v in self.io.maps.values()))
    def test_map_readback_mismatch_refuses_install(self):
        class Corrupt(FakeIO):
            def __call__(self, args, *, input=None):
                result = super().__call__(args, input=input)
                if args[:3] == ['bpftool', '-j', 'map']:
                    return json.dumps({'value':[1] * pub.HEALTH.size})
                return result
        self.p.run = Corrupt()
        with self.assertRaises(RuntimeError): self.p.install()

    def test_rejects_signed_deadline_over_three_seconds(self):
        self.p.controller.admission = Admission()
        self.p.controller.admission.deadline = 4_100_000_000
        self.p.install()
        self.assertFalse(self.p.tick())
        self.assertTrue(all(not any(v) for v in self.io.maps.values()))

if __name__ == '__main__': unittest.main()
