"""Nonprivileged contract tests for the isolated loader-only probe."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).parent
spec = importlib.util.spec_from_file_location('loader_only_probe', HERE/'loader_only_probe.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class LoaderOnlyTests(unittest.TestCase):
    def test_raw_capture_preserves_full_streams_with_private_exclusive_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = "import os;os.write(1,b'A'*100000);os.write(2,b'B'*120000)"
            result = probe._run([sys.executable, '-B', '-c', script],
                                binary=True, raw_dir=root)
            self.assertEqual(0, result.returncode)
            for name, expected in (('bpftool.stdout', b'A'*100000),
                                   ('bpftool.stderr', b'B'*120000)):
                path = root/name
                self.assertEqual(expected, path.read_bytes())
                self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                probe._run([sys.executable, '-c', 'pass'], binary=True, raw_dir=root)

    def test_binary_capture_is_memory_bounded_and_counts_actual_bytes(self):
        script = "import os;os.write(1,b'A'*100000+b'ENDOUT');os.write(2,b'B'*120000+b'ENDERR')"
        result = probe._run([sys.executable, '-B', '-c', script], binary=True)
        self.assertEqual(0, result.returncode)
        self.assertEqual(100006, result.stream_stats['stdout_bytes'])
        self.assertEqual(120006, result.stream_stats['stderr_bytes'])
        self.assertTrue(result.stream_stats['stdout_truncated'])
        self.assertTrue(result.stream_stats['stderr_truncated'])
        self.assertLessEqual(len(result.stdout), 8193)
        self.assertLessEqual(len(result.stderr), 8193)
        self.assertTrue(result.stdout.endswith(b'ENDOUT'))
        self.assertTrue(result.stderr.endswith(b'ENDERR'))

    def test_closed_pipes_do_not_kill_child_before_it_exits(self):
        script = 'import os,time,sys;os.close(1);os.close(2);time.sleep(0.15);sys.exit(7)'
        result = probe._run([sys.executable, '-B', '-c', script], binary=True)
        self.assertEqual(7, result.returncode)

    def test_late_pin_error_not_lost_after_two_bounded_streams(self):
        record = {}
        text = probe._load_diagnostics(record, b'x'*9000,
            b'y'*9000 + b"\nlibbpf: map 'auth_map': failed to pin: File exists\n")
        self.assertEqual(('map_pin_failure', 'unknown', 'auth_map', 'EEXIST'),
                         probe.classify(text)[:4])

    def test_generic_verifier_word_with_permission_error_is_not_rejection(self):
        self.assertEqual('permission_denied', probe.classify(
            'libbpf: verifier log available\nlibbpf: prog failed to load: Operation not permitted')[0])

    def test_probe_report_keeps_both_conflicting_evidence_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); obj = root/'gate.o'; obj.write_bytes(b'fixture')
            raw = (b"libbpf: prog 'wg_ingress': failed to load: Operation not permitted\n"
                   b"invalid mem access 'scalar' private-key=SECRET")
            def run(args, **kwargs):
                if args[0] == 'clang':
                    return subprocess.CompletedProcess(args, 0, '', '')
                return subprocess.CompletedProcess(args, 255, b'', raw)
            report = root/'report.json'
            with mock.patch.object(probe, '_run', side_effect=run):
                self.assertEqual(1, probe.probe(obj, report, root/'pins', source=HERE/'kernel_gate_v2.bpf.c'))
            data = json.loads(report.read_text())
            self.assertEqual('ambiguous', data['category'])
            self.assertEqual('invalid_mem_access', data['explicit_verifier_evidence'])
            self.assertEqual('EPERM', data['permission_error_evidence'])
            self.assertEqual('bpftool', data['failing_executable'])
            self.assertEqual('prog loadall', data['failing_operation'])
            self.assertNotIn('SECRET', report.read_text())

    def test_probe_uses_stderr_pin_failure_over_stdout_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); obj = root/'gate.o'; obj.write_bytes(b'fixture')
            def run(args, **kwargs):
                if args[0] == 'clang':
                    return subprocess.CompletedProcess(args, 0, '', '')
                return subprocess.CompletedProcess(args, 255,
                    b'Error: failed to load object file',
                    b"libbpf: map 'health_map': failed to pin: File exists")
            report = root/'report.json'
            with mock.patch.object(probe, '_run', side_effect=run):
                self.assertEqual(1, probe.probe(obj, report, root/'pins', source=HERE/'kernel_gate_v2.bpf.c'))
            data = json.loads(report.read_text())
            self.assertEqual('map_pin_failure', data['category'])
            self.assertEqual('health_map', data['subject'])

    def test_unattributed_pin_error_not_overridden_by_earlier_abi_text(self):
        self.assertEqual('installation_failure', probe.classify(
            'map ABI mismatch\nlibbpf: failed to pin: File exists')[0])

    def test_load_failure_records_bounded_stream_metadata_and_redacted_argv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); obj = root/'secret-object.o'; obj.write_bytes(b'fixture')
            pin = root/'pins'; report = root/'report.json'
            stdout = b'Error: failed to load object file\n'
            stderr = (b'libbpf: -- BEGIN PROG LOAD LOG --\n' + b'private_key=SECRET\n'*600 +
                      b'libbpf: prog \'wg_ingress\': failed to load: -22\ninvalid mem access \'scalar\'\n')
            def run(args, **kwargs):
                if args[0] == 'clang':
                    return subprocess.CompletedProcess(args, 0, '', '')
                self.assertEqual(['bpftool', '-d', 'prog', 'loadall', str(obj),
                                  str(pin/'progs'), 'type', 'classifier', 'pinmaps',
                                  str(pin/'maps')], args)
                self.assertTrue(kwargs['binary'])
                return subprocess.CompletedProcess(args, 255, stdout, stderr)
            with mock.patch.object(probe, '_run', side_effect=run):
                self.assertEqual(1, probe.probe(obj, report, pin, source=HERE/'kernel_gate_v2.bpf.c'))
            data = json.loads(report.read_text())
            self.assertEqual(['bpftool', '-d', 'prog', 'loadall', '<object>', '<progs>',
                              'type', 'classifier', 'pinmaps', '<maps>'], data['argv'])
            self.assertEqual(255, data['load_exit_code'])
            self.assertEqual(len(stdout), data['stdout_bytes'])
            self.assertEqual(len(stderr), data['stderr_bytes'])
            self.assertTrue(data['stderr_truncated'])
            self.assertFalse(data['stdout_truncated'])
            self.assertTrue(data['verifier_log_present'])
            self.assertEqual('verifier_rejected', data['category'])
            self.assertIn('invalid_mem_access', data['loader_messages'])
            self.assertNotIn('SECRET', report.read_text())
            self.assertNotIn(str(root), report.read_text())

    def test_stdout_only_program_load_error_is_visible_without_guessing_verifier_cause(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); obj = root/'gate.o'; obj.write_bytes(b'fixture')
            def run(args, **kwargs):
                if args[0] == 'clang':
                    return subprocess.CompletedProcess(args, 0, '', '')
                return subprocess.CompletedProcess(args, 255,
                    b"libbpf: prog 'wg_ingress': failed to load: -22\nsecret=NEVER\n", b'')
            report = root/'report.json'
            with mock.patch.object(probe, '_run', side_effect=run):
                self.assertEqual(1, probe.probe(obj, report, root/'pin', source=HERE/'kernel_gate_v2.bpf.c'))
            data = json.loads(report.read_text())
            self.assertEqual('program_load_failed', data['category'])
            self.assertEqual('EINVAL', data['errno'])
            self.assertEqual('wg_ingress', data['subject'])
            self.assertFalse(data['verifier_log_present'])
            self.assertIn('program_load_failed', data['loader_messages'])
            self.assertNotIn('NEVER', report.read_text())

    def test_timeout_records_partial_stream_counts_without_leaking_exception(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); obj = root/'gate.o'; obj.write_bytes(b'fixture')
            def run(args, **kwargs):
                if args[0] == 'clang':
                    return subprocess.CompletedProcess(args, 0, '', '')
                raise subprocess.TimeoutExpired(args, 2, output=b'private_key=SECRET',
                                                stderr=b'libbpf: -- BEGIN PROG LOAD LOG --\n')
            report = root/'report.json'
            with mock.patch.object(probe, '_run', side_effect=run):
                self.assertEqual(1, probe.probe(obj, report, root/'pin', source=HERE/'kernel_gate_v2.bpf.c'))
            data = json.loads(report.read_text())
            self.assertEqual('timeout', data['category'])
            self.assertIsNone(data['load_exit_code'])
            self.assertEqual(len(b'private_key=SECRET'), data['stdout_bytes'])
            self.assertTrue(data['verifier_log_present'])
            self.assertEqual('unknown', data['explicit_verifier_evidence'])
            self.assertNotIn('SECRET', report.read_text())

    def test_two_large_streams_preserve_stderr_tail_category(self):
        record = {}
        text = probe._load_diagnostics(record, b'x'*9000,
            b'y'*9000 + b'\nmap ABI mismatch\n')
        self.assertIn('map ABI mismatch', text)
        self.assertEqual('map_abi_mismatch', probe.classify(text)[0])

    def test_inspection_timeout_does_not_replace_successful_load_counts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); obj = root/'gate.o'; obj.write_bytes(b'fixture')
            pin = root/'pins'; report = root/'report.json'
            def run(args, **kwargs):
                if args[:4] == ['bpftool', '-d', 'prog', 'loadall']:
                    for name in probe.MAP_ABI:
                        (pin/'maps'/name).touch()
                    for name in probe.PROGRAMS:
                        (pin/'progs'/name).touch()
                    return subprocess.CompletedProcess(args, 0, b'loader output', b'')
                if args[:3] == ['bpftool', '-j', 'map']:
                    raise subprocess.TimeoutExpired(args, 2, stderr=b'inspection output')
                return subprocess.CompletedProcess(args, 0, '', '')
            with mock.patch.object(probe, '_run', side_effect=run):
                self.assertEqual(1, probe.probe(obj, report, pin, source=HERE/'kernel_gate_v2.bpf.c'))
            data = json.loads(report.read_text())
            self.assertEqual(0, data['load_exit_code'])
            self.assertEqual(len(b'loader output'), data['stdout_bytes'])
            self.assertEqual('bpftool -j map show pinned <map>', data['failing_subprocess'])
            self.assertEqual('timeout', data['category'])

    def test_failure_records_exact_operation_exit_and_bounded_sanitized_verifier(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            object_path = root/'gate.o'
            object_path.write_bytes(b'fixture')
            evidence = root/'report.json'
            pin = root/'pins'
            raw = ("libbpf: prog 'wg_ingress': failed to load: -22\n"
                   "invalid mem access 'scalar'\nprivate-key=SECRET\n")
            def run(args, **kwargs):
                if args[0] == 'clang':
                    return subprocess.CompletedProcess(args, 0, '', '')
                self.assertEqual(['bpftool', '-d', 'prog', 'loadall', str(object_path),
                                  str(pin/'progs'), 'type', 'classifier', 'pinmaps',
                                  str(pin/'maps')], args)
                return subprocess.CompletedProcess(args, 255, '', raw)
            with mock.patch.object(probe, '_run', side_effect=run):
                code = probe.probe(object_path, evidence, pin, source=HERE/'kernel_gate_v2.bpf.c')
            record = json.loads(evidence.read_text())
            self.assertEqual(1, code)
            self.assertEqual('bpftool -d prog loadall <object> <progs> type classifier pinmaps <maps>',
                             record['failing_subprocess'])
            self.assertEqual(255, record['exit_code'])
            self.assertEqual('verifier_rejected', record['category'])
            self.assertEqual('invalid_mem_access', record['verifier_reason'])
            self.assertEqual(['invalid_mem_access'], record['verifier_output'])
            self.assertNotIn('SECRET', json.dumps(record))
            self.assertFalse(pin.exists())

    def test_success_requires_exact_pin_abi_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            obj, evidence, pin = root/'gate.o', root/'report.json', root/'pins'
            obj.write_bytes(b'fixture')
            def run(args, **kwargs):
                if args[:3] == ['bpftool', '-j', 'map']:
                    name = Path(args[-1]).name
                    expected = {'auth_map': 32, 'health_map': 40, 'verdict_map': 8}[name]
                    output = json.dumps({'type':'array', 'key':4, 'value':expected,
                                         'max_entries':32 if name=='verdict_map' else 1})
                    return subprocess.CompletedProcess(args, 0, output, '')
                if args[:3] == ['bpftool', '-j', 'prog']:
                    return subprocess.CompletedProcess(args, 0, '{"type":"sched_cls"}', '')
                return subprocess.CompletedProcess(args, 0, '', '')
            # Fake bpffs pins created by the kernel on successful load.
            def simulate(args, **kwargs):
                result = run(args, **kwargs)
                if args[:4] == ['bpftool', '-d', 'prog', 'loadall']:
                    for name in ('auth_map','health_map','verdict_map'):
                        (pin/'maps'/name).touch()
                    for name in ('wg_ingress','resource_ingress'):
                        (pin/'progs'/name).touch()
                return result
            with mock.patch.object(probe, '_run', side_effect=simulate):
                code = probe.probe(obj, evidence, pin, source=HERE/'kernel_gate_v2.bpf.c')
            record = json.loads(evidence.read_text())
            self.assertEqual(0, code)
            self.assertEqual('PASS', record['map_pinning_status'])
            self.assertEqual('PASS', record['verifier_load'])
            self.assertFalse(pin.exists())

    def test_unknown_failure_stays_unknown_and_never_reflects_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            obj, evidence, pin = root/'gate.o', root/'report.json', root/'pins'
            obj.write_bytes(b'fixture')
            def fail(args, **kwargs):
                if args[0] == 'clang':
                    return subprocess.CompletedProcess(args, 0, '', '')
                return subprocess.CompletedProcess(args, 1, '', 'secret=/lab/private/key')
            with mock.patch.object(probe, '_run', side_effect=fail):
                self.assertEqual(1, probe.probe(obj, evidence, pin,
                                                 source=HERE/'kernel_gate_v2.bpf.c'))
            data = json.loads(evidence.read_text())
            self.assertEqual('unknown', data['category'])
            self.assertEqual([], data['verifier_output'])
            self.assertNotIn('/lab/private', json.dumps(data))

    def test_success_with_cleanup_failure_is_not_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            obj, evidence, pin = root/'gate.o', root/'report.json', root/'pins'
            obj.write_bytes(b'fixture')
            def run(args, **kwargs):
                if args[:4] == ['bpftool', '-d', 'prog', 'loadall']:
                    for name in ('auth_map','health_map','verdict_map'):
                        (pin/'maps'/name).touch()
                    for name in ('wg_ingress','resource_ingress'):
                        (pin/'progs'/name).touch()
                    (pin/'maps'/'foreign_pin').touch()
                if args[:3] == ['bpftool', '-j', 'map']:
                    name = Path(args[-1]).name
                    return subprocess.CompletedProcess(args, 0, json.dumps({
                        'type':'array', 'bytes_key':4,
                        'bytes_value':{'auth_map':32,'health_map':40,'verdict_map':8}[name],
                        'max_entries':32 if name=='verdict_map' else 1}), '')
                if args[:3] == ['bpftool', '-j', 'prog']:
                    return subprocess.CompletedProcess(args, 0, '{"type":"sched_cls"}', '')
                return subprocess.CompletedProcess(args, 0, '', '')
            with mock.patch.object(probe, '_run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                    probe.probe(obj, evidence, pin, source=HERE/'kernel_gate_v2.bpf.c')
            self.assertEqual('FAIL', json.loads(evidence.read_text())['cleanup'])

    def test_map_inspection_failure_records_inspection_command_and_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            obj, evidence, pin = root/'gate.o', root/'report.json', root/'pins'
            obj.write_bytes(b'fixture')
            def run(args, **kwargs):
                if args[:4] == ['bpftool', '-d', 'prog', 'loadall']:
                    for name in ('auth_map','health_map','verdict_map'):
                        (pin/'maps'/name).touch()
                    for name in ('wg_ingress','resource_ingress'):
                        (pin/'progs'/name).touch()
                if args[:3] == ['bpftool', '-j', 'map']:
                    return subprocess.CompletedProcess(args, 42, '', 'token=SECRET')
                return subprocess.CompletedProcess(args, 0, '', '')
            with mock.patch.object(probe, '_run', side_effect=run):
                self.assertEqual(1, probe.probe(obj, evidence, pin,
                                                 source=HERE/'kernel_gate_v2.bpf.c'))
            data = json.loads(evidence.read_text())
            self.assertEqual('bpftool -j map show pinned <map>', data['failing_subprocess'])
            self.assertEqual('map show pinned', data['failing_operation'])
            self.assertEqual('bpftool', data['failing_executable'])
            self.assertEqual(42, data['exit_code'])
            self.assertNotIn('SECRET', json.dumps(data))

    def test_existing_pin_directory_is_never_cleaned(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pin = root/'pins'
            (pin/'maps').mkdir(parents=True)
            (pin/'maps'/'auth_map').write_text('owned elsewhere')
            obj = root/'gate.o'; obj.write_bytes(b'fixture')
            with mock.patch.object(probe, '_run') as command:
                self.assertEqual(1, probe.probe(obj, root/'report.json', pin,
                                                 source=HERE/'kernel_gate_v2.bpf.c'))
            command.assert_not_called()
            self.assertEqual('owned elsewhere', (pin/'maps'/'auth_map').read_text())
            self.assertEqual('pin_directory_exists',
                             json.loads((root/'report.json').read_text())['category'])

    def test_mount_timeout_keeps_sanitized_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(probe, 'EVIDENCE_ROOT', root/'loader'), \
                 mock.patch.object(probe, 'check_container', return_value=True), \
                 mock.patch.object(probe, 'mount_is_private', return_value=True), \
                 mock.patch.object(probe.subprocess, 'run',
                     side_effect=subprocess.TimeoutExpired(['mount', 'SECRET'], 2)):
                self.assertEqual(1, probe.main())
            report = json.loads((root/'loader'/'report.json').read_text())
            self.assertEqual('mount -t bpf', report['failing_subprocess'])
            self.assertIsNone(report['exit_code'])
            self.assertEqual('mount_timeout', report['category'])
            self.assertNotIn('SECRET', json.dumps(report))

    def test_missing_pin_has_no_failing_subprocess_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); obj = root/'gate.o'; obj.write_bytes(b'fixture')
            with mock.patch.object(probe, '_run', return_value=
                subprocess.CompletedProcess(['bpftool'], 0, '', '')):
                self.assertEqual(1, probe.probe(obj, root/'report.json', root/'pin',
                                                 source=HERE/'kernel_gate_v2.bpf.c'))
            report = json.loads((root/'report.json').read_text())
            self.assertEqual('none', report['failing_subprocess'])
            self.assertEqual('none', report['failing_operation'])
            self.assertIsNone(report['exit_code'])
            self.assertEqual(0, report['load_exit_code'])

    def test_pin_failure_does_not_inherit_prior_verifier_reason(self):
        stderr = ("libbpf: prog 'wg_ingress': failed to load: -22\n"
                  "invalid mem access 'scalar' map ABI mismatch\n"
                  "libbpf: map 'auth_map': failed to pin: File exists")
        category, reason, subject, errno, output = probe.classify(stderr)
        self.assertEqual('map_pin_failure', category)
        self.assertEqual('unknown', reason)
        self.assertEqual([], output)

    def test_mount_propagation_guard(self):
        samples = (
            ('42 3 0:1 / /sys rw - sysfs sysfs rw\n', True),
            ('42 3 0:1 / /sys rw shared:12 - sysfs sysfs rw\n', False),
            ('42 3 0:1 / /sys rw master:12 - sysfs sysfs rw\n', False),
            ('42 3 0:1 / /sys rw - sysfs sysfs rw\n'
             '43 42 0:2 / /sys/fs/bpf rw shared:15 - bpf bpf rw\n', False),
        )
        for data, expected in samples:
            with self.subTest(data=data), mock.patch.object(probe.Path, 'read_text',
                                                             return_value=data):
                self.assertEqual(expected, probe.mount_is_private())

    def test_mount_launch_failure_keeps_sanitized_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(probe, 'EVIDENCE_ROOT', root/'loader'), \
                 mock.patch.object(probe, 'check_container', return_value=True), \
                 mock.patch.object(probe, 'mount_is_private', return_value=True), \
                 mock.patch.object(probe.subprocess, 'run',
                                   side_effect=FileNotFoundError('SECRET')):
                self.assertEqual(1, probe.main())
            report = json.loads((root/'loader'/'report.json').read_text())
            self.assertEqual('mount_launch_failed', report['category'])
            self.assertIsNone(report['exit_code'])
            self.assertNotIn('SECRET', json.dumps(report))

if __name__ == '__main__': unittest.main()
