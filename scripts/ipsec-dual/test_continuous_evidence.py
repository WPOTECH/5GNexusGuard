"""Unprivileged regressions for the opt-in physical packet evidence runner."""
import json
from pathlib import Path
import socket
import socketserver
import tempfile
import threading
import time
import unittest
from unittest import mock

from continuous_evidence import (denial_bracket, grant_bracket, CaptureSet, measure,
                                 EvidenceError, TrafficStream, namespace_capture)


class EvidenceTests(unittest.TestCase):
    def test_namespace_capture_requests_immediate_kernel_delivery(self):
        with tempfile.TemporaryDirectory() as root:
            p = Path(root)
            with mock.patch('continuous_evidence.subprocess.Popen') as spawn:
                namespace_capture('e', 'wg-inner', 'all', p/'probe.pcap', p/'probe.status')
            argv = spawn.call_args.args[0]
            self.assertIn('--immediate-mode', argv)
            self.assertEqual(argv[argv.index('-i')+1], 'wg-inner')

    def test_grant_requires_denial_before_and_delivery_after_callback(self):
        rows = [dict(attempt_ns=1, verdict_ns=2, delivered=False),
                dict(attempt_ns=3, verdict_ns=4, delivered=True)]
        self.assertEqual(grant_bracket(rows, 2)['first_delivered_ns'], 4)
        with self.assertRaises(EvidenceError):
            grant_bracket(rows[1:], 2)

    def test_measure_records_hook_reap_timestamp(self):
        with tempfile.TemporaryDirectory() as root:
            class Stream:
                def start(self, directory): pass
                def ready(self, delivered=True): pass
                def stop(self):
                    return [dict(attempt_ns=1, verdict_ns=2, delivered=True),
                            dict(attempt_ns=3, verdict_ns=4, delivered=False)]
            class Capture:
                def start(self, directory): pass
                def stop(self): pass
            result = measure(Path(root), 'charon_death',
                             {'charon_death': lambda: {'signal_ns': 2, 'reaped_ns': 3}},
                             Stream(), Capture(), clock=lambda: 2, wait_seconds=0)
            self.assertEqual(result['hook']['reaped_ns'], 3)

    def test_real_continuous_echo_delivers_then_denies_without_refresh(self):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                while True:
                    data = self.request.recv(4096)
                    if not data:
                        return
                    if not self.server.denied:
                        self.request.sendall(data)
        with tempfile.TemporaryDirectory() as root:
            with socketserver.ThreadingTCPServer(('127.0.0.1', 0), Handler) as server:
                server.denied = False
                runner = threading.Thread(target=server.serve_forever, daemon=True)
                runner.start()
                stream = TrafficStream('127.0.0.1', server.server_address[1], interval=.005,
                                       timeout=.04)
                stream.start(Path(root))
                try:
                    stream.ready()
                    fault_ns = time.monotonic_ns()
                    server.denied = True
                    time.sleep(.2)
                finally:
                    rows = stream.stop()
                bracket = denial_bracket(rows, fault_ns)
                self.assertGreater(bracket['attempts'], 2)
                self.assertTrue(all('attempt_ns' in row and 'verdict_ns' in row
                                    for row in rows))

    def test_bracket_uses_each_delivery_and_denial_on_monotonic_clock(self):
        rows = [dict(attempt_ns=100, verdict_ns=110, delivered=True),
                dict(attempt_ns=120, verdict_ns=130, delivered=True),
                dict(attempt_ns=140, verdict_ns=151, delivered=False)]
        result = denial_bracket(rows, 135)
        self.assertEqual(result['last_delivered_ns'], 130)
        self.assertEqual(result['first_denied_attempt_ns'], 140)
        self.assertEqual(result['first_denied_verdict_ns'], 151)
        self.assertEqual(result['event_ns'], 135)

    def test_daemon_death_window_includes_post_death_deliveries(self):
        rows = [dict(attempt_ns=1, verdict_ns=2, delivered=True),
                dict(attempt_ns=3, verdict_ns=4, delivered=True),
                dict(attempt_ns=5, verdict_ns=6, delivered=False)]
        result = denial_bracket(rows, 2)
        self.assertEqual(result['last_delivered_ns'], 4)
        self.assertEqual(result['first_denied_attempt_ns'], 5)

    def test_bracket_rejects_sparse_or_out_of_order_evidence(self):
        with self.assertRaises(EvidenceError):
            denial_bracket([dict(attempt_ns=1, verdict_ns=2, delivered=True)], 3)
        with self.assertRaises(EvidenceError):
            denial_bracket([dict(attempt_ns=1, verdict_ns=5, delivered=True),
                            dict(attempt_ns=4, verdict_ns=6, delivered=False)], 3)
        with self.assertRaises(EvidenceError):
            denial_bracket([dict(attempt_ns=1, verdict_ns=2, delivered=True),
                            dict(attempt_ns=3, verdict_ns=4, delivered=False),
                            dict(attempt_ns=5, verdict_ns=6, delivered=True)], 2)

    def test_measure_calls_only_selected_external_hook_and_never_renews(self):
        with tempfile.TemporaryDirectory() as root:
            events = []
            class FakeStream:
                def start(self, directory):
                    events.append('start')
                def ready(self):
                    events.append('ready')
                def stop(self):
                    events.append('stop')
                    return [dict(attempt_ns=1, verdict_ns=2, delivered=True),
                            dict(attempt_ns=3, verdict_ns=4, delivered=False)]
            class FakeCapture:
                def start(self, directory):
                    events.append('capture-start')
                def stop(self):
                    events.append('capture-stop')
            result = measure(Path(root), 'aa_outage', {'aa_outage': lambda: events.append('fault')},
                             FakeStream(), FakeCapture(), clock=lambda: 2)
            self.assertEqual(events, ['capture-start', 'start', 'ready', 'fault', 'stop', 'capture-stop'])
            self.assertEqual(result['last_delivered_ns'], 2)
            self.assertEqual(json.loads((Path(root) / 'aa_outage' / 'summary.json').read_text()), result)

    def test_missing_hook_refuses_to_measure(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(EvidenceError):
                measure(Path(root), 'grant', {}, None, None)

    def test_capture_rejects_drops_or_missing_summary(self):
        with tempfile.TemporaryDirectory() as root:
            class Child:
                returncode = 0
                def poll(self): return None
                def send_signal(self, sig): pass
                def wait(self, timeout=None): return 0
            def spawn(role, interface, direction, pcap, status):
                pcap.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\x00' * 20)
                status.write_text('listening on ' + interface + '\n0 packets dropped by kernel\n')
                return Child()
            captures = CaptureSet(spawn=spawn, boundaries=(('e', 'pub', 'endpoint-public'),))
            captures.start(Path(root))
            captures.stop()
            self.assertEqual(len(list(Path(root).glob('*.pcap'))), 2)
            captures = CaptureSet(spawn=spawn, boundaries=(('e', 'pub', 'endpoint-public'),))
            captures.start(Path(root))
            (Path(root) / 'endpoint-public-wire-egress.capture-status').write_text(
                'listening on pub\n1 packets dropped by kernel\n')
            with self.assertRaises(EvidenceError):
                captures.stop()

    def test_partial_capture_start_stops_already_started_child(self):
        with tempfile.TemporaryDirectory() as root:
            class Child:
                returncode = None
                stopped = False
                def poll(self): return None if not self.stopped else 0
                def send_signal(self, sig): self.stopped = True
                def wait(self, timeout=None): self.returncode = 0
            child = Child()
            def spawn(role, interface, direction, pcap, status):
                if direction == 'out':
                    raise OSError('inject failed capture launch')
                status.write_text('listening on pub\n0 packets dropped by kernel\n')
                pcap.write_bytes(b'\x00' * 24)
                return child
            captures = CaptureSet(spawn=spawn, boundaries=(('e', 'pub', 'endpoint-public'),))
            with self.assertRaises(OSError):
                captures.start(Path(root))
            self.assertTrue(child.stopped)


if __name__ == '__main__':
    unittest.main()
