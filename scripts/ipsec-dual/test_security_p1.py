"""Focused acceptance controls; no privileged operations or fake packet claims."""
import unittest
from continuous_evidence import EvidenceError
from security_p1 import assert_no_extension, verify_denial


class SecurityP1Tests(unittest.TestCase):
    def test_real_echo_worker_distinguishes_established_and_new_connections(self):
        import socketserver
        import tempfile
        import threading
        import time
        from continuous_evidence import TrafficStream

        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                while data := self.request.recv(4096):
                    self.request.sendall(data)

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = True
            accepts = 0
            def get_request(self):
                result = super().get_request()
                self.accepts += 1
                return result

        with Server(('127.0.0.1', 0), Echo) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for fresh in (False, True):
                    before = server.accepts
                    with tempfile.TemporaryDirectory() as directory:
                        stream = TrafficStream('127.0.0.1', server.server_address[1],
                                               new_connections=fresh)
                        stream.start(directory)
                        try:
                            stream.ready()
                            time.sleep(.08)
                        finally:
                            rows = stream.stop()
                        self.assertGreaterEqual(len(rows), 2)
                        self.assertTrue(all(row['delivered'] for row in rows))
                        if fresh:
                            self.assertEqual(len(rows), server.accepts-before)
                        else:
                            self.assertEqual(1, server.accepts-before)
            finally:
                server.shutdown()
                thread.join(timeout=2)

    def test_same_original_deadline_and_live_heartbeat_required(self):
        writes = [dict(map='auth_map', epoch=1, deadline_ns=100),
                  dict(map='health_map', epoch=1, deadline_ns=80),
                  dict(map='auth_map', epoch=0, deadline_ns=0)]
        assert_no_extension(writes, 100)
        with self.assertRaises(EvidenceError): assert_no_extension(writes, 99)
        with self.assertRaises(EvidenceError): assert_no_extension(writes[:1], 100)
        with self.assertRaises(EvidenceError):
            assert_no_extension(writes+[dict(map='auth_map', epoch=1, deadline_ns=101)], 100)

    def test_denial_requires_positive_baseline_and_no_delivery_after_transition(self):
        rows = [dict(attempt_ns=1, verdict_ns=2, delivered=True),
                dict(attempt_ns=5, verdict_ns=6, delivered=False),
                dict(attempt_ns=7, verdict_ns=8, delivered=False)]
        result = verify_denial(rows, 3, 4)
        self.assertEqual([3, 4], result['event_interval_monotonic_ns'])
        with self.assertRaises(EvidenceError): verify_denial(rows[1:], 3, 4)
        with self.assertRaises(EvidenceError):
            verify_denial(rows+[dict(attempt_ns=9, verdict_ns=10, delivered=True)], 3, 4)
        with self.assertRaises(EvidenceError): verify_denial(rows[:1], 3, 4)


if __name__ == '__main__': unittest.main()
