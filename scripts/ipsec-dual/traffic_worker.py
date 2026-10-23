"""Continuous TCP echo application traffic (runs inside the endpoint netns)."""
import json
import signal
import socket
import sys
import time

running = True


def finish(*_):
    global running
    running = False


def main(host, port, interval, timeout):
    signal.signal(signal.SIGINT, finish)
    connection = None
    sequence = 0
    while running:
        attempt = time.monotonic_ns()
        delivered = False
        try:
            if connection is None:
                connection = socket.create_connection((host, port), timeout)
                connection.settimeout(timeout)
            payload = ('native-dual-packet-evidence:%016x\n' % sequence).encode()
            connection.sendall(payload)
            answer = b''
            while len(answer) < len(payload):
                chunk = connection.recv(len(payload) - len(answer))
                if not chunk:
                    raise ConnectionError('echo closed')
                answer += chunk
            delivered = answer == payload
        except (OSError, ConnectionError):
            pass
        if not delivered:
            if connection is not None:
                connection.close()
                connection = None
        verdict = time.monotonic_ns()
        print(json.dumps(dict(attempt_ns=attempt, verdict_ns=verdict,
                              delivered=delivered, sequence=sequence)), flush=True)
        sequence += 1
        if running:
            time.sleep(interval)
    if connection is not None:
        connection.close()


if __name__ == '__main__':
    main(sys.argv[1], int(sys.argv[2]), float(sys.argv[3]), float(sys.argv[4]))
