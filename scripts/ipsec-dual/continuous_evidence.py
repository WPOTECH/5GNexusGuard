"""Opt-in, lab-only continuous packet evidence; never an authorization source.

The caller owns namespace creation, server startup and explicit grant/fault/recovery
hooks. This module does not install a gate, refresh a grant, or change host time.
"""
import json
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

BOUNDARIES = (('e', 'pub', 'endpoint-public'), ('o', 'pub', 'outer-public'),
              ('o', 'transit', 'outer-transit'), ('i', 'transit', 'inner-ingress'),
              ('r', 'resource', 'resource'))
FAULTS = frozenset(('grant', 'revoke', 'aa_revoke', 'aa_outage',
                    'restart_replay', 'supervisor_death', 'charon_death',
                    'clock_regression'))


class EvidenceError(AssertionError):
    pass


class TrafficStream:
    """One persistent TCP connection, retrying after denial; no grant side effects."""
    def __init__(self, host='10.80.0.2', port=8080, *, interval=.01,
                 timeout=.08, namespace=None, new_connections=False):
        self.host, self.port = host, port
        self.interval, self.timeout, self.namespace = interval, timeout, namespace
        self.child = None
        self.new_connections = new_connections

    def start(self, directory):
        self.path = Path(directory) / 'worker.jsonl'
        prefix = ['ip', 'netns', 'exec', self.namespace] if self.namespace else []
        with self.path.open('w') as output:
            self.child = subprocess.Popen(prefix + [sys.executable, '-u',
                str(Path(__file__).with_name('traffic_worker.py')), self.host,
                str(self.port), str(self.interval), str(self.timeout)] +
                (['--new-connections'] if self.new_connections else []),
                stdout=output, stderr=subprocess.DEVNULL)

    def ready(self, delivered=True):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.child.poll() is not None:
                raise EvidenceError('traffic worker exited before baseline')
            if any(row.get('delivered') is delivered for row in self._rows()):
                return
            time.sleep(.01)
        raise EvidenceError('no matching application baseline')

    def _rows(self):
        return [json.loads(line) for line in self.path.read_text().splitlines() if line]

    def stop(self):
        if self.child.poll() is None:
            self.child.send_signal(signal.SIGINT)
        try:
            self.child.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.child.kill()
            self.child.wait()
        if self.child.returncode != 0:
            raise EvidenceError('traffic worker failed')
        return self._rows()


def denial_bracket(rows, event_ns):
    """Report observed probe bracket, never an exact kernel-denial instant."""
    last_end = -1
    baseline = None
    delivered = None
    denied = None
    for row in rows:
        start, end, ok = row['attempt_ns'], row['verdict_ns'], row['delivered']
        if (type(start) is not int or type(end) is not int or type(ok) is not bool
                or start < last_end or end < start):
            raise EvidenceError('invalid/nonsequential monotonic probe record')
        last_end = end
        if ok and end <= event_ns:
            baseline = row
        if ok and denied is None:
            delivered = row
        if not ok and start >= event_ns and denied is None:
            denied = row
        if ok and denied is not None:
            raise EvidenceError('delivery after first denial')
    if baseline is None or delivered is None or denied is None:
        raise EvidenceError('missing pre-event delivery or post-event denial')
    return dict(event_ns=event_ns, last_delivered_ns=delivered['verdict_ns'],
                first_denied_attempt_ns=denied['attempt_ns'],
                first_denied_verdict_ns=denied['verdict_ns'],
                attempts=len(rows), clock='CLOCK_MONOTONIC',
                interpretation='observed probe bracket; not exact denial instant')


def grant_bracket(rows, event_ns):
    """Grant requires a denied baseline and first observed delivery after hook."""
    last_end = -1
    denied, delivered = None, None
    for row in rows:
        start, end, ok = row['attempt_ns'], row['verdict_ns'], row['delivered']
        if (type(start) is not int or type(end) is not int or type(ok) is not bool
                or start < last_end or end < start):
            raise EvidenceError('invalid/nonsequential monotonic probe record')
        last_end = end
        if not ok and end <= event_ns:
            denied = row
        if ok and start >= event_ns and delivered is None:
            delivered = row
    if denied is None or delivered is None:
        raise EvidenceError('missing pre-grant denial or post-grant delivery')
    return dict(event_ns=event_ns, last_denied_ns=denied['verdict_ns'],
                first_delivered_attempt_ns=delivered['attempt_ns'],
                first_delivered_ns=delivered['verdict_ns'], attempts=len(rows),
                clock='CLOCK_MONOTONIC', interpretation='observed probe bracket')


class CaptureSet:
    """Concurrent directional physical captures; require ready and zero kernel drops."""
    def __init__(self, spawn, boundaries=BOUNDARIES, clock=time.monotonic):
        self.spawn, self.boundaries, self.clock = spawn, boundaries, clock
        self.children = []

    def start(self, directory):
        directory = Path(directory)
        try:
            for role, interface, label in self.boundaries:
                for direction in (('all', 'out') if label.endswith('public') else ('all',)):
                    name = label + ('-wire-egress' if direction == 'out' else '')
                    pcap = directory / (name + '.pcap')
                    status = directory / (name + '.capture-status')
                    child = self.spawn(role, interface, direction, pcap, status)
                    self.children.append((pcap, status, child))
            deadline = self.clock() + 3
            while not all(status.exists() and 'listening on' in status.read_text()
                          for _, status, _ in self.children):
                if (self.clock() >= deadline or any(c.poll() is not None for _, _, c in self.children)):
                    raise EvidenceError('capture not ready')
                time.sleep(.02)
        except BaseException:
            try:
                self.stop()
            except EvidenceError:
                pass
            raise

    def stop(self):
        for _, _, child in self.children:
            if child.poll() is None:
                child.send_signal(signal.SIGINT)
        for _, _, child in self.children:
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        for pcap, status, child in self.children:
            if (child.returncode != 0 or not pcap.exists() or pcap.stat().st_size < 24
                    or re.search(r'^0 packets dropped by kernel$', status.read_text(), re.M) is None):
                raise EvidenceError('capture incomplete or kernel drops: ' + pcap.name)


def namespace_capture(role, interface, direction, pcap, status):
    """Called only inside the approved isolated launcher, never by unit tests."""
    from native import NAMES
    argv = ['ip', 'netns', 'exec', NAMES[role], 'tcpdump', '-Z', 'root', '-U',
            '--immediate-mode', '-n']
    if direction == 'out':
        argv += ['-Q', 'out']
    stream = status.open('w')
    try:
        return subprocess.Popen(argv + ['-i', interface, '-w', str(pcap)],
                                stdout=subprocess.DEVNULL, stderr=stream)
    finally:
        stream.close()


def measure(evidence, fault, hooks, stream, captures, clock=time.monotonic_ns,
            wait_seconds=4):
    """Run already-configured transport under continuous captures and external fault.

    A fault hook MUST implement the requested transition, with no automatic grant
    renewal in negative controls. The caller is responsible for recovery separately.
    """
    if fault not in FAULTS or fault not in hooks or not callable(hooks[fault]):
        raise EvidenceError('explicit external gate hook required')
    directory = Path(evidence) / fault
    directory.mkdir(parents=True, exist_ok=False)
    try:
        captures.start(directory)
        try:
            stream.start(directory)
            try:
                if fault == 'grant':
                    stream.ready(delivered=False)
                else:
                    stream.ready()
                event_ns = clock()
                hook = hooks[fault]()
                hook_end_ns = clock()
                time.sleep(wait_seconds)
            finally:
                rows = stream.stop()
        finally:
            captures.stop()
        result = (grant_bracket(rows, event_ns) if fault == 'grant'
                  else denial_bracket(rows, event_ns))
        result['hook_end_ns'] = hook_end_ns
        result['hook'] = hook if isinstance(hook, dict) else {}
        (directory / 'probes.jsonl').write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows))
        (directory / 'summary.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
        return result
    except Exception:
        # The raw captures/status remain in private evidence even on failure.
        raise
