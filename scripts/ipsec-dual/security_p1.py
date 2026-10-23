"""One P1 category at a time on the P0 transport; never a production admission switch."""
import json
from pathlib import Path
import time

from continuous_evidence import CaptureSet, EvidenceError, TrafficStream, denial_bracket, namespace_capture
from grant_boundary_diagnostic import (BOUNDARIES, assert_packet_boundary, packet_deltas, sample)
from kernel_gate_publisher_v2 import AUTH, HEALTH
from native import NAMES

P0_REFERENCE = '4a379415ac4577d36c316d16afe1b8d508252c5f'


def assert_no_extension(writes, deadline):
    live = [row for row in writes if row['map'] == 'auth_map' and row['epoch']]
    if not live or any(row['deadline_ns'] != deadline for row in live):
        raise EvidenceError('P1: authorization deadline changed without fresh authority')
    if not any(row['map'] == 'health_map' and row['epoch'] for row in writes):
        raise EvidenceError('P1: live health publication not observed')


def verify_denial(rows, event_low, event_high):
    result = denial_bracket(rows, event_low)
    if any(row['delivered'] and row['attempt_ns'] >= event_high for row in rows):
        raise EvidenceError('P1: application delivery on a post-event attempt')
    if not any(not row['delivered'] and row['attempt_ns'] >= event_high for row in rows):
        raise EvidenceError('P1: post-event denial observation absent')
    result['event_interval_monotonic_ns'] = [event_low, event_high]
    result['first_denied_verdict_after_event_low_ns'] = result['first_denied_verdict_ns'] - event_low
    result['interpretation'] = 'observed application probe bracket, not a guaranteed kernel maximum'
    return result


def run(root, scenario, fixture, issuer, ticker, publisher, inner, grant):
    root = Path(root)/('p1-'+scenario)
    root.mkdir(mode=0o700)
    for name in ('pre', 'established', 'new'):
        (root/name).mkdir(mode=0o700)
    report = {'p0_reference': P0_REFERENCE, 'scenario': scenario, 'status': 'FAIL',
              'snapshots': [], 'writes': []}
    captures = CaptureSet(namespace_capture, boundaries=BOUNDARIES)
    streams = []
    original_update = publisher._update

    def observed_update(path, value):
        layout = AUTH if Path(path).name == 'auth_map' else HEALTH
        fields = layout.unpack(value)
        row = {'map': Path(path).name, 'epoch': fields[0], 'deadline_ns': fields[1],
               'boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME), 'success': False}
        report['writes'].append(row)
        try:
            result = original_update(path, value)
            row['success'] = True
            return result
        finally:
            (root/'map-writes.local.json').write_text(json.dumps(report['writes'], indent=2))

    publisher._update = observed_update
    try:
        captures.start(root)
        pre = TrafficStream(namespace=NAMES['e'])
        streams.append(pre); pre.start(root/'pre'); pre.ready(delivered=False)
        report['pregrant'] = pre.stop(); streams.remove(pre)
        if any(row['delivered'] for row in report['pregrant']):
            raise EvidenceError('P1: pregrant delivery')
        with ticker.lock:
            report['grant'] = grant(fixture, issuer)
            if not publisher.tick():
                raise EvidenceError('P1: signed grant did not publish')
            report['snapshots'].append(['authorized', sample(fixture, publisher, inner)])
        for name, fresh in (('established', False), ('new', True)):
            stream = TrafficStream(namespace=NAMES['e'], new_connections=fresh)
            streams.append(stream); stream.start(root/name); stream.ready(delivered=True)
        deadline = report['grant']['deadline_boottime_ns']
        with ticker.lock:
            ticker.check()
            if scenario == 'revoke':
                from isolated_enforcement import operation
                event_low = time.monotonic_ns()
                operation(fixture, 'REVOKE')
                publisher.tick()
                event_high = time.monotonic_ns()
                wait_until = event_high + 1_000_000_000
            elif scenario == 'expiry':
                m0 = time.monotonic_ns()
                boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
                m1 = time.monotonic_ns()
                event_low, event_high = m0+deadline-boot, m1+deadline-boot
                if event_low <= m1:
                    raise EvidenceError('P1: grant expired before fault baseline')
                wait_until = event_high+800_000_000
            else:
                raise ValueError('unknown P1 category')
        while time.monotonic_ns() < wait_until:
            ticker.check()
            time.sleep(.05)
        report['application'] = {}
        for name, stream in zip(('established', 'new'), streams):
            rows = stream.stop()
            (root/name/'probes.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows))
            report['application'][name] = verify_denial(rows, event_low, event_high)
        streams.clear()
        with ticker.lock:
            ticker.check()
            report['snapshots'].append(['denied', sample(fixture, publisher, inner)])
        assert_no_extension(report['writes'], deadline)
        before, after = (row[1] for row in report['snapshots'])
        report['packet_deltas'] = packet_deltas(before, after)
        if (after['controller_status'] != 'DENIED' or
                any(row['value']['epoch'] for row in after['maps'].values()) or
                any(not row['attached'] for row in after['tc'].values())):
            raise EvidenceError('P1: control/maps/hooks not in expected denied state')
        if sum(report['packet_deltas']['tc']['wg_ingress'][key] for key in
               ('auth_missing', 'auth_deadline_denied', 'health_deadline_denied')) < 1:
            raise EvidenceError('P1: BPF denial counters absent')
    except BaseException as exc:
        report['failure'] = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        try:
            for stream in streams:
                stream.stop()
            captures.stop()
        finally:
            publisher._update = original_update
            (root/'summary.local.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
    report['packet_boundary'] = assert_packet_boundary(root)
    report['status'] = 'PASS'
    (root/'summary.local.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
    (root.parent/'p1.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
    return report
