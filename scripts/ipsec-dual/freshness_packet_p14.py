"""P1.4 isolated packet controls on the existing Java/AA/Controller/Publisher gate.

Not a production entry point. No host clock, reboot or network configuration is
changed. Negative envelopes/operations use real fixture signatures; fresh grants
always come from Java and the AA. Actual reboot remains a separate qualification.
"""
import base64
from copy import deepcopy
import json
from pathlib import Path
import os
import time
from types import SimpleNamespace

from admission_v2 import OP_FIELDS, operation_bytes
from continuous_evidence import CaptureSet, EvidenceError, TrafficStream, namespace_capture
from functional_p0 import PROBES, frames, inject, mac, packet_id
from grant_boundary_diagnostic import (BOUNDARIES, _map_bytes, assert_packet_boundary,
                                      decode_verdicts, packet_deltas)
from independent_kernel_p1 import Supervisor, assert_hooks, kernel_snapshot
from issuance_v2 import canonical, node_message
from kernel_gate_publisher_v2 import HEALTH, KEY
from native import NAMES
from native_control_v2 import atomic_private_write
from security_p1 import deadline_interval, verify_denial

SCENARIOS = ('p14_wall_rollback', 'p14_envelope_replay', 'p14_operation_replay',
             'p14_stale_generation', 'p14_duplicate_issuance', 'p14_supervisor_restart',
             'p14_highwater_missing', 'p14_highwater_rollback', 'p14_epoch_mismatch')


def assert_live_baseline(snapshot, state, original_deadline, now):
    auth = snapshot['maps']['authorization']['value']; health = snapshot['maps']['health']['value']
    if (state['status'] != 'ATTESTED' or not state['published'] or state['revocation_uncertain'] or
            state['deadline_ns'] != original_deadline or auth['deadline_ns'] != original_deadline or
            not auth['epoch'] or auth['epoch'] != health['epoch'] or
            not health['checked_ns'] <= now < health['deadline_ns'] <= original_deadline or
            not 0 < health['deadline_ns']-health['checked_ns'] <= 500_000_000 or
            any((r['peer'], r['resource'], r['port']) != ('10.79.0.1', '10.80.0.2', 8080)
                for r in (auth, health))):
        raise EvidenceError('P1.4: live original authority/health absent immediately before fault')


def observe_epoch_rejection(publisher, inner, baseline, deadline):
    while True:
        values = decode_verdicts(json.loads(inner(['bpftool', '-j', 'map', 'dump', 'pinned',
                                                   str(publisher.pin_dir/'maps/verdict_map')])))
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        count = values['wg_ingress']['epoch_scope_denied']
        if now >= deadline:
            raise EvidenceError('P1.4: no epoch rejection observed before health expiry')
        if count > baseline:
            return {'boottime_ns': now, 'counter': count, 'health_deadline_ns': deadline}
        time.sleep(.005)


def signed_operation(supervisor, fixture, action):
    current = supervisor.ask('state')
    op = {k: current['challenge'][k] for k in OP_FIELDS if k not in ('action', 'generation')}
    op.update(action=action, generation=current['generation']+1)
    item = dict(operation=op, signature=base64.b64encode(
        fixture.operator.sign(operation_bytes(op))).decode())
    result = supervisor.ask('submit', item=item)
    if result['status'] != 'DENIED' or result['generation'] != op['generation']:
        raise EvidenceError('P1.4: genuine signed operation did not commit')
    return result, item


def fresh_grant(supervisor, fixture, issuer):
    recovered, recovery_item = signed_operation(supervisor, fixture, 'RECOVER')
    envelope = issuer.ask(dict(action='issue', challenge=recovered['challenge'],
        generation=recovered['generation']+1, nowBoottimeNs=time.clock_gettime_ns(time.CLOCK_BOOTTIME),
        lifetimeNs=2_999_000_000))['envelope']
    result = supervisor.ask('submit', item={'envelope': envelope})
    if (result['status'] != 'ATTESTED' or not result['published'] or
            result['deadline_ns'] != envelope['payload']['deadlineBoottimeNs']):
        raise EvidenceError('P1.4: fresh Java/AA authority did not publish')
    return result, envelope, recovery_item


def require_invalid_denied(supervisor, item, *, allow_cached_deadline=False):
    before = supervisor.ask('state')
    after = supervisor.ask('submit', item=item)
    deadline_ok = (after['deadline_ns'] == before['deadline_ns'] and after['until_ns'] == 0
                   if allow_cached_deadline else after['deadline_ns'] is None)
    if (after['status'] != 'DENIED' or after['published'] or not deadline_ok or
            after['generation'] != before['generation']):
        raise EvidenceError('P1.4: invalid/replayed authority changed or restored admission')
    return {k: after[k] for k in ('status', 'admission_state', 'generation', 'published', 'deadline_ns')}


def resign(fixture, payload):
    message = canonical(payload); signature = fixture.operator.sign(message)
    return dict(payload=payload, operatorSignature=base64.b64encode(signature).decode(),
                nodeSignature=base64.b64encode(fixture.node.sign(node_message(message, signature))).decode())


def positive_workers(directory):
    workers = []
    try:
        for name, fresh in (('established', False), ('new', True)):
            (directory/name).mkdir(mode=0o700)
            stream = TrafficStream(namespace=NAMES['e'], new_connections=fresh)
            workers.append((name, stream)); stream.start(directory/name); stream.ready(delivered=True)
        return workers
    except BaseException:
        for _, worker in workers: worker.stop()
        raise


def run(root, scenario, fixture, old_issuer, ticker, publisher, inner, *, topology):
    from isolated_enforcement import JavaIssuer, stop_ticker_for_failure
    if scenario not in SCENARIOS: raise ValueError('unknown P1.4 packet category')
    root = Path(root)/('p1-'+scenario); root.mkdir(mode=0o700)
    report = {'scenario': scenario, 'status': 'FAIL', 'invalid_attempts': [],
              'reboot_qualification': 'NOT_PERFORMED'}
    captures = CaptureSet(namespace_capture, boundaries=BOUNDARIES)
    original_controller = fixture.controller
    supervisor = issuer = None; workers = []
    stop_ticker_for_failure(ticker); publisher.revoke(); old_issuer.close()
    classpath = old_issuer.child.args[2]

    def start_session(directory):
        nonlocal supervisor, issuer
        directory.mkdir(mode=0o700, exist_ok=True)
        fixture.controller = original_controller
        supervisor = Supervisor(fixture, publisher, directory, test_controls=True)
        fixture.controller = SimpleNamespace(session=supervisor.initial['session'])
        issuer = JavaIssuer(fixture, fixture.operator, fixture.node, classpath)

    try:
        captures.start(root)
        (root/'pre').mkdir(mode=0o700)
        pre = TrafficStream(namespace=NAMES['e']); workers.append(('pre', pre))
        pre.start(root/'pre'); pre.ready(delivered=False)
        report['pregrant'] = pre.stop(); workers.clear()
        if any(r['delivered'] for r in report['pregrant']): raise EvidenceError('P1.4: pregrant delivery')
        start_session(root/'initial-supervisor')
        floor_path = fixture.root/'aa-highwater.json'
        old_floor = floor_path.read_bytes()
        report['grant'], envelope, initial_recover = fresh_grant(supervisor, fixture, issuer)
        trusted_floor = floor_path.read_bytes()
        (root/'traffic').mkdir(mode=0o700)
        workers = positive_workers(root/'traffic')
        live = supervisor.ask('reconcile')
        before = kernel_snapshot(publisher, inner); assert_hooks(before)
        assert_live_baseline(before, live, envelope['payload']['deadlineBoottimeNs'],
                             time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        # Same negative underlay probe used in P0/P1.3, no route changes.
        inject('o', 'transit', PROBES['underlay'], mac('i', 'transit'))
        event_start = time.monotonic_ns()
        original_deadline = envelope['payload']['deadlineBoottimeNs']
        report['fault_start_monotonic_ns'] = event_start
        report['old_grant_deadline_boottime_ns'] = original_deadline

        if scenario == 'p14_wall_rollback':
            state = supervisor.ask('wall_offset', seconds=-60)
            restored = supervisor.ask('wall_offset', seconds=0)
            report['clock_fault'] = {k: state[k] for k in ('status', 'wall_clock_failed', 'wall_offset_seconds')}
            if state['status'] != 'DENIED' or not state['wall_clock_failed'] or restored['status'] != 'DENIED':
                raise EvidenceError('P1.4: local clock regression/restoration revived cached authority')
        elif scenario == 'p14_supervisor_restart':
            report['terminated_supervisor'] = supervisor.kill()
            retained = kernel_snapshot(publisher, inner)
            report['retained_after_kill'] = retained
            limit = deadline_interval(retained['maps']['health']['value']['deadline_ns'])[1]
            report['restart_health_deadline_monotonic_ns'] = limit
            while time.monotonic_ns() < limit+150_000_000: time.sleep(.025)
            expired = kernel_snapshot(publisher, inner)
            if (expired['maps'] != retained['maps'] or
                    expired['verdicts']['wg_ingress']['health_deadline_denied'] <=
                    retained['verdicts']['wg_ingress']['health_deadline_denied']):
                raise EvidenceError('P1.4: restart did not retain maps through kernel health expiry')
            report['expired_before_restart_handoff'] = expired
            supervisor.close(); issuer.close(); supervisor = issuer = None
            publisher.revoke()  # legitimate denied ownership handoff after kernel expiry
            start_session(root/'restart-supervisor')
            if supervisor.initial['session'] == report['grant']['session']:
                raise EvidenceError('P1.4: supervisor session was restored')
            if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= original_deadline:
                raise EvidenceError('P1.4: prior grant expired before restart replay control')
            report['invalid_attempts'].append(require_invalid_denied(supervisor, {'envelope': envelope}))
        elif scenario in ('p14_highwater_missing', 'p14_highwater_rollback'):
            if scenario.endswith('missing'): floor_path.unlink()
            else: atomic_private_write(floor_path, old_floor)
            state = supervisor.ask('reconcile')
            if state['status'] != 'DENIED' or state['published']:
                raise EvidenceError('P1.4: invalid high-water state retained authority')
            report['invalid_attempts'].append(require_invalid_denied(supervisor, {'envelope': envelope},
                                                                    allow_cached_deadline=True))
        elif scenario == 'p14_epoch_mismatch':
            supervisor.ask('reconcile')  # fresh real health check before the scoped map fault
            supervisor.ask('pause_publication')
            raw = json.loads(inner(['bpftool', '-j', 'map', 'lookup', 'pinned', publisher.health_path,
                                    'key', 'hex', *KEY]))
            fields = list(HEALTH.unpack(_map_bytes(raw['value'], HEALTH.size)))
            old_epoch = fields[0]; fields[0] = (old_epoch+1) % (1<<64) or 1
            if fields[0] == old_epoch: raise EvidenceError('P1.4: epoch fault did not change epoch')
            value = HEALTH.pack(*fields)
            inner(['bpftool', 'map', 'update', 'pinned', publisher.health_path, 'key', 'hex', *KEY,
                   'value', 'hex', *(f'{b:02x}' for b in value)])
            report['epoch_fault'] = {'old_epoch': old_epoch, 'invalid_epoch': fields[0]}
            report['epoch_fault']['health_deadline_monotonic_ns'] = deadline_interval(fields[1])[1]
            if time.monotonic_ns() >= report['epoch_fault']['health_deadline_monotonic_ns']:
                raise EvidenceError('P1.4: health expired before epoch-mismatch baseline')
            report['epoch_fault']['pre_expiry_rejection'] = observe_epoch_rejection(
                publisher, inner, before['verdicts']['wg_ingress']['epoch_scope_denied'], fields[1])
        else:
            revoked, revoke_item = signed_operation(supervisor, fixture, 'REVOKE')
            if scenario == 'p14_envelope_replay':
                for _ in range(3): report['invalid_attempts'].append(require_invalid_denied(supervisor, {'envelope': envelope}))
            elif scenario == 'p14_operation_replay':
                for item in (revoke_item, initial_recover):
                    report['invalid_attempts'].append(require_invalid_denied(supervisor, item))
                _, recovery_item = signed_operation(supervisor, fixture, 'RECOVER')
                for item in (recovery_item, revoke_item):
                    report['invalid_attempts'].append(require_invalid_denied(supervisor, item))
            else:
                recovered, _ = signed_operation(supervisor, fixture, 'RECOVER')
                now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
                payload = dict(envelope['payload'], nonce=recovered['challenge']['nonce'],
                    issuedBoottimeNs=now, deadlineBoottimeNs=now+2_999_000_000,
                    generation=recovered['generation']+1, issuanceId=os.urandom(16).hex())
                if scenario == 'p14_stale_generation': payload['generation'] = revoked['generation']
                elif scenario == 'p14_duplicate_issuance': payload['issuanceId'] = envelope['payload']['issuanceId']
                else: raise ValueError('unknown replay category')
                report['invalid_attempts'].append(require_invalid_denied(supervisor, {'envelope': resign(fixture, payload)}))
        event_complete = time.monotonic_ns()
        report['fault_complete_monotonic_ns'] = event_complete
        wait_until = event_complete+500_000_000
        if scenario == 'p14_wall_rollback': wait_until = max(wait_until, deadline_interval(original_deadline)[1]+200_000_000)
        while time.monotonic_ns() < wait_until: time.sleep(.025)
        report['application'] = {}
        for name, worker in workers:
            rows = worker.stop()
            bound = report.get('restart_health_deadline_monotonic_ns', event_complete)
            report['application'][name] = verify_denial(rows, event_start, bound)
        workers.clear()
        denied = kernel_snapshot(publisher, inner); assert_hooks(denied)
        report['snapshots'] = {'authorized': before, 'denied': denied}
        report['packet_deltas'] = packet_deltas(before, denied)
        verdicts = report['packet_deltas']['tc']['wg_ingress']
        if sum(verdicts[k] for k in ('auth_missing', 'health_missing', 'epoch_scope_denied',
                                    'auth_deadline_denied', 'health_deadline_denied')) < 1:
            raise EvidenceError('P1.4: physical TC rejection evidence absent')
        if scenario == 'p14_epoch_mismatch':
            a = denied['maps']['authorization']['value']; h = denied['maps']['health']['value']
            if (not a['epoch'] or not h['epoch'] or a['epoch'] == h['epoch'] or
                    report['packet_deltas']['tc']['wg_ingress']['epoch_scope_denied'] < 1):
                raise EvidenceError('P1.4: actual epoch mismatch denial not observed')
            if report['application']['new']['first_denied_attempt_ns'] >= report['epoch_fault']['health_deadline_monotonic_ns']:
                raise EvidenceError('P1.4: epoch denial not isolated from heartbeat expiry')
        elif any(row['value']['epoch'] for row in denied['maps'].values()):
            raise EvidenceError('P1.4: normal denial did not clear permits')
        if before['tc'] != denied['tc'] or before['nft_hooks'] != denied['nft_hooks']:
            raise EvidenceError('P1.4: enforcement hooks changed')
        # Recovery is distinct from the denied observation window and always
        # needs a new real session, operator recovery, Java V2 and AA proof.
        supervisor.close(); issuer.close(); supervisor = issuer = None
        if scenario in ('p14_highwater_missing', 'p14_highwater_rollback'):
            atomic_private_write(floor_path, trusted_floor)
            report['highwater_repair'] = 'fixture trusted pre-fault snapshot; not an external monotonic anchor'
        start_session(root/'recovery-supervisor')
        report['recovery_old_envelope'] = require_invalid_denied(supervisor, {'envelope': envelope})
        fresh, _, _ = fresh_grant(supervisor, fixture, issuer)
        if fresh['generation'] <= report['grant']['generation'] or fresh['session'] == report['grant']['session']:
            raise EvidenceError('P1.4: recovery lacks fresh signed session/generation')
        (root/'recovery').mkdir(mode=0o700)
        workers = positive_workers(root/'recovery'); time.sleep(.08)
        outcomes = {}
        for name, worker in workers:
            rows = worker.stop()
            if not rows or not all(r['delivered'] for r in rows): raise EvidenceError('P1.4: recovered TCP failed')
            outcomes[name] = len(rows)
        workers.clear()
        recovered_kernel = kernel_snapshot(publisher, inner); assert_hooks(recovered_kernel)
        report['recovery'] = {'status': 'PASS', 'generation': fresh['generation'], 'new_session': True,
                              'successful_echoes': outcomes, 'kernel': recovered_kernel}
    except BaseException as exc:
        report['failure'] = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        try:
            for _, worker in workers: worker.stop()
            captures.stop()
        finally:
            if supervisor is not None: supervisor.close()
            if issuer is not None: issuer.close()
            fixture.controller = original_controller
            (root/'summary.local.json').write_text(json.dumps(report, indent=2)+'\n')
    report['packet_boundary'] = assert_packet_boundary(root)
    identity = PROBES['underlay']
    for label in ('outer-transit', 'inner-transit'):
        if identity not in {packet_id(link, frame) for link, frame in frames(root/(label+'.pcap'))}:
            raise EvidenceError('P1.4: labeled underlay probe absent at ingress')
    for label in ('inner-resource', 'resource'):
        if identity in {packet_id(link, frame) for link, frame in frames(root/(label+'.pcap'))}:
            raise EvidenceError('P1.4: direct underlay bypass reached resource')
    drops = [r for r in report['packet_deltas']['nft']['ipsec_dual'] if r['verdicts']==['drop']]
    if len(drops)!=1 or drops[0]['packet_deltas']!=[1]: raise EvidenceError('P1.4: nft underlay rejection counter absent')
    report['underlay_bypass'] = 'DENIED'
    report['status'] = 'PASS'
    (root/'summary.local.json').write_text(json.dumps(report, indent=2)+'\n')
    (root.parent/'p1.json').write_text(json.dumps(report, indent=2)+'\n')
    return report
