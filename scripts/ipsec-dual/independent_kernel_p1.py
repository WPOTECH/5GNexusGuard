"""Packet qualification with a real separate supervisor and untouched stale maps."""
import base64
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
from types import SimpleNamespace

from admission_v2 import OP_FIELDS, operation_bytes
from continuous_evidence import CaptureSet, EvidenceError, TrafficStream, namespace_capture
from grant_boundary_diagnostic import (BOUNDARIES, assert_packet_boundary, decode_map,
                                      decode_verdicts, nft_rule_kind, packet_deltas, parse_tc)
from kernel_gate_publisher_v2 import AUTH, HEALTH, KEY, FreshHealth
from native import NAMES
from security_p1 import assert_no_extension, deadline_interval, verify_denial, xfrm_counts


def kernel_snapshot(publisher, inner):
    result = {'boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME), 'maps': {},
              'interfaces': {}, 'tc': {}, 'programs': {}, 'nft': {}, 'nft_hooks': {}}
    for label, path, layout in (('authorization', publisher.auth_path, AUTH),
                                ('health', publisher.health_path, HEALTH)):
        raw = json.loads(inner(['bpftool', '-j', 'map', 'lookup', 'pinned', path, 'key', 'hex', *KEY]))
        result['maps'][label] = {'value': decode_map(raw, layout)}
    result['verdicts'] = decode_verdicts(json.loads(inner([
        'bpftool', '-j', 'map', 'dump', 'pinned', str(publisher.pin_dir/'maps/verdict_map')])))
    for iface, label in (('wg-inner', 'wg_ingress'), ('resource', 'resource_ingress')):
        result['tc'][iface] = parse_tc(inner(['tc', '-s', 'filter', 'show', 'dev', iface, 'ingress']))
        raw = json.loads(inner(['bpftool', '-j', 'prog', 'show', 'pinned',
                                str(publisher.pin_dir/'progs'/label)]))
        result['programs'][label] = {'id': raw['id'], 'classifier': raw['type'] == 'sched_cls'}
    for table in ('ipsec_dual', 'kernel_gate_v2_test'):
        raw = json.loads(inner(['nft', '-j', 'list', 'chain', 'inet', table, 'forward']))
        result['nft_hooks'][table] = [r['chain'] for r in raw['nftables'] if 'chain' in r]
        result['nft'][table] = [dict(handle=r['rule']['handle'],
            rule_kind=nft_rule_kind(r['rule']['expr'], table),
            counter=[e['counter'] for e in r['rule']['expr'] if 'counter' in e],
            verdicts=[v for e in r['rule']['expr'] for v in ('accept', 'drop') if v in e])
            for r in raw['nftables'] if 'rule' in r]
    return result


def assert_hooks(snapshot):
    for iface, label in (('wg-inner', 'wg_ingress'), ('resource', 'resource_ingress')):
        if (not snapshot['tc'][iface]['attached'] or
                snapshot['tc'][iface]['program_id'] != snapshot['programs'][label]['id'] or
                not snapshot['programs'][label]['classifier']):
            raise EvidenceError('P1.3: TC identity lost')
    for table, priority, kinds in (
            ('ipsec_dual', 0, ['transit_in', 'transit_out', 'forward', 'reverse', 'drop']),
            ('kernel_gate_v2_test', 10, ['forward', 'reverse', 'drop'])):
        hooks = snapshot['nft_hooks'][table]
        if (len(hooks) != 1 or hooks[0].get('hook') != 'forward' or
                hooks[0].get('policy') != 'drop' or hooks[0].get('prio') != priority or
                [r['rule_kind'] for r in snapshot['nft'][table]] != kinds):
            raise EvidenceError('P1.3: independent nft interlock changed')


class Supervisor:
    def __init__(self, fixture, publisher, directory):
        from isolated_enforcement import pkcs8, raw
        self.log = (directory/'supervisor.stderr.local').open('w')
        self.process = subprocess.Popen([sys.executable, '-B', str(Path(__file__).with_name('p1_supervisor_process.py'))],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True, bufsize=1)
        c = fixture.controller
        cfg = dict(directory=str(fixture.root), scope=fixture.scope, operator=raw(fixture.operator).hex(),
                   node=raw(fixture.node).hex(), signer=pkcs8(fixture.supervisor), url=c.url, ca=c.ca,
                   cert=c.cert, key=c.key, aa_key=raw(fixture.aa_signer).hex(),
                   pids=list(publisher.health_check.pids), vici=str(publisher.health_check.vici_dir),
                   pin=str(publisher.pin_dir), audit=str(directory/'map-writes.local.jsonl'))
        try:
            self.process.stdin.write(json.dumps(cfg)+'\n'); self.process.stdin.flush()
            self.initial = self.receive()
            self.start = self.initial['start']
        except BaseException:
            self.process.kill(); self.process.wait(timeout=2)
            self.process.stdin.close(); self.process.stdout.close(); self.log.close()
            raise

    def receive(self):
        if not select.select([self.process.stdout], [], [], 5)[0]:
            raise EvidenceError('P1.3: supervisor reply timed out')
        line = self.process.stdout.readline()
        if not line:
            raise EvidenceError('P1.3: supervisor exited before reply')
        return json.loads(line)

    def ask(self, action, **kwargs):
        self.process.stdin.write(json.dumps(dict(action=action, **kwargs))+'\n')
        self.process.stdin.flush()
        return self.receive()

    def kill(self):
        p = self.process
        if (p.poll() is not None or p.pid <= 1 or p.pid != self.initial['pid'] or
                FreshHealth._start(p.pid) != self.start or
                os.stat(f'/proc/{p.pid}/ns/net').st_ino != os.stat('/proc/self/ns/net').st_ino):
            raise EvidenceError('P1.3: supervisor process identity mismatch')
        low = time.monotonic_ns(); p.kill(); p.wait(timeout=2)
        if p.returncode != -9:
            raise EvidenceError('P1.3: supervisor did not exit by SIGKILL')
        return {'pid': p.pid, 'start': self.start, 'signal_monotonic_ns': low,
                'reaped_monotonic_ns': time.monotonic_ns(), 'returncode': p.returncode}

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try: self.process.wait(timeout=3)
            except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=2)
        if not self.process.stdin.closed: self.process.stdin.close()
        self.process.stdout.close(); self.log.close()


def operate(supervisor, fixture, action):
    state = supervisor.ask('state')
    challenge = state['challenge']
    op = {k: challenge[k] for k in OP_FIELDS if k not in ('action', 'generation')}
    op.update(action=action, generation=state['generation']+1)
    signature = base64.b64encode(fixture.operator.sign(operation_bytes(op))).decode()
    recovered = supervisor.ask('submit', item=dict(operation=op, signature=signature))
    if recovered['status'] != 'DENIED' or recovered['generation'] != op['generation']:
        raise EvidenceError('P1.3: signed operation failed')
    return recovered


def issue(supervisor, fixture, issuer):
    recovered = operate(supervisor, fixture, 'RECOVER')
    envelope = issuer.ask(dict(action='issue', challenge=recovered['challenge'],
        generation=recovered['generation']+1, nowBoottimeNs=time.clock_gettime_ns(time.CLOCK_BOOTTIME),
        lifetimeNs=2_999_000_000))['envelope']
    approved = supervisor.ask('submit', item={'envelope': envelope})
    if (approved['status'] != 'ATTESTED' or not approved['published'] or
            approved['deadline_ns'] != envelope['payload']['deadlineBoottimeNs']):
        raise EvidenceError('P1.3: genuine V2 authorization did not publish')
    return approved, envelope


def retained_deadlines(before, retained, final):
    for label in ('authorization', 'health'):
        value = retained['maps'][label]['value']
        if not value['epoch'] or not value['deadline_ns'] or final['maps'][label] != retained['maps'][label]:
            raise EvidenceError('P1.3: stale maps were cleared or extended during observation')
    if before['maps']['authorization'] != retained['maps']['authorization']:
        raise EvidenceError('P1.3: original authorization changed')
    auth = retained['maps']['authorization']['value']; health = retained['maps']['health']['value']
    if (auth['epoch'] != health['epoch'] or not 0 < health['deadline_ns']-health['checked_ns'] <= 500_000_000 or
            not health['deadline_ns'] < auth['deadline_ns'] or
            any((v['peer'], v['resource'], v['port']) != ('10.79.0.1', '10.80.0.2', 8080)
                for v in (auth, health))):
        raise EvidenceError('P1.3: invalid retained authority/health binding')


def run(root, scenario, fixture, old_issuer, ticker, publisher, inner, *, topology):
    from isolated_enforcement import JavaIssuer, stop_ticker_for_failure
    if scenario not in ('supervisor_failure', 'map_update_failure'):
        raise ValueError('unsupported independent kernel scenario')
    root = Path(root)/('p1-'+scenario); root.mkdir(mode=0o700)
    for name in ('pre', 'established', 'new'): (root/name).mkdir(mode=0o700)
    report = {'scenario': scenario, 'status': 'FAIL'}
    captures = CaptureSet(namespace_capture, boundaries=BOUNDARIES)
    streams = []; supervisor = issuer = None
    original_controller = fixture.controller
    # Ownership transfer happens while maps are zero, before any V2 grant.
    stop_ticker_for_failure(ticker)
    publisher.revoke()
    old_issuer.close()
    try:
        captures.start(root)
        pre = TrafficStream(namespace=NAMES['e']); streams.append(pre)
        pre.start(root/'pre'); pre.ready(delivered=False)
        report['pregrant'] = pre.stop(); streams.remove(pre)
        if any(r['delivered'] for r in report['pregrant']): raise EvidenceError('P1.3: pregrant delivery')
        supervisor = Supervisor(fixture, publisher, root)
        fixture.controller = SimpleNamespace(session=supervisor.initial['session'])
        issuer = JavaIssuer(fixture, fixture.operator, fixture.node, old_issuer.child.args[2])
        report['grant'], envelope = issue(supervisor, fixture, issuer)
        for name, fresh in (('established', False), ('new', True)):
            stream = TrafficStream(namespace=NAMES['e'], new_connections=fresh)
            streams.append(stream); stream.start(root/name); stream.ready(delivered=True)
        before = kernel_snapshot(publisher, inner); assert_hooks(before)
        if scenario == 'supervisor_failure':
            report['fault'] = supervisor.kill()
        else:
            from functional_p0 import PROBES, inject, mac
            inject('o', 'transit', PROBES['underlay'], mac('i', 'transit'))
            report['fault'] = {'signal_monotonic_ns': time.monotonic_ns(),
                               'operation': 'freeze owned auth_map and health_map'}
            for path in (publisher.auth_path, publisher.health_path):
                inner(['bpftool', 'map', 'freeze', 'pinned', path])
            report['fault']['freeze_complete_monotonic_ns'] = time.monotonic_ns()
            report['failed_revoke'] = operate(supervisor, fixture, 'REVOKE')
            report['reconciliation_retries'] = [supervisor.ask('reconcile') for _ in range(3)]
            if (not report['failed_revoke']['revocation_uncertain'] or
                    not report['failed_revoke']['last_error'] or
                    any(not s['revocation_uncertain'] or s['published'] for s in report['reconciliation_retries'])):
                raise EvidenceError('P1.3: failed writes reported as certain revocation or publication')
        retained = kernel_snapshot(publisher, inner)
        health = retained['maps']['health']['value']; auth = retained['maps']['authorization']['value']
        report['health_deadline_interval_monotonic_ns'] = deadline_interval(health['deadline_ns'])
        report['authorization_deadline_interval_monotonic_ns'] = deadline_interval(auth['deadline_ns'])
        event = report['fault']['signal_monotonic_ns']
        health_end = report['health_deadline_interval_monotonic_ns'][1]
        if health_end <= event: raise EvidenceError('P1.3: health expired before crash')
        report['xfrm_after_crash'] = xfrm_counts()
        report['aa_alive'] = fixture.thread.is_alive()
        report['charon_alive'] = all(c.poll() is None for c in topology.daemon_roles.values())
        if not report['aa_alive'] or not report['charon_alive']: raise EvidenceError('P1.3: non-supervisor service died')
        while time.monotonic_ns() < report['authorization_deadline_interval_monotonic_ns'][1]+600_000_000:
            time.sleep(.05)
        report['application'] = {}
        for name, stream in zip(('established', 'new'), streams):
            rows = stream.stop()
            report['application'][name] = verify_denial(rows, event, health_end)
            if any(r['delivered'] and r['verdict_ns'] >= health_end for r in rows):
                raise EvidenceError('P1.3: successful verdict beyond health deadline')
        streams.clear()
        final = kernel_snapshot(publisher, inner); assert_hooks(final)
        retained_deadlines(before, retained, final)
        if before['tc'] != final['tc'] or before['nft_hooks'] != final['nft_hooks']:
            raise EvidenceError('P1.3: enforcement hooks changed during fault')
        report['snapshots'] = {'before': before, 'retained': retained, 'final': final}
        report['packet_deltas'] = packet_deltas(before, final)
        verdicts = report['packet_deltas']['tc']['wg_ingress']
        if verdicts['health_deadline_denied'] < 1 or verdicts['auth_deadline_denied'] < 1:
            raise EvidenceError('P1.3: actual kernel health/auth deadline rejection absent')
        writes = [json.loads(line) for line in (root/'map-writes.local.jsonl').read_text().splitlines()]
        assert_no_extension(writes, auth['deadline_ns'])
        report['map_write_failures'] = sum(not row['success'] for row in writes)
        if scenario == 'supervisor_failure':
            report['revoked_before_measurement'] = False
        else:
            if not report['map_write_failures']:
                raise EvidenceError('P1.3: actual map update rejection absent')
            report['recovery'] = recover(root, fixture, publisher, inner, supervisor, issuer,
                                         envelope, old_issuer.child.args[2], report['grant'],
                                         original_controller)
            supervisor = issuer = None  # recovery closes old and replacement children
    except BaseException as exc:
        report['failure'] = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        try:
            for stream in streams: stream.stop()
            captures.stop()
        finally:
            if supervisor is not None: supervisor.close()
            if issuer is not None: issuer.close()
            fixture.controller = original_controller
            (root/'summary.local.json').write_text(json.dumps(report, indent=2)+'\n')
    report['packet_boundary'] = assert_packet_boundary(root)
    report['status'] = 'PASS'
    (root/'summary.local.json').write_text(json.dumps(report, indent=2)+'\n')
    (root.parent/'p1.json').write_text(json.dumps(report, indent=2)+'\n')
    return report


def recover(root, fixture, publisher, inner, supervisor, issuer, stale_envelope, classpath, old_grant,
            original_controller):
    """Recreate only expired, frozen lab maps under the remaining native deny interlock.

    This is post-measurement lifecycle recovery, never a way to clear stale maps
    before observing their independent deadlines. No production recovery switch.
    """
    from isolated_enforcement import JavaIssuer, clear_owned_pins
    if time.clock_gettime_ns(time.CLOCK_BOOTTIME) <= old_grant['deadline_ns']:
        raise EvidenceError('P1.3: recovery attempted before original authority expired')
    supervisor.kill(); supervisor.close(); issuer.close()
    # The native priority-0 chain remains policy DROP with exact TC-mark matches.
    # Old TC programs still reference expired maps until the normal install
    # replaces them. Unpinning never grants traffic or creates a fallback route.
    inner(['nft', 'delete', 'table', 'inet', 'kernel_gate_v2_test'])
    clear_owned_pins(publisher.pin_dir)
    publisher.pin_dir.mkdir(mode=0o700)
    (publisher.pin_dir/'maps').mkdir(mode=0o700)
    (publisher.pin_dir/'progs').mkdir(mode=0o700)
    publisher.install()
    directory = root/'recovery'; directory.mkdir(mode=0o700)
    for name in ('established', 'new'): (directory/name).mkdir(mode=0o700)
    new_supervisor = new_issuer = None
    streams = []
    try:
        # The real original parent Controller is only an install-time owner;
        # a new child Controller reads durable state and starts denied.
        # Supervisor configuration only reads directory/TLS fields from it.
        fixture.controller = original_controller
        new_supervisor = Supervisor(fixture, publisher, directory)
        fixture.controller = SimpleNamespace(session=new_supervisor.initial['session'])
        replay = new_supervisor.ask('submit', item={'envelope': stale_envelope})
        denied = kernel_snapshot(publisher, inner); assert_hooks(denied)
        if (replay['status'] != 'DENIED' or replay['published'] or
                any(r['value']['epoch'] for r in denied['maps'].values())):
            raise EvidenceError('P1.3: stale authority restored recovery traffic')
        new_issuer = JavaIssuer(fixture, fixture.operator, fixture.node, classpath)
        fresh, _ = issue(new_supervisor, fixture, new_issuer)
        if fresh['generation'] <= old_grant['generation'] or fresh['session'] == old_grant['session']:
            raise EvidenceError('P1.3: recovery did not require fresh signed authority')
        for name, fresh_connections in (('established', False), ('new', True)):
            stream = TrafficStream(namespace=NAMES['e'], new_connections=fresh_connections)
            streams.append(stream); stream.start(directory/name); stream.ready(delivered=True)
        time.sleep(.08)
        outcomes = {}
        for name, stream in zip(('established', 'new'), streams):
            rows = stream.stop()
            if not rows or not all(r['delivered'] for r in rows):
                raise EvidenceError('P1.3: fresh-authority recovery traffic failed')
            outcomes[name] = len(rows)
        streams.clear()
        return {'status': 'PASS', 'old_authority_replay': 'DENIED',
                'fresh_generation': fresh['generation'], 'new_session': True,
                'successful_echoes': outcomes, 'kernel': kernel_snapshot(publisher, inner)}
    finally:
        for stream in streams: stream.stop()
        if new_supervisor is not None: new_supervisor.close()
        if new_issuer is not None: new_issuer.close()
