#!/usr/bin/env python3
"""Opt-in scoped-container packet experiment, not a production gate.

Keys are generated in memory and delivered to the test fixture/Java child only
through private process memory/stdin. No secrets or captures are placed in Git.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature

from admission_v2 import operation_bytes
from continuous_evidence import (CaptureSet, TrafficStream, measure,
                                 namespace_capture, denial_bracket)
from integration import SERVER
from kernel_gate_publisher_v2 import Publisher, FreshHealth, command
from native import NAMES, Topology, require_container
from native_aa_java_harness import Fixture

CLI = 'com.defenderlink.mesh.tunnel.nativeaccess.NativePolicyExporterCli'

def tunnel_error_events(text, source):
    """Classify untrusted daemon output; never forward its words or payloads."""
    if source not in ('swanctl', 'charon-e', 'charon-o'):
        raise ValueError('unknown diagnostic source')
    patterns = (('authentication_failed', r'auth(?:entication)?[^\n]{0,80}(?:fail|reject)|AUTH_FAILED'),
                ('timeout', r'timeout|timed out'),
                ('no_proposal', r'no proposal|NO_PROPOSAL_CHOSEN'),
                ('certificate_rejected', r'certificate[^\n]{0,80}(?:reject|invalid)'),
                ('initiate_failed', r'fail|error|reject'))
    return [name for name, pattern in patterns
            if re.search(pattern, text[:8192], flags=re.I)] or ['unclassified_failure']


def raw(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def pkcs8(key):
    return base64.b64encode(key.private_bytes(serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())).decode()


class JavaIssuer:
    def __init__(self, fixture, operator, node, classpath):
        self.child = subprocess.Popen(['java', '-cp', classpath, CLI], stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                      text=True, bufsize=1)
        try:
            self.ask(dict(action='init', operatorPkcs8=pkcs8(operator), nodePkcs8=pkcs8(node),
                operatorPublic=raw(operator).hex(), nodePublic=raw(node).hex(),
                supervisorPublic=raw(fixture.supervisor).hex(), serviceId=fixture.scope['serviceId'],
                clientNodeId=fixture.scope['clientNodeId'], resource=fixture.scope['resource'],
                sessionId=fixture.controller.session))
        except BaseException:
            self.close()
            raise

    def ask(self, request):
        if self.child.poll() is not None:
            raise RuntimeError('Java issuer exited')
        self.child.stdin.write(json.dumps(request, separators=(',', ':')) + '\n')
        self.child.stdin.flush()
        response = self.child.stdout.readline()
        if not response:
            raise RuntimeError('Java issuer returned no response')
        result = json.loads(response)
        if 'error' in result:
            raise RuntimeError('Java issuer refused request: ' + str(result['error']))
        return result

    def close(self):
        if self.child.poll() is None:
            self.child.stdin.close()
            try:
                self.child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait()
        self.child.stdout.close()


class TickLoop:
    def __init__(self, publisher):
        self.publisher = publisher
        self.lock = threading.RLock()
        self.stopped = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stopped.is_set():
            try:
                with self.lock:
                    self.publisher.tick()
            except Exception as exc:
                self.error = exc
                self.stopped.set()
                return
            self.stopped.wait(.08)

    def check(self):
        if self.error is not None:
            raise RuntimeError('gate publisher failed') from self.error
        if not self.thread.is_alive():
            raise RuntimeError('gate publisher stopped')

    def close(self):
        self.stopped.set()
        if self.thread.ident is not None:
            self.thread.join(timeout=3)
        self.publisher.revoke()


def operation(fixture, action, trace=None):
    challenge = json.loads((fixture.root/'challenge.json').read_text())
    op = dict(action=action, bootId=challenge['bootId'], sessionId=challenge['sessionId'],
              nonce=challenge['nonce'], generation=fixture.controller.admission.generation + 1,
              **fixture.scope)
    message = operation_bytes(op)
    signature = fixture.operator.sign(message)
    if trace is not None:
        admission = fixture.controller.admission
        try:
            fixture.operator.public_key().verify(signature, message)
            signature_valid = raw(fixture.operator) == admission.operator_key
        except InvalidSignature:
            signature_valid = False
        trace.update(action=action, state_before=admission.status,
            expected_generation=admission.generation + 1,
            supplied_generation=op['generation'],
            boot_id=op['bootId'], enforcement_epoch=fixture.aa_epoch,
            operator_id=raw(fixture.operator).hex(), node_id=fixture.node_id,
            signature_valid=signature_valid,
            challenge_bound=bool(admission.pending and all(
                op[k] == admission.pending[k] for k in ('bootId', 'sessionId', 'nonce'))),
            local_generation_floor=admission.generation,
            external_recovery_floor_verified=False,
            aa_generation=fixture.aa_generation, aa_revocation=fixture.aa_revocation,
            journal_healthy=admission.healthy,
            durable_state_present=admission.path.exists(),
            challenge_pending=admission.pending is not None)
    response = fixture.dispatch(dict(action='operation', operation=op,
        signature=base64.b64encode(signature).decode()))
    if trace is not None:
        trace.update(state_after=fixture.controller.admission.status,
            committed_generation=fixture.controller.admission.generation,
            local_journal_commit_observed=fixture.controller.admission.path.exists() and
                fixture.controller.admission.healthy and
                fixture.controller.admission.generation == op['generation'],
            supervisor_status=response['status'])
        if trace['committed_generation'] != op['generation']:
            trace['rejection_reason'] = (
                'missing_pending_challenge' if not trace['challenge_pending'] else
                'challenge_binding_mismatch' if not trace['challenge_bound'] else
                'invalid_operator_signature_or_pin' if not trace['signature_valid'] else
                'generation_floor' if op['generation'] <= trace['local_generation_floor'] else
                'challenge_lost_during_step' if fixture.controller.admission.pending is None else
                'durable_state_or_supervisor_rejection')
        else:
            trace['rejection_reason'] = None
    if response['status'] != 'DENIED' or fixture.controller.admission.generation != op['generation']:
        raise RuntimeError('signed operation not committed in denied state')
    return response


def grant(fixture, issuer, recover_trace=None):
    operation(fixture, 'RECOVER', trace=recover_trace)
    challenge = json.loads((fixture.root/'challenge.json').read_text())
    now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    envelope = issuer.ask(dict(action='issue', challenge=challenge,
        generation=fixture.controller.admission.generation + 1, nowBoottimeNs=now,
        lifetimeNs=2_999_000_000))['envelope']
    issuer.last_envelope = envelope
    result = fixture.dispatch(dict(action='grant', envelope=envelope))
    if result['status'] != 'ATTESTED' or fixture.controller.admission.deadline != envelope['payload']['deadlineBoottimeNs']:
        raise RuntimeError('Java issuance/AA attestation did not bind original deadline')
    return dict(status=result['status'], deadline_boottime_ns=fixture.controller.admission.deadline,
                generation=fixture.controller.admission.generation)


def guarded_grant(fixture, issuer, ticker):
    with ticker.lock:
        return grant(fixture, issuer)


def prepare_admission(fixture, ticker):
    """Leave a previous epoch denied and explicitly reauthorize AA before RECOVER."""
    with ticker.lock:
        if fixture.controller.admission.generation:
            operation(fixture, 'REVOKE')
        fixture.aa_generation += 1
        fixture.aa_epoch += 1
        fixture.transition('authorize')


def revoke_aa_only(fixture):
    fixture.aa_revocation += 1
    fixture.aa_epoch += 1
    fixture.transition('revoke')
    return dict(aa_generation=fixture.aa_generation, aa_revocation=fixture.aa_revocation,
                aa_epoch=fixture.aa_epoch, status_at_fault=fixture.controller.step(),
                cached_until_boottime_ns=fixture.controller.until_ns)


def stop_ticker_for_failure(ticker):
    """Stop the supervisor heartbeat without proactively zeroing either BPF map."""
    stopped_ns = time.monotonic_ns()
    ticker.stopped.set()
    ticker.thread.join(timeout=3)
    if ticker.thread.is_alive():
        raise RuntimeError('supervisor ticker failed to stop')
    return dict(stopped_ns=stopped_ns, joined_ns=time.monotonic_ns())


def restart_and_replay(fixture, ticker, stale_envelope):
    with ticker.lock:
        (fixture.root/'inbox.json').unlink(missing_ok=True)
        fixture.controller = fixture.new_controller()
        ticker.publisher.controller = fixture.controller
        initial = fixture.controller.step()
        replay = fixture.dispatch(dict(action='grant', envelope=stale_envelope))
        ticker.publisher.tick()  # read back denial before allowing the ticker to resume
        if initial != 'DENIED' or replay['status'] != 'DENIED':
            raise RuntimeError('restart or stale signed envelope resurrected admission')
        return dict(restart_status=initial, replay_status=replay['status'],
                    session=fixture.controller.session)


def stop_aa_only(fixture):
    """Stop the owned AA server; do not mutate the controller's cached attestation."""
    stopped_ns = time.monotonic_ns()
    fixture.server.shutdown()
    fixture.server.server_close()
    fixture.thread.join(timeout=3)
    if fixture.thread.is_alive():
        raise RuntimeError('AA server did not stop')
    fixture.authority.close()
    return dict(stopped_ns=stopped_ns, joined_ns=time.monotonic_ns(),
                status_at_fault=fixture.controller.step(),
                cached_until_boottime_ns=fixture.controller.until_ns)


def check_denial_budget(name, result, remaining_seconds):
    # Probe verdict includes worker scheduling and TCP timeout. This is an
    # observed upper bound, NOT the precise kernel transition timestamp.
    budget_ns = int((remaining_seconds + 1 if name in ('aa_revoke', 'aa_outage')
                     else 1) * 1_000_000_000)
    elapsed = result['first_denied_verdict_ns'] - result['event_ns']
    if elapsed < 0 or elapsed > budget_ns:
        raise RuntimeError('observed denial budget exceeded')
    result['observed_denial_elapsed_ns'] = elapsed
    result['probe_budget_ns'] = budget_ns


def captured_fault(root, name, fixture, issuer, ticker, hook, *, wait_seconds=3.5,
                   check_ticker=True):
    """A fresh signed admission and captured delivery baseline precede every fault."""
    prepare_admission(fixture, ticker)
    issued = guarded_grant(fixture, issuer, ticker)
    ticker.check()
    generation, deadline = issued['generation'], issued['deadline_boottime_ns']
    remaining = (deadline - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / 1e9
    if remaining <= .2:
        raise RuntimeError('fresh grant expired before captured baseline')
    # AA changes do not necessarily invalidate cached attestation immediately.
    # Wait through the ORIGINAL signed deadline instead of forcing reattestation.
    if name in ('aa_revoke', 'aa_outage'):
        wait_seconds = max(wait_seconds, remaining + .8)
    result = measure(root, name, {name: hook}, TrafficStream(namespace=NAMES['e']),
                     CaptureSet(namespace_capture), wait_seconds=wait_seconds)
    check_denial_budget(name, result, remaining)
    if check_ticker:
        ticker.check()
    observed = fixture.controller.admission
    expected_generation = generation + (name == 'revoke')
    if (observed.generation != expected_generation or
            observed.deadline not in (None, deadline)):
        raise RuntimeError('grant renewed or deadline extended during negative control')
    result['original_grant'] = issued
    result['post_status'] = fixture.controller.step()
    if result['post_status'] != 'DENIED':
        raise RuntimeError('control remained attested after denial observation')
    directory = Path(root)/name
    (directory/'summary.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    return result


def expiry_measure(root, fixture, issuer, ticker):
    result = measure(root, 'grant', {'grant': lambda: guarded_grant(fixture, issuer, ticker)},
                     TrafficStream(namespace=NAMES['e']), CaptureSet(namespace_capture),
                     wait_seconds=1.0)
    ticker.check()
    deadline = fixture.controller.admission.deadline
    # No renewal, no explicit revocation. Continuous traffic/captures straddle expiry.
    remaining = (deadline - time.clock_gettime_ns(time.CLOCK_BOOTTIME)) / 1e9
    if remaining <= .2:
        raise RuntimeError('grant expired before independent expiry baseline; rerun')
    result2 = observe_expiry(root, deadline, max(3.2, remaining + 1))
    ticker.check()
    if time.clock_gettime_ns(time.CLOCK_BOOTTIME) < deadline:
        raise RuntimeError('expiry observation finished before original deadline')
    return result, result2


def observe_expiry(root, deadline, duration):
    """Passive expiry: deliberately no fault hook and no lease renewal."""
    directory = Path(root)/'expiry'
    directory.mkdir(mode=0o700)
    captures = CaptureSet(namespace_capture)
    stream = TrafficStream(namespace=NAMES['e'])
    captures.start(directory)
    try:
        stream.start(directory)
        try:
            stream.ready()
            event = time.monotonic_ns()
            time.sleep(duration)
        finally:
            rows = stream.stop()
    finally:
        captures.stop()
    result = denial_bracket(rows, event)
    result['deadline_boottime_ns'] = deadline
    (directory/'probes.jsonl').write_text(''.join(json.dumps(r, sort_keys=True)+'\n' for r in rows))
    (directory/'summary.json').write_text(json.dumps(result, sort_keys=True, indent=2)+'\n')
    return result


def daemon_death(root, fixture, issuer, ticker, topology):
    # Expired admission cannot RECOVER directly: explicitly revoke, re-authorize
    # AA and obtain a new signed RECOVER and Java issuance before the control.
    with ticker.lock:
        operation(fixture, 'REVOKE')
        fixture.aa_generation += 1
        fixture.aa_epoch += 1
        fixture.transition('authorize')
    guarded_grant(fixture, issuer, ticker)
    ticker.check()
    child = topology.daemon_roles['o']
    if child.poll() is not None:
        raise RuntimeError('outer charon is not alive before death control')
    def kill():
        sent = time.monotonic_ns()
        child.send_signal(signal.SIGKILL)
        child.wait(timeout=2)
        reaped = time.monotonic_ns()
        return dict(signal_ns=sent, reaped_ns=reaped, exit_code=child.returncode)
    result = measure(root, 'charon_death', {'charon_death': kill},
                     TrafficStream(namespace=NAMES['e']), CaptureSet(namespace_capture),
                     wait_seconds=3.2)
    ticker.check()
    return result


def isolated_path(path):
    path = Path(path)
    # Explicit disposable mount, not a source checkout or generic /tmp directory.
    if (not path.is_absolute() or path.parent != Path('/lab/evidence')
            or path.name in ('.', '..') or path.is_symlink()):
        raise ValueError('evidence must be below private /lab/evidence mount')
    if path.exists():
        raise FileExistsError('refusing existing evidence')
    path.mkdir(mode=0o700)
    return path


def complete_cleanup(actions, primary):
    """Attempt every owned cleanup; keep the original diagnostic failure."""
    errors = []
    for name, action in actions:
        try:
            action()
        except Exception:
            errors.append(name if name in ('ticker', 'publisher', 'issuer',
                                           'fixture', 'server', 'topology', 'pins')
                          else 'unknown')
    if errors:
        print('isolated-cleanup-failure ' + json.dumps({'stages': errors}), file=sys.stderr)
        if primary is None:
            raise RuntimeError('isolated cleanup failed') from None


def clear_owned_pins(pin):
    if pin is None or not pin.exists():
        return
    # Do not unlink unknown pins or recursively delete bpffs.
    allowed = {'progs': {'wg_ingress', 'resource_ingress'},
               'maps': {'auth_map', 'health_map', 'verdict_map'}}
    for kind, names in allowed.items():
        leaf = pin/kind
        if leaf.exists():
            for entry in leaf.iterdir():
                if entry.name not in names:
                    raise RuntimeError('unexpected bpffs pin; manual cleanup required')
                entry.unlink()
            leaf.rmdir()
    pin.rmdir()


def run(args):
    require_container()
    if os.geteuid() != 0:
        raise RuntimeError('isolated namespace capabilities required')
    os.umask(0o077)
    evidence = isolated_path(args.evidence)
    if not os.path.ismount('/lab/private'):
        raise RuntimeError('container-private /lab/private tmpfs mount required for tunnel credentials')
    state = Path('/lab/private/state')
    state.mkdir(mode=0o700, exist_ok=False)
    topology = Topology(state)
    server = fixture = issuer = ticker = publisher = pin = None
    try:
        try:
            import native as native_module
            import config as config_module
            original_command = native_module.command
            original_provision = config_module.provision_lab
            def diagnostic_provision(directory):
                original_provision(directory)
                for role in ('e', 'o'):
                    path = directory/role/'strongswan.conf'
                    text = path.read_text()
                    path.write_text(text[:-2] + ' filelog { stdout { default = 2\n flush_line = yes\n } }\n}\n')
            config_module.provision_lab = diagnostic_provision
            def diagnostic_command(*argv, data=None):
                if 'swanctl' not in argv or '--initiate' not in argv:
                    return original_command(*argv, data=data)
                result = subprocess.run(argv, input=data, text=True, capture_output=True,
                                        timeout=30)
                if result.returncode:
                    print('tunnel-diagnostic ' + json.dumps(dict(source='swanctl',
                        categories=tunnel_error_events(result.stdout + '\n' + result.stderr,
                                                       'swanctl'), exit_code=result.returncode)),
                        file=sys.stderr)
                    raise RuntimeError('isolated swanctl initiate failed (exit ' + str(result.returncode) + ')')
                return result.stdout.strip()
            native_module.command = diagnostic_command
            try:
                topology.create()
            finally:
                native_module.command = original_command
                config_module.provision_lab = original_provision
        except RuntimeError:
            # Classify daemon logs; never forward raw lines, payloads or paths.
            for role in ('e', 'o'):
                log = state/role/'charon.log'
                if log.exists():
                    print('tunnel-diagnostic ' + json.dumps(dict(source='charon-' + role,
                        categories=tunnel_error_events(log.read_text(errors='replace'),
                                                       'charon-' + role))), file=sys.stderr)
            raise
        server = subprocess.Popen(['ip', 'netns', 'exec', NAMES['r'], 'python3', '-u', '-c', SERVER, '8080'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        operator, node, supervisor = (Ed25519PrivateKey.generate() for _ in range(3))
        fixture = Fixture(dict(operatorPkcs8=pkcs8(operator), nodePkcs8=pkcs8(node),
                               supervisorPkcs8=pkcs8(supervisor)))
        issuer = JavaIssuer(fixture, operator, node, args.classpath)
        pin = Path('/sys/fs/bpf/dl-isolated-evidence')
        pin.mkdir(mode=0o700, exist_ok=False)
        (pin/'maps').mkdir()
        (pin/'progs').mkdir()
        def inner(argv, *, input=None):
            # BPF objects and pins belong to the container's bpffs mount, not to
            # a network namespace. TC attachment and nft remain inner-netns only.
            if argv and argv[0] == 'bpftool':
                return command(argv, input=input)
            if argv and argv[0] == 'tc':
                # ip netns exec also enters a fresh mount namespace and hides the
                # container bpffs pins. nsenter switches ONLY the network namespace.
                return command(['nsenter', '--net=/run/netns/' + NAMES['i'], '--', *argv], input=input)
            return command(['ip', 'netns', 'exec', NAMES['i'], *argv], input=input)
        health = FreshHealth([topology.daemon_roles[x].pid for x in ('e', 'o')],
                             'wg-inner', 'resource', NAMES['e'], NAMES['o'], NAMES['i'],
                             vici_dir=state)
        publisher = Publisher(fixture.controller, inner, pin, 'wg-inner', 'resource',
                              health=health, object_path=args.object)
        publisher.install()
        health.prepare()
        print('health identities=' + str(health._identities()), file=sys.stderr)
        for role, dst, source in ((NAMES['e'], '10.79.0.2', '10.79.0.1'),
                                  (NAMES['i'], '10.79.0.1', '10.79.0.2')):
            route = json.loads(command(['ip', 'netns', 'exec', role, 'ip', '-j',
                                        'route', 'get', dst, 'from', source]))
            print('health route ' + role + ': ' +
                  str([(x.get('dev'), x.get('src'), x.get('prefsrc')) for x in route]),
                  file=sys.stderr)
        for role in ('e', 'o'):
            raw_state = command(['ip', 'netns', 'exec', NAMES[role], 'ip',
                                 '-s', 'xfrm', 'state'])
            print('health xfrm ' + role + ': length=' + str(len(raw_state)) +
                  ' states=' + str(raw_state.count('src ')) +
                  ' lifetime-current=' + str(raw_state.count('lifetime current:')),
                  file=sys.stderr)
        print('pregrant snapshot=' + str(health._snapshot() is not None) +
              ' challenge=' + str(health()), file=sys.stderr)
        ticker = TickLoop(publisher)
        ticker.thread.start()
        if getattr(args, 'security_p1', None):
            from security_p1 import run as qualify_security
            qualify_security(evidence, args.security_p1, fixture, issuer, ticker,
                             publisher, inner, grant, topology=topology)
            return
        if args.grant_diagnostic or getattr(args, 'functional_p0', False):
            from grant_boundary_diagnostic import run as diagnose_grant
            active_probe = None
            if getattr(args, 'functional_p0', False):
                from functional_p0 import active_grant_probe
                active_probe = active_grant_probe
            report = diagnose_grant(evidence, fixture, issuer, ticker, publisher, inner, grant,
                                    active_probe=active_probe)
            if active_probe is not None:
                from functional_p0 import assert_captures
                report['active_packet_evidence'] = assert_captures(evidence/'grant-diagnostic')
                (evidence/'p0.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
            return  # Never run faults before a positive packet baseline.
        expiry_measure(evidence, fixture, issuer, ticker)
        captured_fault(evidence, 'revoke', fixture, issuer, ticker,
                       lambda: operation(fixture, 'REVOKE'))
        captured_fault(evidence, 'aa_revoke', fixture, issuer, ticker,
                       lambda: revoke_aa_only(fixture))
        captured_fault(evidence, 'restart_replay', fixture, issuer, ticker,
                       lambda: restart_and_replay(fixture, ticker, issuer.last_envelope))
        # The new controller has a new signed session/challenge; reset Java's
        # issuance sequence by starting a NEW exporter, never reuse the old one.
        issuer.close()
        issuer = JavaIssuer(fixture, operator, node, args.classpath)
        captured_fault(evidence, 'supervisor_death', fixture, issuer, ticker,
                       lambda: stop_ticker_for_failure(ticker), check_ticker=False)
        ticker.close()
        ticker = TickLoop(publisher)
        ticker.thread.start()
        captured_fault(evidence, 'aa_outage', fixture, issuer, ticker,
                       lambda: stop_aa_only(fixture))
        (evidence/'result.json').write_text(json.dumps(dict(status='measured',
            scenarios=['grant', 'expiry', 'revoke', 'aa_revoke', 'restart_replay',
                       'supervisor_death', 'aa_outage'],
            blocked=['clock_regression: no process-local wall-clock injection',
                     'charon_death: separate destructive transport run required'],
            interpretation='probe brackets only; inspect captures before acceptance')) + '\n')
    finally:
        primary = sys.exc_info()[1]
        def stop_server():
            if server is not None:
                server.terminate()
                try: server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill(); server.wait()
        actions = []
        if ticker is not None:
            actions.append(('ticker', ticker.close))
        elif publisher is not None and publisher.installed:
            actions.append(('publisher', publisher.revoke))
        if issuer is not None:
            actions.append(('issuer', issuer.close))
        if fixture is not None:
            actions.append(('fixture', fixture.close))
        actions.extend((('server', stop_server), ('topology', topology.close),
                        ('pins', lambda: clear_owned_pins(pin))))
        complete_cleanup(actions, primary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--object', required=True, type=Path)
    parser.add_argument('--classpath', default='/lab/target/test-classes:/lab/target/classes:/lab/lib/*')
    parser.add_argument('--grant-diagnostic', action='store_true',
                        help='one bounded grant-phase packet probe; never run faults')
    parser.add_argument('--functional-p0', action='store_true',
                        help='grant-only positive path plus active-grant negative packet probes; no faults')
    parser.add_argument('--security-p1', choices=('expiry', 'revoke', 'charon_crash'),
                        help='exactly one P1 fault category per isolated container')
    args = parser.parse_args()
    if not args.object.is_file():
        parser.error('compiled BPF object required')
    run(args)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        from grant_boundary_diagnostic import safe_failure
        print('isolated-runner-failure ' + json.dumps(safe_failure(exc), sort_keys=True),
              file=sys.stderr)
        sys.exit(1)
