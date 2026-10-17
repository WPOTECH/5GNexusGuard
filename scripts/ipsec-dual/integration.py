#!/usr/bin/env python3
"""Privileged data-plane gates. Synthetic leases here are NOT product-policy integration."""
import os
import re
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from native import Topology, NAMES, command, ns, require_container

SERVER = '''import socketserver
class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  while True:
   data = self.request.recv(4096)
   if not data: break
   self.request.sendall(data)
class Server(socketserver.ThreadingTCPServer):
 allow_reuse_address = True
Server(("10.80.0.2", int(__import__('sys').argv[1])), Handler).serve_forever()
'''
CLIENT = '''import socket,sys
s=socket.create_connection((sys.argv[1],int(sys.argv[2])),1)
s.settimeout(1)
payload=b"native-dual-packet-evidence"*2048
s.sendall(payload)
received=b""
while len(received)<len(payload):
 chunk=s.recv(8192)
 assert chunk
 received+=chunk
assert received==payload
'''


def process(role, *args, **kwargs):
    return subprocess.Popen(['ip', 'netns', 'exec', NAMES[role], *args], **kwargs)


def probe(role='e', host='10.80.0.2', port=8080):
    result = subprocess.run(['ip', 'netns', 'exec', NAMES[role], 'python3', '-c', CLIENT,
                             host, str(port)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=4)
    return result.returncode == 0


def check(label, condition):
    if not condition:
        raise AssertionError(label)
    print('PASS ' + label, flush=True)


def stop(child):
    if child.poll() is None:
        child.send_signal(signal.SIGINT)
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill(); child.wait()


BOUNDARIES = (('e', 'pub', 'endpoint-public'), ('o', 'pub', 'outer-public'),
              ('o', 'transit', 'outer-transit'), ('i', 'transit', 'inner-ingress'),
              ('r', 'resource', 'resource'))


def observe(topology, destination):
    """Allowlisted metadata only: never XFRM state, credentials or packet payload."""
    destination.mkdir(parents=True, exist_ok=True)
    for role in ('e', 'o'):
        (destination / (role + '-sas.txt')).write_text(topology.swan(role, '--list-sas')
            if topology.daemon_roles[role].poll() is None else 'owned charon exited\n')
        (destination / (role + '-policy.txt')).write_text(ns(role, 'ip', '-s', 'xfrm', 'policy'))
    for role in NAMES:
        (destination / (role + '-routes.txt')).write_text(ns(role, 'ip', 'route', 'show'))
        (destination / (role + '-nft.txt')).write_text(ns(role, 'nft', 'list', 'ruleset'))


def capture_phase(topology, evidence, label, action, expected):
    """Each phase has five bidirectional captures and before/after observations."""
    directory = evidence / label
    directory.mkdir(parents=True, exist_ok=False)
    captures = []
    try:
        for role, interface, boundary in BOUNDARIES:
            directions = ('all', 'out') if boundary.endswith('public') else ('all',)
            for direction in directions:
                suffix = '-wire-egress' if direction == 'out' else ''
                name = boundary + suffix
                path = directory / (name + '.pcap')
                log = directory / (name + '.capture-status')
                args = ['tcpdump', '-Z', 'root', '-U', '-n']
                if direction == 'out':
                    args += ['-Q', 'out']
                with log.open('w') as stream:
                    child = process(role, *args, '-i', interface, '-w', str(path),
                                    stdout=subprocess.DEVNULL, stderr=stream)
                captures.append((name, path, log, child))
        deadline = time.monotonic() + 3
        while not all('listening on' in log.read_text() for _, _, log, _ in captures):
            if time.monotonic() >= deadline or any(c.poll() is not None for _, _, _, c in captures):
                raise AssertionError('capture readiness failed')
            time.sleep(0.05)
        observe(topology, directory / 'before')
        action()
        # Refresh after slow observations/injection so a denial cannot be lease expiry.
        if expected is not None:
            topology.authorize(3000)
            check(label + ' live probe', probe() == expected)
        observe(topology, directory / 'after')
        time.sleep(1.1)
    finally:
        for _, _, _, child in captures:
            stop(child)
    for boundary, path, log, child in captures:
        check(label + ' ' + boundary + ' capture intact',
              path.exists() and path.stat().st_size >= 24 and child.returncode == 0
              and re.search(r'^0 packets dropped by kernel$', log.read_text(), re.MULTILINE) is not None)
        if boundary != 'resource':
            public = boundary.startswith(('endpoint-public', 'outer-public'))
            wire = boundary.endswith('-wire-egress')
            # AF_PACKET may show post-XFRM decrypted WG on the receiving public
            # interface. The separate outbound capture tests actual wire escape.
            allowed = ('(ip proto 50 or udp port 500 or udp port 4500)'
                       if wire else
                       '(ip proto 50 or udp port 500 or udp port 4500 or udp port 51821)'
                       if public else '(udp port 51821)')
            disallowed = 'ip and not ' + allowed
            if wire:
                check(label + ' ' + boundary + ' pinned peers and no IPv6',
                      not command('tcpdump', '-nn', '-r', str(path), 'ip6')
                      and not command('tcpdump', '-nn', '-r', str(path),
                                      'ip and not (host 192.0.2.1 and host 192.0.2.2)'))
            check(label + ' ' + boundary + ' encrypted only',
                  b'native-dual-packet-evidence' not in path.read_bytes()
                  and not command('tcpdump', '-nn', '-r', str(path), disallowed))
            if expected is True:
                transport = 'ip proto 50' if public else 'udp port 51821'
                check(label + ' ' + boundary + ' encrypted traffic observed',
                      bool(command('tcpdump', '-nn', '-r', str(path), transport)))
        elif expected is not None:
            check(label + ' resource marker',
                  (b'native-dual-packet-evidence' in path.read_bytes()) == expected)


def run_fault(topology, evidence, label, inject, restore, failure_expected=False):
    def lifecycle():
        capture_phase(topology, evidence, label + '-baseline', lambda: None, True)
        try:
            capture_phase(topology, evidence, label + '-fault', inject, failure_expected)
        finally:
            # Recovery has its own captures, including link/daemon restart and retries.
            def recover():
                for _ in range(8):
                    if not topology.reconcile_routes():
                        topology.authorize(0)
                        time.sleep(1)
                        continue
                    if not topology.ipsec_ready():
                        try:
                            topology.recover_ipsec()
                        except RuntimeError:
                            time.sleep(1)
                            continue
                    topology.authorize(3000)
                    if probe():
                        return
                    time.sleep(1)
                raise AssertionError(label + ' bounded recovery exhausted')
            # A down interface cannot accept a new tcpdump attachment. The
            # continuous envelope records restoration itself; phase captures
            # begin once the interface/process is restored.
            restore()
            capture_phase(topology, evidence, label + '-recovery', recover, True)
    # An overlapping capture covers the gaps between phase observers and starts.
    capture_phase(topology, evidence, label + '-continuous', lifecycle, None)


def readiness_extension(topology, evidence):
    for role, interface in (('o', 'pub'), ('i', 'wg-inner')):
        run_fault(topology, evidence, role + '-' + interface + '-outage',
                  lambda: ns(role, 'ip', 'link', 'set', interface, 'down'),
                  lambda: ns(role, 'ip', 'link', 'set', interface, 'up'))
    run_fault(topology, evidence, 'sa-loss',
              lambda: topology.swan('e', '--terminate', '--ike', 'hybrid', '--timeout', '3'),
              topology.recover_ipsec)
    for role in ('o', 'e'):
        def crash():
            child = topology.daemon_roles[role]
            child.kill()
            child.wait(timeout=3)
            check(role + ' dead daemon never ready', not topology.ipsec_ready())
            topology.authorize(0)
            check(role + ' supervisor crash gate denies', not probe())
        # Kernel SAs can survive SIGKILL. Do not reauthorize for the crash probe.
        run_fault(topology, evidence, role + '-charon-crash', crash,
                  topology.recover_ipsec, failure_expected=None)
    def unrevoked_sa_window():
        # Negative control: reproduce the surviving-kernel-SA window. No
        # supervisor revocation is run until the timed set denies the flow.
        topology.authorize(3000)
        check('pre-crash application baseline', probe())
        before_kill_ns = time.monotonic_ns()
        child = topology.daemon_roles['o']
        child.kill()
        child.wait(timeout=2)
        reaped_ns = time.monotonic_ns()
        check('gateway daemon reaped', child.poll() is not None)
        observations = []
        until = time.monotonic() + 6
        while time.monotonic() < until:
            started_ns = time.monotonic_ns()
            permitted = probe()
            ended_ns = time.monotonic_ns()
            observations.append((started_ns, ended_ns, permitted))
            if not permitted:
                break
            time.sleep(0.05)
        check('surviving SA forwards after daemon exit', any(row[2] for row in observations))
        check('unrenewed lease eventually denies', bool(observations) and not observations[-1][2])
        last = next((row for row in reversed(observations) if row[2]), None)
        denied = observations[-1]
        (evidence / 'surviving-sa-window.txt').write_text(
            'clock=CLOCK_MONOTONIC ns; death bracket (signal, reaped); '
            'probe bracket (start, end, delivered)\n'
            + f'death {before_kill_ns} {reaped_ns}\n'
            + ''.join(f'probe {start} {end} {int(ok)}\n' for start, end, ok in observations)
            + f'last_delivered_end {last[1] if last else "none"}\n'
            + f'first_denied_bracket {denied[0]} {denied[1]}\n')
        check('denial remains after expiry', not probe())
    run_fault(topology, evidence, 'unrevoked-charon-death', unrevoked_sa_window,
              topology.recover_ipsec, failure_expected=None)

    def revoke_race():
        # Bounded serialized policy transition with traffic in flight; no refresh worker.
        topology.authorize(3000)
        child = process('e', 'python3', '-c', CLIENT, '10.80.0.2', '8080',
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            topology.authorize(0)
            child.wait(timeout=4)
            check('post-revocation new flow denied', not probe())
        finally:
            stop(child)
    run_fault(topology, evidence, 'revoke-inflight', revoke_race,
              lambda: topology.authorize(3000), failure_expected=None)


def main():
    require_container()
    if os.geteuid() != 0:
        print('BLOCKED: root, NET_ADMIN and SYS_ADMIN required; no packet gates executed.')
        return 77
    for tool in ('ip', 'wg', 'nft', 'tcpdump', 'python3', 'openssl', 'swanctl'):
        import shutil
        if shutil.which(tool) is None:
            print('BLOCKED: missing ' + tool)
            return 77
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='ipsec-dual-') as temporary:
        state = Path(temporary)
        topology = Topology(state)
        children = []
        captures = []
        try:
            container_forward = command('sysctl', '-n', 'net.ipv4.ip_forward')
            container_rp = command('sysctl', '-n', 'net.ipv4.conf.all.rp_filter')
            topology.create()
            for role in NAMES:
                check(role + ' namespaced forwarding',
                      ns(role, 'sysctl', '-n', 'net.ipv4.ip_forward')
                      == ('1' if role in 'oi' else '0'))
                check(role + ' namespaced rp_filter',
                      ns(role, 'sysctl', '-n', 'net.ipv4.conf.all.rp_filter') == '0')
            check('container initial namespace sysctls unchanged',
                  command('sysctl', '-n', 'net.ipv4.ip_forward') == container_forward
                  and command('sysctl', '-n', 'net.ipv4.conf.all.rp_filter') == container_rp)
            public_keys = [ns(role, 'wg', 'show', device, 'public-key')
                           for role, device in (('e', 'wg-inner'), ('i', 'wg-inner'))]
            check('two independent inner WireGuard keys', len(set(public_keys)) == 2)
            for port in (8080, 9090):
                children.append(process('r', 'python3', '-c', SERVER, str(port),
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            time.sleep(0.5)
            check('resource processes running', all(c.poll() is None for c in children))
            check('default deny without lease', not probe())
            for role, interface, label in (('e', 'pub', 'pub-endpoint'),
                                           ('o', 'pub', 'pub-gateway'),
                                           ('o', 'transit', 'transit'),
                                           ('i', 'transit', 'inner-receive'),
                                           ('r', 'resource', 'resource')):
                capture = state / (label + '.pcap')
                log_path = state / (label + '.tcpdump.log')
                direction = ('-Q', 'out') if interface == 'pub' else ()
                child = process(role, 'tcpdump', '-Z', 'root', '-U', '-n', *direction,
                                '-i', interface, '-w', str(capture),
                                stdout=subprocess.DEVNULL, stderr=open(log_path, 'w'))
                children.append(child); captures.append((capture, child))
            time.sleep(0.5)
            check('packet capture processes running', all(child.poll() is None for _, child in captures))
            for attempt in range(5):
                topology.authorize(3000)
                if probe():
                    break
                time.sleep(1)
            else:
                for role in ('e', 'i'):
                    print('WG DIAGNOSTIC ' + role + ': '
                          + ns(role, 'wg', 'show', 'wg-inner', 'latest-handshakes'), flush=True)
                time.sleep(2)
                raise AssertionError('resource reachable over nested tunnels')
            check('resource reachable over nested tunnels', probe())
            for role, interface in (('e', 'wg-inner'), ('i', 'wg-inner')):
                handshakes = ns(role, 'wg', 'show', interface, 'latest-handshakes').splitlines()
                check(role + ' ' + interface + ' real handshake',
                      bool(handshakes) and all(int(line.split()[1]) > 0 for line in handshakes))
                transfer = ns(role, 'wg', 'show', interface, 'transfer').splitlines()
                check(role + ' ' + interface + ' encrypted transfer counters',
                      bool(transfer) and all(int(line.split()[1]) > 0 and int(line.split()[2]) > 0 for line in transfer))
            time.sleep(2)  # Allow libpcap's packet buffer timeout to deliver frames.
            for capture, child in captures:
                stop(child)
                if capture.stat().st_size <= 24:
                    print('CAPTURE DIAGNOSTIC ' + capture.stem + ': '
                          + (state / (capture.stem + '.tcpdump.log')).read_text()[-1000:],
                          flush=True)
                check(capture.stem + ' packet capture populated', capture.stat().st_size > 24)
                contains = b'native-dual-packet-evidence' in capture.read_bytes()
                check(capture.stem + ' plaintext visibility', contains == (capture.stem == 'resource'))
                if capture.stem != 'resource':
                    expected = 'ip proto 50' if capture.stem.startswith('pub') else 'udp port 51821'
                    permitted = ('(ip proto 50 or udp port 500 or udp port 4500)'
                                 if capture.stem.startswith('pub') else '(udp port 51821)')
                    encrypted = command('tcpdump', '-nn', '-r', str(capture), expected)
                    unexpected = command('tcpdump', '-nn', '-r', str(capture), 'ip and not ' + permitted)
                    check(capture.stem + ' expected encrypted transport only', bool(encrypted) and not unexpected)
            evidence = Path('/evidence')
            evidence.mkdir(exist_ok=True)
            for role in ('e', 'o'):
                sa = topology.swan(role, '--list-sas')
                check(role + ' IKEv2 and tunnel ESP installed', 'ESTABLISHED' in sa and 'INSTALLED' in sa and 'ESP' in sa)
                import re
                counters = re.findall(r'(\d+) bytes', sa)
                check(role + ' IPsec counters nonzero both ways', len(counters) >= 2 and all(int(n) > 0 for n in counters))
                (evidence / (role + '-sas.txt')).write_text(sa)
                # Policy only: NEVER dump ip xfrm state (contains session encryption keys).
                (evidence / (role + '-policy.txt')).write_text(ns(role, 'ip', '-s', 'xfrm', 'policy'))
            for role in NAMES:
                (evidence / (role + '-nft.txt')).write_text(ns(role, 'nft', 'list', 'ruleset'))
            for role in ('e', 'i'):
                (evidence / (role + '-wg.txt')).write_text(ns(role, 'wg', 'show', 'wg-inner', 'transfer'))
            readiness_extension(topology, evidence / 'faults')
            fault_evidence = evidence / 'faults'
            def bypasses():
                for label, kwargs in (('wrong-port', {'port': 9090}),
                                      ('public-bypass', {'host': '192.0.2.2'}),
                                      ('outer-origin', {'role': 'o'})):
                    topology.authorize(3000)
                    check(label + ' denied', not probe(**kwargs))
            run_fault(topology, fault_evidence, 'bypasses', bypasses, lambda: None,
                      failure_expected=None)

            def established_revocation():
                topology.authorize(3000)
                live = process('e', 'python3', '-u', '-c', '''import socket,sys
s=socket.create_connection(("10.80.0.2",8080),1);s.settimeout(1)
s.sendall(b"before");assert s.recv(6)==b"before"
print("ready",flush=True);sys.stdin.readline()
try:
 s.sendall(b"after"); data=s.recv(5)
except (TimeoutError,OSError): sys.exit(0)
sys.exit(1 if data else 0)
''', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                children.append(live)
                import select
                ready, _, _ = select.select([live.stdout], [], [], 3)
                check('established flow ready', bool(ready) and live.stdout.readline().strip() == 'ready')
                topology.authorize(0)
                live.communicate('\n', timeout=4)
                check('revocation blocks established flow', live.returncode == 0)
                check('revocation blocks new flow', not probe())
            run_fault(topology, fault_evidence, 'established-revocation', established_revocation,
                      lambda: None, failure_expected=None)

            def expire_lease():
                # The packet gate truncates to whole seconds, conservatively.
                # Keep an established TCP socket active across the fixed deadline.
                deadline_ms = time.time_ns() // 1_000_000 + 2500
                topology.authorize(3000, deadline_ms=deadline_ms)
                check('short lease initially works', probe())
                live = process('e', 'python3', '-u', '-c', '''import socket,sys
s=socket.create_connection(("10.80.0.2",8080),1);s.settimeout(1)
s.sendall(b"before");assert s.recv(6)==b"before"
print("ready",flush=True);sys.stdin.readline()
try:
 s.sendall(b"after"); data=s.recv(5)
except (TimeoutError,OSError): sys.exit(0)
sys.exit(1 if data else 0)
''', stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                children.append(live)
                import select
                assert live.stdout is not None
                ready, _, _ = select.select([live.stdout], [], [], 3)
                check('expiry established flow ready', bool(ready) and live.stdout.readline().strip() == 'ready')
                time.sleep(2.7)
                live.communicate('\n', timeout=4)
                check('kernel expiry blocks established flow', live.returncode == 0)
                check('kernel lease expiry without refresh', not probe())
                topology.authorize(3000, deadline_ms=deadline_ms)
                check('expired lease replay cannot reopen traffic', not probe())
            run_fault(topology, fault_evidence, 'lease-expiry', expire_lease,
                      lambda: None, failure_expected=None)

            conf = state / 'e/swanctl.conf'
            original_conf = conf.read_text()
            def wrong_identity():
                topology.swan('e', '--terminate', '--ike', 'hybrid', '--timeout', '3')
                conf.write_text(original_conf.replace('id = gateway.test', 'id = wrong.test'))
                topology.swan('e', '--load-conns', '--file', str(conf))
                rejected = False
                try:
                    topology.swan('e', '--initiate', '--child', 'inner-transport', '--timeout', '3')
                except RuntimeError:
                    rejected = True
                check('wrong pinned identity rejected', rejected)
            def restore_identity():
                try:
                    topology.swan('e', '--terminate', '--ike', 'hybrid', '--timeout', '3')
                except RuntimeError:
                    pass
                conf.write_text(original_conf)
                topology.swan('e', '--load-conns', '--file', str(conf))
            run_fault(topology, fault_evidence, 'wrong-identity', wrong_identity, restore_identity)

            original = ns('e', 'wg', 'show', 'wg-inner', 'peers')
            wrong = command('wg', 'pubkey', data=command('wg', 'genkey') + '\n')
            def wrong_peer():
                ns('e', 'wg', 'set', 'wg-inner', 'peer', original, 'remove')
                ns('e', 'wg', 'set', 'wg-inner', 'peer', wrong, 'allowed-ips', '10.80.0.2/32',
                   'endpoint', '10.78.0.2:51821')
            def restore_peer():
                ns('e', 'wg', 'set', 'wg-inner', 'peer', wrong, 'remove')
                ns('e', 'wg', 'set', 'wg-inner', 'peer', original, 'allowed-ips', '10.80.0.2/32',
                   'endpoint', '10.78.0.2:51821', 'persistent-keepalive', '1')
            run_fault(topology, fault_evidence, 'wrong-inner-peer', wrong_peer, restore_peer)
            run_fault(topology, fault_evidence, 'fallback-route',
                      lambda: ns('e', 'ip', 'route', 'replace', '10.80.0.2/32',
                                 'via', '192.0.2.2', 'dev', 'pub'), topology.reconcile_routes)
            (evidence / 'packages.txt').write_text(command('dpkg-query', '-W'))
            print('PASS all hybrid data-plane gates (synthetic policy; see Java policy tests).')
            return 0
        finally:
            for child in reversed(children):
                stop(child)
            try:
                # Retain packet evidence even if a gate fails; never copy credentials.
                import shutil
                evidence = Path('/evidence')
                evidence.mkdir(exist_ok=True)
                for capture, _ in captures:
                    if capture.exists():
                        shutil.copyfile(capture, evidence / capture.name)
            finally:
                topology.close()
                remaining = command('ip', 'netns', 'list').splitlines()
                check('owned namespaces cleaned up', not any(
                    line.split()[0] in NAMES.values() for line in remaining if line.strip()))



if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        # No subprocess output or key material is included.
        print('FAIL native data-plane gate: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
