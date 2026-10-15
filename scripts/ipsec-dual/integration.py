#!/usr/bin/env python3
"""Privileged data-plane gates. Synthetic leases here are NOT product-policy integration."""
import os
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
            check('resource reachable over nested tunnels', True)
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
            # Keep a second public capture throughout the negative tests.
            negative_capture = state / 'fail-closed-public.pcap'
            negative_child = process('e', 'tcpdump', '-Z', 'root', '-U', '-n', '-Q', 'out', '-i', 'pub',
                                     '-w', str(negative_capture), stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            children.append(negative_child)
            captures.append((negative_capture, negative_child))
            time.sleep(0.3)
            check('negative capture started', negative_child.poll() is None)
            topology.authorize(3000)
            check('other live resource port denied', not probe(port=9090))
            check('public service bypass denied', not probe(host='192.0.2.2'))
            check('outer gateway cannot originate resource access', not probe(role='o'))
            # An already-established TCP flow must lose authorization as well.
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
            topology.authorize(1000)
            check('renewed authorization works', probe())
            time.sleep(1.2)
            check('kernel expiry without supervisor refresh', not probe())
            # Down a layer with a valid lease: no alternative plaintext path.
            for role, interface in (('o', 'pub'), ('i', 'wg-inner')):
                topology.authorize(3000)
                ns(role, 'ip', 'link', 'set', interface, 'down')
                check(interface + ' loss fails closed', not probe())
                ns(role, 'ip', 'link', 'set', interface, 'up')
                check(interface + ' owned routes reconciled', topology.reconcile_routes())
                for attempt in range(8):
                    if attempt == 3 and interface == 'pub':
                        topology.swan('e', '--terminate', '--ike', 'hybrid', '--timeout', '3')
                        topology.swan('e', '--initiate', '--child', 'inner-transport', '--timeout', '8')
                    topology.authorize(3000)
                    if probe():
                        break
                    time.sleep(1)
                else:
                    print('RECOVERY DIAGNOSTIC route: '
                          + ns('e', 'ip', 'route', 'get', '192.0.2.2'), flush=True)
                    print('RECOVERY DIAGNOSTIC IKE: '
                          + topology.swan('e', '--list-sas')[-1200:], flush=True)
                    print('RECOVERY DIAGNOSTIC WG: '
                          + ns('e', 'wg', 'show', 'wg-inner', 'latest-handshakes'), flush=True)
                    print('RECOVERY DIAGNOSTIC gateway IKE: '
                          + topology.swan('o', '--list-sas')[-1200:], flush=True)
                    print('RECOVERY DIAGNOSTIC gateway return route: '
                          + ns('o', 'ip', 'route', 'show', '10.77.0.1/32'), flush=True)
                    print('RECOVERY DIAGNOSTIC gateway forwarding: '
                          + ns('o', 'nft', 'list', 'chain', 'inet', 'ipsec_dual', 'forward'), flush=True)
                    print('RECOVERY DIAGNOSTIC inner WG endpoint/transfer: '
                          + ns('i', 'wg', 'show', 'wg-inner', 'endpoints') + ' / '
                          + ns('i', 'wg', 'show', 'wg-inner', 'transfer'), flush=True)
                    print('RECOVERY DIAGNOSTIC inner routes: '
                          + ns('i', 'ip', 'route', 'get', '10.77.0.1'), flush=True)
                    for side in ('e', 'o'):
                        print('RECOVERY DIAGNOSTIC ' + side + ' link/neigh: '
                              + ns(side, 'ip', '-br', 'link', 'show', 'dev', 'pub') + ' / '
                              + ns(side, 'ip', 'neigh', 'show', 'dev', 'pub'), flush=True)
                    raise AssertionError(interface + ' restore recovers')
                check(interface + ' restore recovers', True)
            # Explicit SA/policy loss must deny transport, even while routes remain.
            topology.swan('e', '--terminate', '--ike', 'hybrid', '--timeout', '3')
            topology.authorize(3000)
            check('outer SA removal fails closed', not probe())
            topology.swan('e', '--initiate', '--child', 'inner-transport', '--timeout', '8')
            topology.authorize(3000)
            check('outer SA restore recovers', probe())
            # CA-trusted certificate with the wrong pinned identity must be rejected.
            topology.swan('e', '--terminate', '--ike', 'hybrid', '--timeout', '3')
            conf = state / 'e/swanctl.conf'
            original_conf = conf.read_text()
            conf.write_text(original_conf.replace('id = gateway.test', 'id = wrong.test'))
            topology.swan('e', '--load-conns', '--file', str(conf))
            rejected = False
            try:
                topology.swan('e', '--initiate', '--child', 'inner-transport', '--timeout', '3')
            except RuntimeError:
                rejected = True
            check('wrong pinned certificate identity rejected', rejected)
            topology.authorize(3000)
            check('wrong certificate identity denies resource', not probe())
            # Clear pending failed negotiation before restoring the connection.
            try:
                topology.swan('e', '--terminate', '--ike', 'hybrid', '--timeout', '3')
            except RuntimeError:
                pass
            conf.write_text(original_conf)
            topology.swan('e', '--load-conns', '--file', str(conf))
            topology.swan('e', '--initiate', '--child', 'inner-transport', '--timeout', '8')
            topology.authorize(3000)
            check('certificate profile restore recovers', probe())
            # Remove a valid peer and substitute a separately generated wrong key.
            original = ns('e', 'wg', 'show', 'wg-inner', 'peers')
            wrong = command('wg', 'pubkey', data=command('wg', 'genkey') + '\n')
            ns('e', 'wg', 'set', 'wg-inner', 'peer', original, 'remove')
            ns('e', 'wg', 'set', 'wg-inner', 'peer', wrong, 'allowed-ips', '10.80.0.2/32',
               'endpoint', '10.78.0.2:51821')
            topology.authorize(3000)
            check('wrong inner peer cannot reach resource', not probe())
            ns('e', 'wg', 'set', 'wg-inner', 'peer', wrong, 'remove')
            ns('e', 'wg', 'set', 'wg-inner', 'peer', original, 'allowed-ips', '10.80.0.2/32',
               'endpoint', '10.78.0.2:51821', 'persistent-keepalive', '1')
            topology.authorize(3000)
            # Handshake retries after a peer replacement may take several seconds.
            for _ in range(6):
                topology.authorize(3000)
                if probe():
                    break
                time.sleep(1)
            topology.authorize(3000)
            check('correct inner peer restored before fallback test', probe())
            # Even an injected fallback route must be rejected by endpoint egress policy.
            ns('e', 'ip', 'route', 'replace', '10.80.0.2/32', 'via', '192.0.2.2', 'dev', 'pub')
            topology.authorize(3000)
            check('injected public fallback route blocked', not probe())
            stop(negative_child)
            check('failure tests emit no public plaintext or WG transport',
                  not command('tcpdump', '-nn', '-r', str(negative_capture),
                              'ip and not (ip proto 50 or udp port 500 or udp port 4500)')
                  and b'native-dual-packet-evidence' not in negative_capture.read_bytes())
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
        import traceback
        traceback.print_exc()
        print('FAIL native data-plane gate: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
