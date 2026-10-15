#!/usr/bin/env python3
"""Privileged data-plane gates. Synthetic leases here are NOT product-policy integration."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from native import Topology, NAMES, command, ns

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
s.sendall(b"native-dual-packet-evidence")
assert s.recv(4096)==b"native-dual-packet-evidence"
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
    if os.geteuid() != 0:
        print('BLOCKED: root, NET_ADMIN and SYS_ADMIN required; no packet gates executed.')
        return 77
    for tool in ('ip', 'wg', 'nft', 'tcpdump', 'python3'):
        import shutil
        if shutil.which(tool) is None:
            print('BLOCKED: missing ' + tool)
            return 77
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='native-dual-') as temporary:
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
                           for role, device in (('e', 'wg-outer'), ('o', 'wg-outer'),
                                                ('e', 'wg-inner'), ('i', 'wg-inner'))]
            check('four independent WireGuard keys', len(set(public_keys)) == 4)
            for port in (8080, 9090):
                children.append(process('r', 'python3', '-c', SERVER, str(port),
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            time.sleep(0.5)
            check('resource processes running', all(c.poll() is None for c in children))
            check('default deny without lease', not probe())
            for role, interface, label in (('e', 'pub', 'pub'),
                                           ('e', 'wg-outer', 'endpoint-outer'),
                                           ('o', 'wg-outer', 'gateway-outer'),
                                           ('o', 'transit', 'transit'),
                                           ('i', 'transit', 'inner-receive'),
                                           ('r', 'resource', 'resource')):
                capture = state / (label + '.pcap')
                child = process(role, 'tcpdump', '-U', '-n', '-i', interface, '-w', str(capture),
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                children.append(child); captures.append((capture, child))
            time.sleep(0.5)
            topology.authorize(3000)
            if not probe():
                for role in NAMES:
                    print('DIAGNOSTIC ' + role + ' routes: ' + ns(role, 'ip', '-4', 'route', 'show'), flush=True)
                    print('DIAGNOSTIC ' + role + ' links: ' + ns(role, 'ip', '-br', 'addr'), flush=True)
                for role, interface in (('e', 'wg-outer'), ('o', 'wg-outer'),
                                        ('e', 'wg-inner'), ('i', 'wg-inner')):
                    print('DIAGNOSTIC ' + role + '/' + interface + ' handshakes: '
                          + ns(role, 'wg', 'show', interface, 'latest-handshakes'), flush=True)
                    print('DIAGNOSTIC ' + role + '/' + interface + ' transfer: '
                          + ns(role, 'wg', 'show', interface, 'transfer'), flush=True)
                print('DIAGNOSTIC endpoint nft output: '
                      + ns('e', 'nft', 'list', 'chain', 'inet', 'native_dual', 'output'), flush=True)
                print('DIAGNOSTIC inner endpoint route: '
                      + ns('e', 'ip', 'route', 'get', '10.78.0.2'), flush=True)
                print('DIAGNOSTIC inner gateway return route: '
                      + ns('i', 'ip', 'route', 'get', '10.77.0.1'), flush=True)
                for capture, child in captures:
                    stop(child)
                    print('DIAGNOSTIC capture ' + capture.stem + ': '
                          + command('tcpdump', '-nn', '-r', str(capture)), flush=True)
            check('resource reachable over nested tunnels', probe())
            for role, interface in (('e', 'wg-outer'), ('o', 'wg-outer'), ('e', 'wg-inner'), ('i', 'wg-inner')):
                handshakes = ns(role, 'wg', 'show', interface, 'latest-handshakes').splitlines()
                check(role + ' ' + interface + ' real handshake',
                      bool(handshakes) and all(int(line.split()[1]) > 0 for line in handshakes))
                transfer = ns(role, 'wg', 'show', interface, 'transfer').splitlines()
                check(role + ' ' + interface + ' encrypted transfer counters',
                      bool(transfer) and all(int(line.split()[1]) > 0 and int(line.split()[2]) > 0 for line in transfer))
            for capture, child in captures:
                stop(child)
                check(capture.stem + ' packet capture populated', capture.stat().st_size > 24)
                contains = b'native-dual-packet-evidence' in capture.read_bytes()
                check(capture.stem + ' plaintext visibility', contains == (capture.stem == 'resource'))
                if capture.stem != 'resource':
                    port = '51820' if capture.stem == 'pub' else '51821'
                    encrypted = command('tcpdump', '-nn', '-r', str(capture), 'udp', 'port', port)
                    unexpected = command('tcpdump', '-nn', '-r', str(capture),
                                         'ip and not (udp and port ' + port + ')')
                    check(capture.stem + ' carries only expected WG transport', bool(encrypted) and not unexpected)
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
            for role, interface in (('o', 'wg-outer'), ('i', 'wg-inner')):
                topology.authorize(3000)
                ns(role, 'ip', 'link', 'set', interface, 'down')
                check(interface + ' loss fails closed', not probe())
                ns(role, 'ip', 'link', 'set', interface, 'up')
                topology.authorize(3000)
                check(interface + ' restore recovers', probe())
            # Remove a valid peer and substitute a separately generated wrong key.
            original = ns('e', 'wg', 'show', 'wg-inner', 'peers')
            wrong = command('wg', 'pubkey', data=command('wg', 'genkey') + '\n')
            ns('e', 'wg', 'set', 'wg-inner', 'peer', original, 'remove')
            ns('e', 'wg', 'set', 'wg-inner', 'peer', wrong, 'allowed-ips', '10.80.0.2/32',
               'endpoint', '10.78.0.2:51821')
            topology.authorize(3000)
            check('wrong inner peer cannot reach resource', not probe())
            # Even an injected fallback route must be rejected by endpoint egress policy.
            ns('e', 'ip', 'route', 'replace', '10.80.0.2/32', 'via', '192.0.2.2', 'dev', 'pub')
            topology.authorize(3000)
            check('injected public fallback route blocked', not probe())
            print('PASS all native data-plane gates (synthetic policy; see Java policy tests).')
            return 0
        finally:
            for child in reversed(children):
                stop(child)
            topology.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        # No subprocess output or key material is included.
        import traceback
        traceback.print_exc()
        print('FAIL native data-plane gate: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
