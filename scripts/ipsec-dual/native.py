#!/usr/bin/env python3
"""Bounded IKEv2/ESP + WireGuard deployment. No shell execution or key logging."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

NAMES = {r: 'dlip-' + r for r in 'eoir'}


def command(*args, data=None):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=10)
    if result.returncode:
        # Do not dump arguments/output: future commands may contain sensitive data.
        detail = ('; '.join(line for line in result.stderr.splitlines()
                            if not line.startswith("plugin '") )[-1000:]
                  if 'wg' in args or 'swanctl' in args else '')
        if 'swanctl' in args:
            detail += '; ' + result.stdout[-1000:].replace('\n', '; ')
        raise RuntimeError('native command failed: ' + args[0] + ' (exit '
                           + str(result.returncode) + '; ' + detail + ')')
    return result.stdout.strip()


def ns(role, *args, data=None):
    return command('ip', 'netns', 'exec', NAMES[role], *args, data=data)


def ns_sysctl(role, forwarding):
    # Docker bind-mounts /proc/sys read-only. Only this command's private mount
    # namespace gets a fresh procfs; writes remain scoped to the named netns.
    setting = '1' if forwarding else '0'
    ns(role, 'unshare', '-m', 'sh', '-c',
       'mount -t proc proc /proc && sysctl -qw net.ipv4.ip_forward=' + setting
       + ' net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0')


def remaining_ms(lease, service, client, owner, now_ms):
    """Fail closed on malformed, mismatched, denied, expired or far-future leases."""
    if not isinstance(lease, dict):
        return 0
    if (type(lease.get('version')) is not int or lease['version'] != 2
            or lease.get('transport') != 'IKEV2_ESP_WIREGUARD'
            or lease.get('allowed') is not True
            or lease.get('serviceId') != service or lease.get('clientNodeId') != client
            or lease.get('ownerNodeId') != owner or type(lease.get('expiresAtMs')) is not int):
        return 0
    delta = lease['expiresAtMs'] - now_ms
    return delta if 0 < delta <= 3000 else 0


def read_lease(path, uid):
    # Directory must belong to the configured ledger process UID, with no other access.
    parent = path.parent
    info = parent.stat()
    if parent.resolve() != parent or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('untrusted lease directory')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError('untrusted lease file')
        return json.loads(stream.read(4097)) if info.st_size <= 4096 else None


def firewall(role, inputs='', outputs='', forwards='', extra=''):
    ns(role, 'nft', '-f', '-', data=f'''table inet ipsec_dual {{
 {extra}
 chain input {{ type filter hook input priority 0; policy drop;
 iifname "lo" accept
 {inputs}
 }}
 chain output {{ type filter hook output priority 0; policy drop;
 oifname "lo" accept
 {outputs}
 }}
 chain forward {{ type filter hook forward priority 0; policy drop;
 {forwards}
 }}
}}''')


class Topology:
    def __init__(self, state, credentials=None):
        self.state = state
        self.credentials = credentials
        self.created = []
        self.keys = []
        self.daemons = []

    def link(self, left, right, name, a, b):
        # Create inside a namespace, never attach interfaces to host network.
        ns(left, 'ip', 'link', 'add', name, 'type', 'veth', 'peer', 'name', name + 'p')
        ns(left, 'ip', 'link', 'set', name + 'p', 'netns', NAMES[right])
        ns(right, 'ip', 'link', 'set', name + 'p', 'name', name)
        for role, address in ((left, a), (right, b)):
            ns(role, 'ip', 'addr', 'add', address, 'dev', name)
            ns(role, 'ip', 'link', 'set', name, 'up')

    def wg(self, role, name, address, port, key, peer, allowed, endpoint=None):
        ns(role, 'ip', 'link', 'add', name, 'type', 'wireguard')
        args = ['wg', 'set', name, 'private-key', '/dev/stdin', 'listen-port', str(port),
                'peer', peer, 'allowed-ips', allowed]
        if endpoint:
            args += ['endpoint', endpoint, 'persistent-keepalive', '1']
        ns(role, *args, data=key.read_text())
        ns(role, 'ip', 'addr', 'add', address + '/32', 'dev', name)
        ns(role, 'ip', 'link', 'set', name, 'mtu', '1280')

    def route(self, role, destination, *via):
        ns(role, 'ip', 'route', 'add', destination, *via)

    def create(self):
        require_container()
        if Path('/run') == self.state or Path('/run') in self.state.parents:
            raise ValueError('state must be outside the daemon private /run')
        existing = command('ip', 'netns', 'list').splitlines()
        if any(line.split()[0] in NAMES.values() for line in existing if line.strip()):
            raise RuntimeError('native namespaces already exist; refusing to adopt/delete them')
        for role in NAMES:
            command('ip', 'netns', 'add', NAMES[role])
            self.created.append(role)
            ns(role, 'ip', 'link', 'set', 'lo', 'up')
            ns_sysctl(role, False)
        # Firewalls installed before any network connectivity or WireGuard devices.
        firewall('e',
            'iifname "pub" ip saddr 192.0.2.2 ip protocol esp counter accept\n'
            'iifname "pub" ip saddr 192.0.2.2 udp sport { 500, 4500 } udp dport { 500, 4500 } accept\n'
            'ipsec in reqid 42 ip saddr 10.78.0.2 udp sport 51821 udp dport 51821 accept\n'
            'iifname "wg-inner" ip saddr 10.80.0.2 tcp sport 8080 ct state established accept',
            'oifname "pub" ip daddr 192.0.2.2 ip protocol esp counter accept\n'
            'oifname "pub" ip daddr 192.0.2.2 udp sport { 500, 4500 } udp dport { 500, 4500 } accept\n'
            'ipsec out reqid 42 ip daddr 10.78.0.2 udp sport 51821 udp dport 51821 counter accept\n'
            'oifname "wg-inner" ip daddr 10.80.0.2 tcp dport 8080 accept\n'
            'counter drop')
        firewall('o',
            'iifname "pub" ip saddr 192.0.2.1 ip protocol esp counter accept\n'
            'iifname "pub" ip saddr 192.0.2.1 udp sport { 500, 4500 } udp dport { 500, 4500 } accept',
            'oifname "pub" ip daddr 192.0.2.1 ip protocol esp counter accept\n'
            'oifname "pub" ip daddr 192.0.2.1 udp sport { 500, 4500 } udp dport { 500, 4500 } accept',
            'ipsec in reqid 42 oifname "transit" ip saddr 10.77.0.1 ip daddr 10.78.0.2 udp sport 51821 udp dport 51821 counter accept\n'
            'iifname "transit" ipsec out reqid 42 ip saddr 10.78.0.2 ip daddr 10.77.0.1 udp sport 51821 udp dport 51821 counter accept\n'
            'counter drop')
        firewall('i',
            'iifname "transit" ip saddr 10.77.0.1 udp sport 51821 udp dport 51821 accept',
            'oifname "transit" ip daddr 10.77.0.1 udp sport 51821 udp dport 51821 accept',
            'iifname "wg-inner" oifname "resource" ip saddr @authorized ip daddr 10.80.0.2 tcp dport 8080 accept\n'
            'iifname "resource" oifname "wg-inner" ip saddr 10.80.0.2 ip daddr @authorized tcp sport 8080 ct state established accept',
            'set authorized { type ipv4_addr; flags timeout; timeout 3s; }')
        firewall('r',
            'iifname "resource" ip saddr 10.79.0.1 ip daddr 10.80.0.2 tcp dport 8080 accept',
            'oifname "resource" ip saddr 10.80.0.2 ip daddr 10.79.0.1 tcp sport 8080 ct state established accept')
        self.link('e', 'o', 'pub', '192.0.2.1/30', '192.0.2.2/30')
        self.link('o', 'i', 'transit', '10.78.0.1/30', '10.78.0.2/30')
        self.link('i', 'r', 'resource', '10.80.0.1/30', '10.80.0.2/30')
        pubs = {}
        paths = {}
        for label in ('e-inner', 'i-inner'):
            path = self.state / (label + '.key')
            key = command('wg', 'genkey')
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            self.keys.append(path)
            with os.fdopen(fd, 'w') as stream:
                stream.write(key + '\n')
            pubs[label] = command('wg', 'pubkey', data=key + '\n')
            paths[label] = path
        if len(set(pubs.values())) != 2:
            raise RuntimeError('independent key generation failed')
        ns('e', 'ip', 'addr', 'add', '10.77.0.1/32', 'dev', 'lo')
        self.route('e', '10.78.0.2/32', 'via', '192.0.2.2', 'src', '10.77.0.1')
        self.route('o', '10.77.0.1/32', 'via', '192.0.2.1')
        self.route('i', '10.77.0.1/32', 'via', '10.78.0.1')
        self.wg('e', 'wg-inner', '10.79.0.1', 51821, paths['e-inner'], pubs['i-inner'],
                '10.80.0.2/32', '10.78.0.2:51821')
        self.wg('i', 'wg-inner', '10.79.0.2', 51821, paths['i-inner'], pubs['e-inner'],
                '10.79.0.1/32', '10.77.0.1:51821')
        self.route('r', '10.79.0.1/32', 'via', '10.80.0.1')
        for role in 'oi':
            ns_sysctl(role, True)

        self.start_ipsec()
        # Do not launch a WireGuard handshake until the mandatory CHILD_SA exists.
        ns('i', 'ip', 'link', 'set', 'wg-inner', 'up')
        ns('e', 'ip', 'link', 'set', 'wg-inner', 'up')
        self.route('e', '10.80.0.2/32', 'dev', 'wg-inner', 'src', '10.79.0.1')
        self.route('i', '10.79.0.1/32', 'dev', 'wg-inner')

    def reconcile_routes(self):
        # Administrative link-down removes manually installed host routes. Restore
        # only the exact owned routes; firewall/XFRM policy remains fail-closed.
        routes = (
            ('e', '10.78.0.2/32', ('via', '192.0.2.2', 'src', '10.77.0.1')),
            ('o', '10.77.0.1/32', ('via', '192.0.2.1')),
            ('i', '10.77.0.1/32', ('via', '10.78.0.1')),
            ('e', '10.80.0.2/32', ('dev', 'wg-inner', 'src', '10.79.0.1')),
            ('i', '10.79.0.1/32', ('dev', 'wg-inner')),
        )
        ready = True
        for role, destination, via in routes:
            try:
                if not ns(role, 'ip', 'route', 'show', destination):
                    ns(role, 'ip', 'route', 'replace', destination, *via)
            except RuntimeError:
                ready = False
        return ready

    def ipsec_ready(self):
        try:
            status = self.swan('e', '--list-sas')
            return ('hybrid: #' in status and 'ESTABLISHED, IKEv2' in status
                    and 'inner-transport: #' in status
                    and 'reqid 42, INSTALLED, TUNNEL, ESP:' in status
                    and 'local  10.77.0.1/32[17/51821]' in status
                    and 'remote 10.78.0.2/32[17/51821]' in status)
        except RuntimeError:
            return False

    def swan(self, role, *args):
        return ns(role, 'swanctl', *args, '--uri', 'unix://' + str(self.state / role / 'vici'))

    def start_ipsec(self):
        from config import provision_lab, provision_operator
        if self.credentials is None:
            provision_lab(self.state)  # Only the integration harness selects this branch.
        else:
            provision_operator(self.state, self.credentials)
        for role in ('o', 'e'):
            directory = self.state / role
            log = open(directory / 'charon.log', 'w')
            child = subprocess.Popen(['ip', 'netns', 'exec', NAMES[role],
                'env', 'STRONGSWAN_CONF=' + str(directory / 'strongswan.conf'),
                'unshare', '-m', '--propagation', 'private', 'sh', '-c',
                'mount -t tmpfs tmpfs /run && exec /usr/lib/ipsec/charon'], stdout=log, stderr=log)
            log.close()
            self.daemons.append(child)
            for _ in range(50):
                if (directory / 'vici').exists():
                    break
                if child.poll() is not None:
                    raise RuntimeError('charon exited; inspect private runtime log')
                time.sleep(0.1)
            self.swan(role, '--load-all', '--file', str(directory / 'swanctl.conf'))
        self.swan('e', '--initiate', '--child', 'inner-transport', '--timeout', '8')

    def authorize(self, milliseconds):
        # One atomic nft transaction, no established-flow exception around this set.
        rule = 'flush set inet ipsec_dual authorized\n'
        if milliseconds > 0:
            rule += ('add element inet ipsec_dual authorized { 10.79.0.1 timeout '
                     + str(min(milliseconds, 3000)) + 'ms }\n')
        ns('i', 'nft', '-f', '-', data=rule)

    def close(self):
        failed = False
        for child in reversed(self.daemons):
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
        for role in reversed(self.created):
            try:
                # Only processes in namespaces created by this instance.
                for pid in command('ip', 'netns', 'pids', NAMES[role]).split():
                    try:
                        os.kill(int(pid), signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                time.sleep(0.1)
                for pid in command('ip', 'netns', 'pids', NAMES[role]).split():
                    try:
                        os.kill(int(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                command('ip', 'netns', 'del', NAMES[role])
            except (RuntimeError, ProcessLookupError):
                failed = True
        for path in self.keys:
            path.unlink(missing_ok=True)
        if failed:
            print('Native cleanup incomplete; inspect dlip-* namespaces.', file=sys.stderr)


def require_container():
    # Safety guard, not an authentication boundary. Never run this harness on host.
    if not Path('/.dockerenv').exists() or os.environ.get('DL_IPSEC_ISOLATED') != '1':
        raise RuntimeError('use the approved isolated Docker launcher')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--credentials', type=Path, required=True,
                        help='absolute protected operator e/o certificate configuration directory')
    parser.add_argument('--service', required=True)
    parser.add_argument('--client', required=True)
    parser.add_argument('--owner', required=True)
    parser.add_argument('--ledger-uid', type=int, required=True)
    parser.add_argument('--lease', type=Path, default=Path('/run/defenderlink-native/lease.json'))
    parser.add_argument('--state', type=Path, default=Path('/tmp/defenderlink-ipsec-network'))
    args = parser.parse_args()
    require_container()
    if os.geteuid() != 0:
        parser.error('root with CAP_NET_ADMIN and CAP_SYS_ADMIN is required')
    if not re.fullmatch('[0-9a-f]{64}', args.client) or not re.fullmatch('[0-9a-f]{64}', args.owner):
        parser.error('client and owner must be pinned Ed25519 node IDs')
    if not args.lease.is_absolute() or not args.state.is_absolute() or not args.credentials.is_absolute():
        parser.error('paths must be absolute')
    os.umask(0o077)
    args.state.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = args.state.stat()
    if args.state.resolve() != args.state or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        parser.error('state must be a root-owned private real directory')
    fd = os.open(args.state / 'lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    topology = Topology(args.state, args.credentials)
    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        topology.create()
        print('Native namespaces ready; access requires a current ledger lease.', flush=True)
        last_retry = 0.0
        while True:
            milliseconds = 0
            try:
                milliseconds = remaining_ms(read_lease(args.lease, args.ledger_uid), args.service,
                                            args.client, args.owner, time.time_ns() // 1_000_000)
            except (OSError, ValueError, TypeError):
                pass
            routes_ready = topology.reconcile_routes()
            sa_ready = topology.ipsec_ready()
            if not (routes_ready and sa_ready):
                milliseconds = 0
            topology.authorize(milliseconds)
            # Retry only the named CHILD_SA; never relax routes, XFRM or ACLs.
            if routes_ready and not sa_ready and time.monotonic() - last_retry >= 5:
                last_retry = time.monotonic()
                try:
                    topology.swan('e', '--initiate', '--child', 'inner-transport', '--timeout', '3')
                except RuntimeError:
                    pass
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        topology.close()
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('Native deployment failed (details suppressed to protect credentials).', file=sys.stderr)
        sys.exit(1)
