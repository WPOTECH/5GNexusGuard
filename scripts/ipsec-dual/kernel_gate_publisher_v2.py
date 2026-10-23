"""Explicit isolated-only gate publisher. Never imported by native.py.

Run in a disposable network namespace with exclusive ownership of the pinned maps.
There is no production admission switch here. Any exception leaves nft deny interlock.
"""
import argparse
import hashlib
import json
import os
import secrets
from pathlib import Path
import re
import socket
import struct
import subprocess
import time

AUTH = struct.Struct('<QQIIHH4x')
HEALTH = struct.Struct('<QQQIIHH4x')
PEER, RESOURCE, PORT = socket.htonl(0x0a4f0001), socket.htonl(0x0a500002), 8080
KEY = ['00', '00', '00', '00']
HERE = Path(__file__).resolve().parent


def _loadall_diagnostic(stderr, stdout='', *, bounded=False, exit_code=None,
                        stats=None):
    """Allowlisted loader evidence; never copy raw output, paths or exception text."""
    def sample(value):
        raw = value if isinstance(value, bytes) else (value or '').encode('utf-8', 'replace')
        return len(raw), len(raw) > 8192, (raw[:4096] + (b'\n' + raw[-4096:] if len(raw) > 8192 else raw[4096:])).decode('utf-8', 'replace')
    err_size, err_cut, err_text = sample(stderr)
    out_size, out_cut, out_text = sample(stdout)
    if bounded:  # The probe has already capped each stream independently.
        err_text = stderr.decode('utf-8', 'replace') if isinstance(stderr, bytes) else (stderr or '')
        out_text = stdout.decode('utf-8', 'replace') if isinstance(stdout, bytes) else (stdout or '')
    text = err_text + '\n' + out_text
    failure_pattern = r'\b(?:failed to pin|pinning failed|failed to load|load failed|failed to create map|map creation failed)\b'
    stderr_failures = [line for line in err_text.splitlines() if re.search(failure_pattern, line, re.I)]
    stdout_failures = [line for line in out_text.splitlines() if re.search(failure_pattern, line, re.I)]
    # Streams have no shared chronology. Prefer bpftool/libbpf stderr over a
    # generic stdout summary; only use stdout when stderr has no failure line.
    specific_pattern = (r"libbpf: (?:prog|map) '[a-z_]{1,32}'.*\b(?:failed to pin|pinning failed|failed to load|failed to create map)\b"
                        r"|\b(?:failed to pin|pinning failed) (?:map '[a-z_]{1,32}'|program\b|prog\b)")
    specific_stderr = [line for line in stderr_failures if re.search(specific_pattern, line, re.I)]
    specific_stdout = [line for line in stdout_failures if re.search(specific_pattern, line, re.I)]
    selected = (specific_stderr or specific_stdout or stderr_failures or stdout_failures or [''])[-1]
    pin = bool(re.search(r'\b(?:failed to pin|pinning failed)\b', selected, re.I))
    stage = ('map_pinning' if pin and re.search(r'\bmap\b|\bpinmaps\b', selected, re.I)
             else 'program_pinning' if pin and re.search(r'\bprog(?:ram)?\b', selected, re.I)
             else 'installation' if pin else 'program_load' if selected else 'unknown')
    trusted = {'auth_map', 'health_map', 'verdict_map', 'wg_ingress', 'resource_ingress'}
    subject_match = (re.search(r"\b(?:pin|pinning) map '([a-z_]{1,32})'", selected, re.I)
                     if stage == 'map_pinning' else None)
    found = subject_match or re.search(r"libbpf: (?:map|prog) '([a-z_]{1,32})'", selected)
    if stage == 'map_pinning' and not subject_match and "libbpf: prog '" in selected:
        found = None
    subject = found.group(1) if found and found.group(1) in trusted else 'unknown'
    errors = ((r'(?<!\d)-17(?!\d)|\bFile exists\b', 'EEXIST'),
              (r'(?<!\d)-2(?!\d)|\bNo such file or directory\b', 'ENOENT'),
              (r'(?<!\d)-22(?!\d)|\bInvalid argument\b', 'EINVAL'),
              (r'(?<!\d)-1(?!\d)|\bOperation not permitted\b|\bEPERM\b', 'EPERM'),
              (r'(?<!\d)-13(?!\d)|\bPermission denied\b|\bEACCES\b', 'EACCES'),
              (r'(?<!\d)-95(?!\d)|\bOperation not supported\b', 'EOPNOTSUPP'))
    errno = next((name for pattern, name in errors if re.search(pattern, selected, re.I)), 'unknown')
    reason = next((name for pattern, name in (
        (r'\binvalid mem access\b', 'invalid_mem_access'),
        (r'\binvalid bpf_context access\b', 'invalid_context_access'),
        (r'\bunbounded loop\b', 'unbounded_loop'),
        (r'\binvalid indirect read\b', 'invalid_indirect_read'),
        (r'\bverifier rejected\b|\bverification failed\b', 'verifier_rejected'))
        if re.search(pattern, text, re.I)), 'unknown')
    permission = (next((name for pattern, name in errors if name in ('EPERM', 'EACCES')
                        and re.search(pattern, text, re.I)), 'unknown'))
    map_evidence = (['pinning_failed'] if re.search(r'\bfailed to pin\b|\bpinning failed\b', text, re.I) else [])
    if re.search(r'\bmap ABI\b|\bincompatible map definition\b', text, re.I):
        map_evidence.append('map_abi_mismatch')
    if pin:
        category = {'map_pinning':'map_pin_failure', 'program_pinning':'program_pin_failure',
                    'installation':'installation_failure'}[stage]
    elif reason != 'unknown' and permission != 'unknown':
        category = 'ambiguous'
    elif 'map_abi_mismatch' in map_evidence and permission != 'unknown':
        category = 'ambiguous'
    elif reason != 'unknown':
        category = 'verifier_rejected'
    elif permission != 'unknown':
        category = 'permission_denied'
    elif map_evidence:
        category = 'map_abi_mismatch'
    elif stage == 'program_load':
        category = 'program_load_failed'
    else:
        category = 'unknown'
    report = dict(failing_executable='bpftool', failing_operation='prog loadall',
                  exit_code=exit_code, category=category, stage=('verifier' if category == 'verifier_rejected' else stage),
                  subject=subject, errno=errno, explicit_verifier_evidence=reason,
                  permission_error_evidence=permission, map_pinning_evidence=map_evidence,
                  ambiguous_or_unknown=category in ('ambiguous', 'unknown'),
                  stdout_bytes=out_size, stderr_bytes=err_size,
                  stdout_truncated=out_cut, stderr_truncated=err_cut,
                  diagnostic_tokens=([reason] if reason != 'unknown' else []) +
                                    ([permission] if permission != 'unknown' else []) + map_evidence)
    if stats:
        report.update({key: stats[key] for key in ('stdout_bytes', 'stderr_bytes',
                      'stdout_truncated', 'stderr_truncated') if key in stats})
    return report


def _loadall_failure(stderr, *, bounded=False):
    data = _loadall_diagnostic(stderr, bounded=bounded)
    return _format_loadall(data)


def _format_loadall(data):
    return (f"Kernel gate command failed: {data['category']}; stage={data['stage']}; "
            f"subject={data['subject']}; errno={data['errno']}; "
            f"reason={data['explicit_verifier_evidence']}")


def command(args, *, input=None):
    loadall = any(args[i:i+3] == ['bpftool', 'prog', 'loadall']
                  for i in range(len(args)-2))
    try:
        result = subprocess.run(args, input=input, text=True, capture_output=True,
                                check=True, timeout=2)
    except (subprocess.TimeoutExpired, OSError) as error:
        if loadall:
            stage = 'timeout' if isinstance(error, subprocess.TimeoutExpired) else 'launch'
            data = _loadall_diagnostic(error.stderr if stage == 'timeout' else '',
                error.stdout if stage == 'timeout' else '', exit_code=None)
            data.update(stage=stage, category='kernel_command_failed', subject='unknown',
                        errno='unknown', ambiguous_or_unknown=True)
            failure = RuntimeError(_format_loadall(data))
            failure.diagnostic = data
            raise failure from None
        raise
    except subprocess.CalledProcessError as error:
        if 'bpftool' in args or 'tc' in args:
            if loadall:
                data = _loadall_diagnostic(error.stderr, error.stdout,
                                           exit_code=error.returncode)
                failure = RuntimeError(_format_loadall(data))
                failure.diagnostic = data
                raise failure from None
            stderr = (error.stderr or '')[:4096]
            category = ('verifier_rejected' if re.search(r'verifier|map ABI', stderr, re.I)
                        else 'permission_denied' if re.search(r'permission denied|operation not permitted', stderr, re.I)
                        else 'kernel_command_failed')
            raise RuntimeError('Kernel gate command failed: ' + category) from None
        raise RuntimeError('isolated command failed') from None
    return result.stdout


class Publisher:
    def __init__(self, controller, run, pin_dir, wg_iface, resource_iface, *, now=None,
                 health=None, object_path=None):
        self.controller, self.run = controller, run
        self.pin_dir = Path(pin_dir)
        if (not self.pin_dir.is_absolute() or str(self.pin_dir).rstrip('/') == '/' or
                not str(self.pin_dir).startswith('/sys/fs/bpf/') or
                not all(re.fullmatch(r'[A-Za-z0-9_-]{1,15}', x)
                        for x in (wg_iface, resource_iface)) or wg_iface == resource_iface):
            raise ValueError('isolated bpffs path and distinct literal interface names required')
        self.wg, self.resource = wg_iface, resource_iface
        self.auth_path = str(self.pin_dir/'maps'/'auth_map')
        self.health_path = str(self.pin_dir/'maps'/'health_map')
        self.now = now or (lambda: time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        self.health_check = health or (lambda: False)
        self.object_path = Path(object_path) if object_path else HERE/'kernel_gate_v2.bpf.o'
        self.installed = False
        self.used_epochs = set()
        self.current = None
        self.revocation_uncertain = False

    def _update(self, path, value):
        self.run(['bpftool', 'map', 'update', 'pinned', path, 'key', 'hex', *KEY,
                  'value', 'hex', *(f'{b:02x}' for b in value)])
        observed = json.loads(self.run(['bpftool', '-j', 'map', 'lookup', 'pinned',
                                        path, 'key', 'hex', *KEY]))['value']
        if not isinstance(observed, list) or len(observed) != len(value):
            raise RuntimeError('BPF map readback length mismatch')
        decoded = bytes(int(item, 16) if isinstance(item, str) and
                        re.fullmatch(r'0x[0-9a-fA-F]{2}', item) else item
                        if type(item) is int and 0 <= item < 256 else -1
                        for item in observed)
        if decoded != value:
            raise RuntimeError('BPF map readback mismatch')

    def revoke(self):
        # Revoke health first. A failed write may leave a live old value;
        # only its independently checked kernel deadline then bounds access.
        self.current = None
        self.revocation_uncertain = True
        errors = 0
        for path, size in ((self.health_path, HEALTH.size), (self.auth_path, AUTH.size)):
            try: self._update(path, bytes(size))
            except Exception: errors += 1
        if errors:
            raise RuntimeError('map zero/readback failed; revocation uncertain until kernel deadline') from None
        self.revocation_uncertain = False

    def install(self):
        # No allow rules before the independent fail-closed nft chain is installed.
        # The two pre-existing interface names are deliberately fixed to this namespace.
        rules = f'''table inet kernel_gate_v2_test {{
 chain forward {{ type filter hook forward priority 10; policy drop;
  iifname "{self.wg}" oifname "{self.resource}" ip saddr 10.79.0.1 ip daddr 10.80.0.2 tcp dport 8080 meta mark 0x5a17c0de counter accept
  iifname "{self.resource}" oifname "{self.wg}" ip saddr 10.80.0.2 ip daddr 10.79.0.1 tcp sport 8080 meta mark 0x5a17c0de ct state established counter accept
  counter drop
 }}
}}'''
        self.run(['nft', '-f', '-'], input=rules)
        original = json.loads(self.run(['nft', '-j', 'list', 'chain', 'inet',
                                        'ipsec_dual', 'forward']))
        if not any(item.get('chain', {}).get('policy') == 'drop' and
                   item['chain'].get('hook') == 'forward' and
                   item['chain'].get('table') == 'ipsec_dual'
                   for item in original['nftables']):
            raise RuntimeError('native forward chain is not deny-by-default')
        # Test-only atomic forward-chain substitution: the old synthetic
        # @authorized/absolute_lease wall-clock path must not confound evidence.
        # Existing input/output chains, tunnel policy, and default drop remain.
        override = f'''flush chain inet ipsec_dual forward
add rule inet ipsec_dual forward iifname "transit" ip saddr 10.77.0.1 udp sport 51821 udp dport 51821 accept
add rule inet ipsec_dual forward oifname "transit" ip daddr 10.77.0.1 udp sport 51821 udp dport 51821 accept
add rule inet ipsec_dual forward iifname "{self.wg}" oifname "{self.resource}" ip saddr 10.79.0.1 ip daddr 10.80.0.2 tcp dport 8080 meta mark 0x5a17c0de counter accept
add rule inet ipsec_dual forward iifname "{self.resource}" oifname "{self.wg}" ip saddr 10.80.0.2 ip daddr 10.79.0.1 tcp sport 8080 ct state established meta mark 0x5a17c0de counter accept
add rule inet ipsec_dual forward counter drop
'''
        self.run(['nft', '-f', '-'], input=override)
        # Local-only echo exception: never touches forward or the resource host.
        self.run(['nft', '-f', '-'], input=f'''add rule inet ipsec_dual input iifname "{self.wg}" ip saddr 10.79.0.1 ip daddr 10.79.0.2 ip protocol icmp icmp type echo-request accept
add rule inet ipsec_dual output oifname "{self.wg}" ip saddr 10.79.0.2 ip daddr 10.79.0.1 ip protocol icmp icmp type echo-reply accept
''')
        # Refuse reusing existing pins: no way to inherit a stale live authorization.
        self.run(['bpftool', 'prog', 'loadall', str(self.object_path),
                  str(self.pin_dir/'progs'), 'type', 'classifier',
                  'pinmaps', str(self.pin_dir/'maps')])
        self.revoke()
        try:
            for iface, name in ((self.wg, 'wg_ingress'),
                                (self.resource, 'resource_ingress')):
                self.run(['tc', 'qdisc', 'replace', 'dev', iface, 'clsact'])
                self.run(['tc', 'filter', 'replace', 'dev', iface, 'ingress',
                          'pref', '49152', 'handle', '1', 'bpf', 'da', 'pinned',
                          str(self.pin_dir/'progs'/name)])
        except Exception:
            self.revoke()
            raise
        self.installed = True

    def tick(self):
        if not self.installed:
            raise RuntimeError('interlock and both TC hooks must install first')
        if self.revocation_uncertain:
            raise RuntimeError('revocation uncertain; no publication until fresh authority')
        try:
            c = self.controller
            status = c.step()
            now = self.now()  # Never pass a pre-step timestamp to rollback-sensitive state().
            if (status != 'ATTESTED' or c.admission.state(now) != 'AUTHORIZED' or
                    c.scope['bootId'] != _boot_id() or not c.approval_nonce or
                    not c.session or not all(isinstance(x, int) for x in c.floors) or
                    not now < c.until_ns <= c.admission.deadline or
                    not 0 < c.admission.deadline - now <= 3_000_000_000 or
                    int(time.time()*1000) >= c.until_ms or not self.health_check()):
                self.revoke()
                return False
            epoch_text = json.dumps([c.scope['bootId'], c.session, c.approval_nonce,
                                     c.admission.generation, c.floors], separators=(',', ':'))
            epoch = int.from_bytes(hashlib.sha256(epoch_text.encode()).digest()[:8], 'little') or 1
            if self.current != epoch:
                self.revoke()
                if epoch in self.used_epochs:
                    return False
                self.used_epochs.add(epoch)
                self._update(self.auth_path, AUTH.pack(epoch, c.admission.deadline,
                                                       PEER, RESOURCE, PORT, 0))
                self.current = epoch
            # Always bound heartbeat against original signed deadline and fresh health.
            checked = self.now()
            if checked >= c.admission.deadline or checked >= c.until_ns:
                self.revoke()
                return False
            self._update(self.health_path, HEALTH.pack(epoch,
                min(checked + 500_000_000, c.admission.deadline, c.until_ns),
                checked, PEER, RESOURCE, PORT, 0))
            return True
        except Exception:
            self.revoke()
            raise


def _boot_id():
    from native_control_v2 import boot_id
    return boot_id()


class FreshHealth:
    """One independent echo per tick, bracketed by live VICI and ESP progress."""
    def __init__(self, pids, wg_iface, resource_iface, endpoint_ns,
                 gateway_ns, inner_ns, run=command, *, vici_dir):
        self.pids = {pid: self._start(pid) for pid in pids}
        if len(self.pids) != 2: raise ValueError('exactly two daemon identities required')
        if not all(re.fullmatch(r'[A-Za-z0-9_-]{1,64}', name) for name in
                   (endpoint_ns, gateway_ns, inner_ns)):
            raise ValueError('invalid network namespace')
        if not Path(vici_dir).is_absolute(): raise ValueError('absolute private VICI directory required')
        self.vici_dir = Path(vici_dir)
        self.endpoint_ns, self.gateway_ns, self.inner_ns = endpoint_ns, gateway_ns, inner_ns
        self.wg, self.resource, self.run = wg_iface, resource_iface, run

    @staticmethod
    def _start(pid):
        if type(pid) is not int or pid <= 1: raise ValueError('invalid pid')
        text = Path(f'/proc/{pid}/stat').read_text()
        return int(text[text.rfind(')')+2:].split()[19])

    def _namespace(self, pid, namespace):
        return (os.stat(f'/proc/{pid}/ns/net').st_ino ==
                os.stat(f'/run/netns/{namespace}').st_ino)

    def _identities(self):
        return (all(self._start(pid) == start for pid, start in self.pids.items()) and
                all(self._namespace(pid, namespace) for pid, namespace in
                    zip(self.pids, (self.endpoint_ns, self.gateway_ns))))

    def prepare(self):
        """Test-only WG peer route; retain resource allowed-ips, never edit native.py."""
        prefix = ['ip','netns','exec',self.endpoint_ns]
        peers = self.run([*prefix,'wg','show',self.wg,'peers']).splitlines()
        if len(peers) != 1 or not re.fullmatch(r'[A-Za-z0-9+/]{43}=', peers[0]):
            raise RuntimeError('exactly one inner WG peer required')
        self.run([*prefix,'wg','set',self.wg,'peer',peers[0],
                  'allowed-ips','10.80.0.2/32,10.79.0.2/32'])
        self.run([*prefix,'ip','route','replace','10.79.0.2/32',
                  'dev',self.wg,'src','10.79.0.1'])
        # The endpoint output chain ends with an explicit unconditional drop;
        # append would leave both narrowly scoped local probe rules unreachable.
        self.run([*prefix,'nft','-f','-'], input=f'''insert rule inet ipsec_dual output oifname "{self.wg}" ip saddr 10.79.0.1 ip daddr 10.79.0.2 ip protocol icmp icmp type echo-request accept
insert rule inet ipsec_dual input iifname "{self.wg}" ip saddr 10.79.0.2 ip daddr 10.79.0.1 ip protocol icmp icmp type echo-reply accept
''')

    def _snapshot(self):
        if not self._identities(): return None
        for ns, dst, source in ((self.endpoint_ns,'10.79.0.2','10.79.0.1'),
                                 (self.inner_ns,'10.79.0.1','10.79.0.2')):
            route = json.loads(self.run(['ip','netns','exec',ns,'ip','-j','route','get',
                                         dst,'from',source]))
            if len(route) != 1 or route[0].get('dev') != self.wg or \
                    route[0].get('src', source) != source:
                return None
            addresses = json.loads(self.run(['ip','netns','exec',ns,'ip','-j',
                                             'addr','show','dev',self.wg]))
            if len(addresses) != 1 or addresses[0].get('ifname') != self.wg or \
                    not any(info.get('family') == 'inet' and info.get('local') == source
                            for info in addresses[0].get('addr_info', [])):
                return None
        counts = []
        sa_ids = []
        for namespace, role, pair, local, remote in (
            (self.endpoint_ns, 'e', ('192.0.2.1','192.0.2.2'),
             '10.77.0.1/32[17/51821]', '10.78.0.2/32[17/51821]'),
            (self.gateway_ns, 'o', ('192.0.2.2','192.0.2.1'),
             '10.78.0.2/32[17/51821]', '10.77.0.1/32[17/51821]')):
            status = self.run(['ip','netns','exec',namespace,'swanctl','--list-sas',
                '--uri','unix://' + str(self.vici_dir/role/'vici')])
            found = re.findall(r'(?m)^hybrid: #\d+, ESTABLISHED, IKEv2, '
                r'([0-9a-f]{16})_i\*? ([0-9a-f]{16})_r\*?', status)
            if len(found) != 1 or not re.search(r'(?m)^\s*inner-transport: #\d+, '
                    r'reqid 42, INSTALLED, TUNNEL, ESP:',status) or \
                    'local  '+local not in status or 'remote '+remote not in status:
                return None
            sa_ids.append(found[0])
            raw = self.run(['ip','netns','exec',namespace,'ip','-s','xfrm','state'])
            # This lab's iproute2 prints text even with -j. Bind the counter to
            # the outer ESP SA, not the inner traffic selectors shown by VICI.
            records = re.split(r'(?=^src )', raw, flags=re.M)
            selected = [record for record in records if
                record.startswith('src ' + pair[0] + ' dst ' + pair[1] + '\n') and
                re.search(r'(?m)^\s+proto esp spi 0x[0-9a-f]+\(\d+\) reqid 42\(0x0000002a\) mode tunnel\s*$', record)]
            if len(selected) != 1: return None
            current = re.findall(r'(?m)^\s+lifetime current:\s*\n\s*(\d+)\(bytes\), \d+\(packets\)\s*$', selected[0])
            if len(current) != 1: return None
            counts.append(int(current[0]))
        return (tuple(sa_ids), tuple(counts)) if sa_ids[0] == sa_ids[1] else None

    def __call__(self):
        try:
            return self._challenge()
        except (OSError, RuntimeError, ValueError, KeyError, json.JSONDecodeError):
            return False

    def _challenge(self):
        before = self._snapshot()
        if before is None: return False
        # ping's per-process random echo identifier/sequence and pattern bind a
        # new response to this invocation. A successful exit alone is insufficient.
        nonce = secrets.token_hex(16)
        result = self.run(['ip','netns','exec',self.endpoint_ns,'ping','-n','-c','1',
                           '-W','1','-I','10.79.0.1','-s','32','-p',nonce,'10.79.0.2'])
        after = self._snapshot()
        return (after is not None and before[0] == after[0] and
                re.search(r'(?m)^\d+ bytes from 10\.79\.0\.2: icmp_seq=1\b', result) is not None and
                'wrong data byte' not in result and
                '1 received' in result and '1 packets transmitted' in result and
                all(new > old for old,new in zip(before[1],after[1])))


def main():
    parser = argparse.ArgumentParser(description='isolated gate only; never production native.py')
    parser.add_argument('--pin-dir', required=True)
    parser.add_argument('--wg-iface', required=True)
    parser.add_argument('--resource-iface', required=True)
    parser.add_argument('--pid', action='append', required=True, type=int)
    parser.add_argument('--inner-netns', required=True)
    parser.add_argument('--endpoint-netns', required=True)
    parser.add_argument('--gateway-netns', required=True)
    parser.add_argument('--vici-dir', required=True, type=Path,
                        help='private topology state directory containing endpoint/gateway VICI sockets')
    parser.add_argument('--object', required=True, type=Path)
    parser.add_argument('--controller-factory', required=True,
                        help='module:function creating configured native_control_v2.Controller')
    args = parser.parse_args()
    import importlib
    module, sep, function = args.controller_factory.partition(':')
    if not sep or not module or not function: parser.error('module:function required')
    controller = getattr(importlib.import_module(module), function)()
    if not isinstance(controller, __import__('native_control_v2').Controller):
        parser.error('factory must return native_control_v2.Controller')
    health = FreshHealth(args.pid, args.wg_iface, args.resource_iface,
                         args.endpoint_netns, args.gateway_netns, args.inner_netns,
                         vici_dir=args.vici_dir)
    if not args.object.is_file(): parser.error('compiled BPF object required')
    def inner_command(argv, *, input=None):
        return command(['ip', 'netns', 'exec', args.inner_netns, *argv], input=input)
    path = Path(args.pin_dir)
    path.mkdir(parents=True, exist_ok=False)
    (path/'maps').mkdir()
    (path/'progs').mkdir()
    publisher = Publisher(controller, inner_command, path, args.wg_iface,
                          args.resource_iface, health=health, object_path=args.object)
    try:
        publisher.install()
        health.prepare()
        while True:
            publisher.tick()
            time.sleep(0.1)
    finally:
        publisher.revoke()


if __name__ == '__main__': main()
