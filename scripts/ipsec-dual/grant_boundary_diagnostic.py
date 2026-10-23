"""Read-only, test-only authorization and packet-boundary diagnostic."""
import json
from pathlib import Path
import re
import socket
import struct
import time
import traceback

from continuous_evidence import (CaptureSet, TrafficStream, namespace_capture,
                                 grant_bracket, EvidenceError)
from kernel_gate_publisher_v2 import AUTH, HEALTH, KEY, command
from native import NAMES

BOUNDARIES = (('e', 'wg-inner', 'endpoint-wg'), ('i', 'wg-inner', 'inner-wg'),
              ('i', 'resource', 'inner-resource'), ('r', 'resource', 'resource'),
              ('e', 'pub', 'endpoint-public'), ('o', 'pub', 'outer-public'),
              ('o', 'transit', 'outer-transit'), ('i', 'transit', 'inner-transit'))
VERDICT_REASONS = ('invoked', 'parse_denied', 'scope_denied', 'syn_matched',
                   'auth_missing', 'health_missing', 'epoch_scope_denied',
                   'auth_deadline_denied', 'health_deadline_denied',
                   'syn_passed', 'syn_dropped', 'icmp_passed', 'arp_reply_passed')

def _map_bytes(value, size):
    if not isinstance(value, list) or len(value) != size:
        raise ValueError('verdict map ABI length mismatch')
    if not all(isinstance(n, str) and re.fullmatch(r'0x[0-9a-fA-F]{2}', n)
               or type(n) is int and 0 <= n < 256 for n in value):
        raise ValueError('invalid verdict map bytes')
    return bytes(int(n, 16) if isinstance(n, str) else n for n in value)

def decode_verdicts(rows):
    """Only fixed enum reasons from the 32-entry, little-endian lab map."""
    if not isinstance(rows, list) or len(rows) != 32:
        raise ValueError('verdict map entry count mismatch')
    entries = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('malformed verdict map entry')
        key = int.from_bytes(_map_bytes(row.get('key'), 4), 'little')
        if key >= 32 or key in entries:
            raise ValueError('invalid verdict map key')
        entries[key] = int.from_bytes(_map_bytes(row.get('value'), 8), 'little')
    return {direction: {reason: entries[base + n]
                        for n, reason in enumerate(VERDICT_REASONS)}
            for direction, base in (('wg_ingress', 0), ('resource_ingress', 16))}

def parse_link(rows, expected):
    item = rows[0] if isinstance(rows, list) and len(rows) == 1 and type(rows[0]) is dict else {}
    stats = item.get('stats64', {})
    return {'ifindex': item.get('ifindex') if type(item.get('ifindex')) is int else None,
            'name_matches': item.get('ifname') == expected,
            'rx_packets': stats.get('rx', {}).get('packets') if type(stats.get('rx', {}).get('packets')) is int else None,
            'tx_packets': stats.get('tx', {}).get('packets') if type(stats.get('tx', {}).get('packets')) is int else None}

def parse_forwarding(text):
    return text.strip() == 'net.ipv4.ip_forward = 1'

FORWARD_MATCHES = {('meta', 'iifname'): 'wg-inner',
                   ('meta', 'oifname'): 'resource',
                   ('payload:ip', 'saddr'): '10.79.0.1',
                   ('payload:ip', 'daddr'): '10.80.0.2',
                   ('payload:tcp', 'dport'): 8080,
                   ('meta', 'mark'): 1511506142}
REVERSE_MATCHES = {('meta', 'iifname'): 'resource',
                   ('meta', 'oifname'): 'wg-inner',
                   ('payload:ip', 'saddr'): '10.80.0.2',
                   ('payload:ip', 'daddr'): '10.79.0.1',
                   ('payload:tcp', 'sport'): 8080,
                   ('meta', 'mark'): 1511506142,
                   ('ct', 'state'): 'established'}
TRANSIT_IN = {('meta', 'iifname'): 'transit',
              ('payload:ip', 'saddr'): '10.77.0.1',
              ('payload:udp', 'sport'): 51821,
              ('payload:udp', 'dport'): 51821}
TRANSIT_OUT = {('meta', 'oifname'): 'transit',
               ('payload:ip', 'daddr'): '10.77.0.1',
               ('payload:udp', 'sport'): 51821,
               ('payload:udp', 'dport'): 51821}

def nft_rule_kind(expressions, table):
    """Recognize only the known ordered allowlist and unconditional drop."""
    if not isinstance(expressions, list):
        return 'unknown'
    if (len(expressions) == 2 and
            type(expressions[0]) is dict and set(expressions[0]) == {'counter'} and
            type(expressions[1]) is dict and set(expressions[1]) == {'drop'}):
        return 'drop'
    if (not isinstance(expressions, list) or len(expressions) < 2 or
            type(expressions[-1]) is not dict or 'accept' not in expressions[-1]):
        return 'unknown'
    counted = type(expressions[-2]) is dict and set(expressions[-2]) == {'counter'}
    if set(expressions[-1]) != {'accept'}:
        return 'unknown'
    matches = expressions[:-2] if counted else expressions[:-1]
    observed = {}
    for expr in matches:
        match = expr.get('match') if type(expr) is dict else None
        if type(match) is not dict:
            return 'unknown'
        left = match.get('left')
        if type(left) is not dict:
            return 'unknown'
        if type(left.get('meta')) is dict:
            key = ('meta', left['meta'].get('key'))
        elif type(left.get('payload')) is dict:
            key = ('payload:' + str(left['payload'].get('protocol')),
                   left['payload'].get('field'))
        elif type(left.get('ct')) is dict:
            key = ('ct', left['ct'].get('key'))
        else:
            return 'unknown'
        value = match.get('right')
        # nft serializes the single-state bitmask test as membership, while
        # scalar tuple/mark matches remain equality tests. Accept only this
        # exact observed form; multi-state sets and other membership stay denied.
        if match.get('op') != '==' and not (
                match.get('op') == 'in' and key == ('ct', 'state') and
                value == 'established'):
            return 'unknown'
        if key == ('meta', 'mark') and isinstance(value, str):
            try: value = int(value, 0)
            except ValueError: return 'unknown'
        if key in observed:
            return 'unknown'
        observed[key] = value
    candidates = [('forward', FORWARD_MATCHES, True),
                  ('reverse', REVERSE_MATCHES, True)]
    if table == 'ipsec_dual':
        candidates += [('transit_in', TRANSIT_IN, False),
                       ('transit_out', TRANSIT_OUT, False)]
    return next((name for name, expected, needs_counter in candidates
                 if observed == expected and counted is needs_counter), 'unknown')

def exact_forward_rule(expressions):
    return nft_rule_kind(expressions, 'kernel_gate_v2_test') == 'forward'

def packet_deltas(before, after):
    """Only monotonic values from a worker-free baseline to a stopped worker."""
    result = {'tc': {}, 'nft': {}, 'interfaces': {}}
    for direction in ('wg_ingress', 'resource_ingress'):
        old, new = before['verdicts'][direction], after['verdicts'][direction]
        result['tc'][direction] = {}
        for reason in VERDICT_REASONS:
            if type(old[reason]) is not int or type(new[reason]) is not int or new[reason] < old[reason]:
                raise ValueError('nonmonotonic TC diagnostic count')
            result['tc'][direction][reason] = new[reason] - old[reason]
    for table in ('ipsec_dual', 'kernel_gate_v2_test'):
        if ([row.get('handle') for row in before['nft'][table]] !=
                [row.get('handle') for row in after['nft'][table]]):
            raise ValueError('nft rule order changed across protected traffic window')
        previous = {row['handle']: row for row in before['nft'][table]}
        current = {row['handle']: row for row in after['nft'][table]}
        if None in previous or previous.keys() != current.keys():
            raise ValueError('nft rules changed across protected traffic window')
        result['nft'][table] = []
        for handle, old in previous.items():
            new = current[handle]
            if (old['verdicts'] != new['verdicts'] or
                    old.get('rule_kind') != new.get('rule_kind') or
                    len(old['counter']) != len(new['counter'])):
                raise ValueError('nft verdict changed across traffic window')
            deltas = []
            for a, b in zip(old['counter'], new['counter']):
                if (type(a['packets']) is not int or type(b['packets']) is not int or
                        b['packets'] < a['packets']):
                    raise ValueError('nonmonotonic nft diagnostic count')
                deltas.append(b['packets'] - a['packets'])
            result['nft'][table].append({'handle': handle, 'verdicts': new['verdicts'],
                                         'packet_deltas': deltas})
    for iface in before['interfaces']:
        a, b = before['interfaces'][iface], after['interfaces'][iface]
        if not a['name_matches'] or not b['name_matches'] or a['ifindex'] != b['ifindex']:
            raise ValueError('interface changed across traffic window')
        result['interfaces'][iface] = {}
        for field in ('rx_packets', 'tx_packets'):
            if type(a[field]) is int and type(b[field]) is int and b[field] >= a[field]:
                result['interfaces'][iface][field] = b[field] - a[field]
            else:
                result['interfaces'][iface][field] = None
    return result

SAFE_ERRORS = {'signed operation not committed in denied state',
               'Java issuance/AA attestation did not bind original deadline',
               'gate publisher failed', 'Java issuer exited',
               'Java issuer returned no response',
               'grant assertion: Java issuance/AA acceptance absent',
               'grant assertion: BPF publication not confirmed',
               'grant assertion: supervisor admission absent',
               'grant assertion: valid scoped BPF maps absent',
               'grant assertion: TC classifier attachment absent',
               'grant assertion: independent nft interlock absent',
               'grant assertion: scoped TC verdict evidence absent',
               'grant assertion: scoped nft verdict evidence absent',
               'missing pre-grant denial or post-grant delivery',
               'grant assertion: expected SYN missing from protected resource path',
               'map zero/readback failed; revocation uncertain until kernel deadline',
               'revocation uncertain; no publication until fresh authority',
               'Kernel gate command failed: verifier_rejected',
               'Kernel gate command failed: permission_denied',
               'Kernel gate command failed: kernel_command_failed',
               'isolated command failed', 'diagnostic evidence write failed'}
SAFE_FRAMES = {'grant_boundary_diagnostic.py', 'isolated_enforcement.py',
               'kernel_gate_publisher_v2.py', 'native_control_v2.py',
               'admission_v2.py', 'native_aa_java_harness.py'}

def safe_failure(exc):
    """Only known static errors and code locations; never exception locals/payloads."""
    frames = traceback.extract_tb(exc.__traceback__)
    kind = type(exc).__name__
    message = str(exc)
    # Only values synthesized from fixed loader allowlists may cross evidence boundary.
    loader = re.fullmatch(
        r'Kernel gate command failed: (?:verifier_rejected|kernel_command_failed); '
        r'stage=(?:unknown|map_pinning|program_pinning|installation|verifier|program_load|timeout|launch); '
        r'subject=(?:unknown|auth_map|health_map|verdict_map|wg_ingress|resource_ingress); '
        r'errno=(?:unknown|EEXIST|ENOENT|EINVAL|EPERM|EACCES|EOPNOTSUPP); '
        r'reason=(?:unknown|invalid_mem_access|invalid_context_access|unbounded_loop|invalid_indirect_read)',
        message)
    if message.startswith('grant diagnostic failed: '):
        detail = message.removeprefix('grant diagnostic failed: ')
        message = message if detail in SAFE_ERRORS or detail == 'diagnostic evidence write failed' else 'redacted'
    elif message not in SAFE_ERRORS and not loader:
        message = 'redacted'
    return {'type': kind if kind in ('RuntimeError', 'ValueError', 'EvidenceError',
                                    'TimeoutExpired', 'CalledProcessError') else 'Exception',
            'message': message,
            'traceback': [{'module': (Path(frame.filename).name
                                      if Path(frame.filename).name in SAFE_FRAMES else 'external'),
                           'function': (frame.name if re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]{0,80}', frame.name)
                                        else 'external'), 'line': frame.lineno}
                          for frame in frames[-8:]]}


def decode_map(item, layout):
    raw = item.get('value')
    if not isinstance(raw, list) or len(raw) != layout.size:
        raise ValueError('map ABI length mismatch')
    try:
        data = bytes(int(n, 16) if isinstance(n, str) and
                     re.fullmatch(r'0x[0-9a-fA-F]{2}', n) else n
                     if type(n) is int and 0 <= n <= 255 else -1 for n in raw)
    except (ValueError, TypeError) as exc:
        raise ValueError('malformed BPF map value') from exc
    fields = layout.unpack(data)
    if layout == AUTH:
        epoch, deadline, peer, resource, port, reserved = fields
        value = {'epoch': epoch, 'deadline_ns': deadline}
    elif layout == HEALTH:
        epoch, deadline, checked, peer, resource, port, reserved = fields
        value = {'epoch': epoch, 'deadline_ns': deadline, 'checked_ns': checked}
    else:
        raise ValueError('unknown map layout')
    value.update(peer=socket.inet_ntoa(struct.pack('<I', peer)),
                 resource=socket.inet_ntoa(struct.pack('<I', resource)),
                 port=port, reserved=reserved)
    return value

def parse_tc(text):
    """Extract only hook identity and numeric aggregate counts, never raw tc text."""
    match = re.search(r'\bpref\s+49152\s+bpf\b[^\n]*\bid\s+(\d+)\b', text)
    counts = re.search(r'\bSent\s+(\d+)\s+bytes\s+(\d+)\s+pkt', text)
    return {'attached': match is not None, 'program_id': int(match[1]) if match else None,
            'aggregate_bytes': int(counts[1]) if counts else None,
            'aggregate_packets': int(counts[2]) if counts else None}

def parse_route(rows, expected_dev, destination='10.80.0.2'):
    """Record only expected lab interface labels and exact destination comparison."""
    item = rows[0] if isinstance(rows, list) and rows and type(rows[0]) is dict else {}
    dev = item.get('dev')
    return {'selected_dev': dev if dev in ('wg-inner', 'resource', 'transit', 'pub') else 'other',
            'expected_dev': dev == expected_dev,
            'destination_matches': item.get('dst') == destination}

def syn_flows(path):
    """Decode bounded pcap records, returning only expected tuple SYN identities."""
    path = Path(path)
    if path.stat().st_size > 2_000_000:
        raise EvidenceError('grant assertion: capture exceeds diagnostic bound')
    data = path.read_bytes()
    if len(data) < 24:
        raise EvidenceError('grant assertion: invalid capture header')
    endian = {b'\xd4\xc3\xb2\xa1': '<', b'\xa1\xb2\xc3\xd4': '>',
              b'\x4d\x3c\xb2\xa1': '<', b'\xa1\xb2\x3c\x4d': '>'}.get(data[:4])
    if not endian:
        raise EvidenceError('grant assertion: unknown capture format')
    link = struct.unpack_from(endian + 'I', data, 20)[0]
    if link not in (1, 101):
        raise EvidenceError('grant assertion: unsupported capture link type')
    flows = set()
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise EvidenceError('grant assertion: truncated capture record')
        caplen, wirelen = struct.unpack_from(endian + 'II', data, offset + 8)
        offset += 16
        if caplen > 65535 or caplen > wirelen or offset + caplen > len(data):
            raise EvidenceError('grant assertion: invalid capture record length')
        frame = data[offset:offset + caplen]
        offset += caplen
        start = 0 if link == 101 else 14
        if link == 1 and (len(frame) < 14 or frame[12:14] != b'\x08\x00'):
            continue
        if len(frame) < start + 40 or frame[start] >> 4 != 4 or frame[start + 9] != 6:
            continue
        ihl = (frame[start] & 15) * 4
        total = struct.unpack_from('!H', frame, start + 2)[0]
        fragments = struct.unpack_from('!H', frame, start + 6)[0]
        tcp = start + ihl
        if (ihl < 20 or total < ihl + 20 or total > len(frame) - start or
                fragments & 0x3fff or tcp + 20 > len(frame) or
                frame[tcp + 12] >> 4 < 5 or
                (frame[tcp + 12] >> 4) * 4 > total - ihl or
                frame[start + 12:start + 16] != b'\x0a\x4f\x00\x01'
                or frame[start + 16:start + 20] != b'\x0a\x50\x00\x02'
                or struct.unpack_from('!H', frame, tcp + 2)[0] != 8080
                or frame[tcp + 13] & 0x12 != 0x02):
            continue
        flows.add((struct.unpack_from('!H', frame, tcp)[0],
                   struct.unpack_from('!I', frame, tcp + 4)[0]))
    return flows

def assert_packet_boundary(root):
    labels = ('endpoint-wg', 'inner-wg', 'inner-resource', 'resource')
    flows = {label: syn_flows(Path(root)/(label + '.pcap')) for label in labels}
    common = set.intersection(*(flows[label] for label in labels))
    if not common:
        raise EvidenceError('grant assertion: expected SYN missing from protected resource path')
    return {'matched_syn_flows': len(common),
            'boundary_syn_counts': {label: len(flows[label]) for label in labels}}


def sample(fixture, publisher, inner):
    c = fixture.controller
    status = c.step()
    now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    data = {'monotonic_ns': time.monotonic_ns(), 'boottime_ns': now,
            'controller_status': status, 'admission_state': c.admission.status,
            'generation': c.admission.generation,
            'original_deadline_ns': c.admission.deadline,
            'aa_attestation_until_ns': c.until_ns, 'aa_attestation_until_ms': c.until_ms,
            'aa_floors': c.floors,
            'scope_matches_resource': c.scope.get('resource') == 'tcp:10.80.0.2:8080',
            'epoch_active': publisher.current, 'maps': {}, 'programs': {}}
    for label, path, layout in (('authorization', publisher.auth_path, AUTH),
                                ('health', publisher.health_path, HEALTH)):
        response = json.loads(inner(['bpftool', '-j', 'map', 'lookup', 'pinned',
                                     path, 'key', 'hex', *KEY]))
        data['maps'][label] = {'key': KEY, 'value': decode_map(response, layout)}
    data['verdicts'] = decode_verdicts(json.loads(inner([
        'bpftool', '-j', 'map', 'dump', 'pinned', str(publisher.pin_dir/'maps'/'verdict_map')])))
    for label in ('wg_ingress', 'resource_ingress'):
        raw = json.loads(inner(['bpftool', '-j', 'prog', 'show', 'pinned',
                                str(publisher.pin_dir/'progs'/label)]))
        data['programs'][label] = {
            'id': raw.get('id') if type(raw.get('id')) is int else None,
            'expected_name': raw.get('name') == label,
            'classifier': raw.get('type') == 'sched_cls',
            'run_cnt': raw.get('run_cnt') if type(raw.get('run_cnt')) is int else None,
            'run_time_ns': (raw.get('run_time_ns') if type(raw.get('run_time_ns')) is int
                            else None)}
    data['tc'] = {interface: parse_tc(inner(['tc', '-s', 'filter', 'show', 'dev', interface,
                                             'ingress']))
                  for interface in ('wg-inner', 'resource')}
    data['nft'] = {}
    data['nft_hooks'] = {}
    for table in ('ipsec_dual', 'kernel_gate_v2_test'):
        rules = json.loads(inner(['nft', '-j', 'list', 'chain', 'inet', table, 'forward']))
        chains = [row['chain'] for row in rules.get('nftables', []) if 'chain' in row]
        data['nft_hooks'][table] = [{'hook_forward': ch.get('hook') == 'forward',
                                    'priority': ch.get('prio') if type(ch.get('prio')) is int else None,
                                    'policy_drop': ch.get('policy') == 'drop'} for ch in chains]
        data['nft'][table] = [
            {'handle': (rule['rule'].get('handle')
                        if type(rule['rule'].get('handle')) is int else None),
             'expected_forward': nft_rule_kind(rule['rule'].get('expr', []), table) == 'forward',
             'rule_kind': nft_rule_kind(rule['rule'].get('expr', []), table),
             'counter': [{'packets': (expr['counter'].get('packets')
                                       if type(expr['counter'].get('packets')) is int else None),
                          'bytes': (expr['counter'].get('bytes')
                                    if type(expr['counter'].get('bytes')) is int else None)}
                         for expr in rule['rule'].get('expr', [])
                         if 'counter' in expr],
             'verdicts': [name for expr in rule['rule'].get('expr', [])
                          for name in ('accept', 'drop') if name in expr]}
            for rule in rules.get('nftables', []) if 'rule' in rule]
    data['interfaces'] = {}
    for label, iface, runner in (('inner_wg', 'wg-inner', inner),
                                  ('inner_resource', 'resource', inner),
                                  ('resource', 'resource', lambda argv: command([
                                      'ip', 'netns', 'exec', NAMES['r'], *argv]))):
        data['interfaces'][label] = parse_link(json.loads(runner([
            'ip', '-j', '-s', 'link', 'show', 'dev', iface])), iface)
    data['inner_forwarding_enabled'] = parse_forwarding(inner(['sysctl', 'net.ipv4.ip_forward']))
    data['route'] = {}
    for role, dst, src, expected, incoming in (
            ('e', '10.80.0.2', '10.79.0.1', 'wg-inner', None),
            ('i', '10.80.0.2', '10.79.0.1', 'resource', 'wg-inner'),
            ('r', '10.79.0.1', '10.80.0.2', 'resource', None)):
        try:
            args = ['ip', 'netns', 'exec', NAMES[role], 'ip', '-j', 'route', 'get', dst, 'from', src]
            if incoming:
                args += ['iif', incoming]
            rows = json.loads(command(args))
            data['route'][role] = parse_route(rows, expected, dst)
        except Exception as exc:
            data['route'][role] = {'error_type': type(exc).__name__}
    return data


def assert_grant(report):
    issued = report.get('issuance')
    if not issued or issued.get('java_aa_status') != 'ATTESTED':
        raise EvidenceError('grant assertion: Java issuance/AA acceptance absent')
    if report.get('publish_returned') is not True:
        raise EvidenceError('grant assertion: BPF publication not confirmed')
    after = dict(report['snapshots']).get('post-grant')
    if not after or after['controller_status'] != 'ATTESTED' or after['admission_state'] != 'AUTHORIZED':
        raise EvidenceError('grant assertion: supervisor admission absent')
    bindings = (('wg-inner', 'wg_ingress'), ('resource', 'resource_ingress'))
    if not all(after['tc'].get(iface, {}).get('attached') is True and
               type(after['tc'][iface].get('program_id')) is int and
               after['tc'][iface]['program_id'] > 0 and
               after['tc'][iface]['program_id'] == after['programs'].get(label, {}).get('id') and
               after['programs'][label].get('expected_name') is True and
               after['programs'][label].get('classifier') is True
               for iface, label in bindings):
        raise EvidenceError('grant assertion: TC classifier attachment absent')
    for table, priority in (('ipsec_dual', 0), ('kernel_gate_v2_test', 10)):
        hooks = after.get('nft_hooks', {}).get(table, [])
        rules = after.get('nft', {}).get(table, [])
        expected_kinds = (['transit_in', 'transit_out', 'forward', 'reverse', 'drop']
                          if table == 'ipsec_dual' else ['forward', 'reverse', 'drop'])
        if (len(hooks) != 1 or hooks[0] != {'hook_forward': True,
                                           'priority': priority, 'policy_drop': True} or
                [rule.get('rule_kind') for rule in rules] != expected_kinds or
                not any(rule.get('expected_forward') is True and
                        rule.get('verdicts') == ['accept'] and rule.get('counter')
                        for rule in rules) or
                not rules or rules[-1].get('verdicts') != ['drop'] or
                not rules[-1].get('counter')):
            raise EvidenceError('grant assertion: independent nft interlock absent')
    finish = dict(report.get('snapshots', [])).get('post-traffic')
    if (not finish or finish.get('nft_hooks') != after['nft_hooks'] or
            not finish.get('inner_forwarding_enabled', False) or
            not after.get('inner_forwarding_enabled', False)):
        raise EvidenceError('grant assertion: independent nft interlock absent')
    auth = after['maps']['authorization']['value']
    health = after['maps']['health']['value']
    if (after['generation'] != issued['generation'] or
            after['original_deadline_ns'] != issued['original_deadline_ns'] or
            not auth['epoch'] or auth['epoch'] != health['epoch'] or
            auth['deadline_ns'] != issued['original_deadline_ns'] or
            not after['boottime_ns'] < health['deadline_ns'] <= auth['deadline_ns'] or
            not 0 < health['deadline_ns'] - health['checked_ns'] <= 500_000_000 or
            any(entry['peer'] != '10.79.0.1' or entry['resource'] != '10.80.0.2' or
                entry['port'] != 8080 for entry in (auth, health))):
        raise EvidenceError('grant assertion: valid scoped BPF maps absent')
    report['grant_bracket'] = grant_bracket(report['attempts'], report['grant_event_ns'])
    deltas = report.get('packet_deltas', {})
    tc = deltas.get('tc', {}).get('wg_ingress', {})
    post_attempts = [row for row in report['attempts']
                     if row['attempt_ns'] >= after['monotonic_ns']]
    if (type(tc.get('syn_passed')) is not int or
            not post_attempts or tc['syn_passed'] < 1 or
            tc.get('syn_dropped') != 0 or tc.get('syn_matched') != tc['syn_passed']):
        raise EvidenceError('grant assertion: scoped TC verdict evidence absent')
    for table in ('ipsec_dual', 'kernel_gate_v2_test'):
        allowed = {r['handle'] for r in after['nft'][table]
                   if r.get('expected_forward') is True and r.get('verdicts') == ['accept']}
        counted = [r for r in deltas.get('nft', {}).get(table, [])
                   if r.get('handle') in allowed and r.get('verdicts') == ['accept']
                   and r.get('packet_deltas') and type(r['packet_deltas'][0]) is int
                   and r['packet_deltas'][0] >= tc['syn_passed']]
        if len(counted) != 1:
            raise EvidenceError('grant assertion: scoped nft verdict evidence absent')
    return True


def run(root, fixture, issuer, ticker, publisher, inner, grant, *, active_probe=None):
    root = Path(root) / 'grant-diagnostic'
    root.mkdir(mode=0o700, exist_ok=False)
    (root/'pre').mkdir(mode=0o700)
    (root/'post').mkdir(mode=0o700)
    captures = CaptureSet(namespace_capture, boundaries=BOUNDARIES)
    stream = None
    report = {'snapshots': [], 'issuance': None, 'attempts': [], 'recover': {}}
    captures_started = False
    failure = None
    try:
        captures.start(root)
        captures_started = True
        with ticker.lock:
            report['snapshots'].append(['pre', sample(fixture, publisher, inner)])
        stream = TrafficStream(namespace=NAMES['e'])
        stream.start(root/'pre')
        stream.ready(delivered=False)
        report['attempts'].extend(stream.stop())
        stream = None
        with ticker.lock:
            report['grant_event_ns'] = time.monotonic_ns()
            issued = grant(fixture, issuer, report['recover'])
            report['issuance'] = {'java_aa_status': issued['status'],
                'generation': issued['generation'],
                'original_deadline_ns': issued['deadline_boottime_ns']}
            report['publish_returned'] = publisher.tick()
            if report['publish_returned'] is not True:
                raise EvidenceError('grant assertion: BPF publication not confirmed')
        with ticker.lock:
            report['snapshots'].append(['post-grant', sample(fixture, publisher, inner)])
        # No protected application worker runs during the counter baseline.
        # Only this second worker emits the protected tuple until it stops.
        stream = TrafficStream(namespace=NAMES['e'])
        stream.start(root/'post')
        time.sleep(.8)
        report['attempts'].extend(stream.stop())
        stream = None
        with ticker.lock:
            report['snapshots'].append(['post-traffic', sample(fixture, publisher, inner)])
        snapshots = dict(report['snapshots'])
        report['packet_deltas'] = packet_deltas(snapshots['post-grant'], snapshots['post-traffic'])
        if active_probe is not None:
            # Validate the positive path and exact nft interlock before sending
            # any negative probes. No fault or new grant is introduced here.
            assert_grant(report)
            from functional_p0 import assert_pregrant
            assert_pregrant(report)
            report['active_grant'] = active_probe(root, fixture, ticker, publisher, inner)
    except Exception as exc:
        failure = exc
        report['failure'] = safe_failure(exc)
    finally:
        if stream is not None:
            try:
                report['attempts'].extend(stream.stop())
            except Exception as exc:
                report['cleanup_failure'] = safe_failure(exc)
                if failure is None:
                    failure = exc
        if captures_started:
            try:
                captures.stop()
            except Exception as exc:
                report.setdefault('cleanup_failure', safe_failure(exc))
                if failure is None:
                    failure = exc
        if failure is None:
            try:
                assert_grant(report)
                report['packet_boundary'] = assert_packet_boundary(root)
            except Exception as exc:
                failure = exc
                report['failure'] = safe_failure(exc)
        report['status'] = 'FAIL' if failure is not None else 'PASS'
        try:
            (root/'diagnostic.json').write_text(json.dumps(report, sort_keys=True, indent=2)+'\n')
        except (OSError, TypeError) as exc:
            if failure is None:
                failure = exc
                report['failure'] = {'message': 'diagnostic evidence write failed'}
            # Keep the original grant failure primary; packet/status files may still exist.
    if failure is not None:
        record = report.get('failure', report.get('cleanup_failure', {'message': 'redacted'}))
        raise EvidenceError('grant diagnostic failed: ' + record['message']) from None
    return report
