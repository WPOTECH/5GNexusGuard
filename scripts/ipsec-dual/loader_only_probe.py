"""One-shot isolated BPF loader probe. No network namespace, TC attachment or grant."""
import json
from contextlib import ExitStack
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

from kernel_gate_publisher_v2 import _loadall_diagnostic

MAP_ABI = {'auth_map': (4, 32, 1), 'health_map': (4, 40, 1),
           'verdict_map': (4, 8, 32)}
PROGRAMS = ('wg_ingress', 'resource_ingress')
LOAD_ARGV = ['bpftool', '-d', 'prog', 'loadall', '<object>', '<progs>',
             'type', 'classifier', 'pinmaps', '<maps>']
COMMAND = ' '.join(LOAD_ARGV)
EVIDENCE_ROOT = Path('/lab/evidence/loader-only-aa')

def _stream_sample(data):
    """Count captured bytes, but inspect only bounded head/tail; never persist raw data."""
    if data is None:
        raw = b''
    elif isinstance(data, bytes):
        raw = data
    else:
        raw = data.encode('utf-8', errors='replace')
    truncated = len(raw) > 8192
    sampled = raw[:4096] + (b'\n' + raw[-4096:] if truncated else raw[4096:])
    return len(raw), truncated, sampled.decode('utf-8', errors='replace')

def _load_diagnostics(record, stdout, stderr, stats=None):
    out_count, out_cut, out_text = _stream_sample(stdout)
    err_count, err_cut, err_text = _stream_sample(stderr)
    record.update(stdout_bytes=out_count, stderr_bytes=err_count,
                  stdout_truncated=out_cut, stderr_truncated=err_cut,
                  output_truncated=out_cut or err_cut)
    if stats:
        record.update(stats)
        record['output_truncated'] = (record['stdout_truncated'] or record['stderr_truncated'])
    # stderr is normally authoritative; stdout may contain the sole bpftool error.
    text = err_text + '\n' + out_text
    record['verifier_log_present'] = bool(re.search(
        r'\b(?:BEGIN PROG LOAD LOG|processed \d+ insns|invalid mem access|'
        r'invalid bpf_context access|R\d+ (?:type|invalid)|verifier log)\b', text, re.I))
    # Static messages only: no paths, source lines, offsets, credentials or raw log text.
    recognized = ((r'\binvalid mem access\b', 'invalid_mem_access'),
                  (r'\binvalid bpf_context access\b', 'invalid_context_access'),
                  (r'\bunbounded loop\b', 'unbounded_loop'),
                  (r'\binvalid indirect read\b', 'invalid_indirect_read'),
                  (r'\bfailed to pin\b|\bpinning failed\b', 'pinning_failed'),
                  (r'\b(?:No such file or directory|ENOENT)\b', 'no_such_file'),
                  (r'\b(?:Operation not permitted|EPERM)\b', 'operation_not_permitted'),
                  (r'\b(?:Invalid argument|EINVAL)\b', 'invalid_argument'),
                  (r'\bfailed to (?:open|load) object(?: file)?\b', 'object_open_or_load_failed'),
                  (r'\b(?:failed to load|load failed)\b', 'program_load_failed'),
                  (r'\b(?:failed to create map|map creation failed)\b', 'map_creation_failed'),
                  (r'\b(?:Usage: bpftool|unrecognized option|unknown command)\b', 'invalid_invocation'))
    record['loader_messages'] = [token for pattern, token in recognized
                                 if re.search(pattern, text, re.I)][:8]
    return text


def classify(stderr, stdout=''):
    """Fixed signals only. Unknown messages never become reported raw evidence."""
    data = _loadall_diagnostic(stderr, stdout, bounded=True)
    category = data['category']
    text = stderr + '\n' + stdout
    if category in ('unknown', 'program_load_failed'):
        if re.search(r'\b(?:CAP_BPF|CAP_PERFMON|CAP_SYS_ADMIN)\b.{0,60}\b(?:required|missing)\b', text, re.I):
            category = 'missing_kernel_capability'
        elif re.search(r'\b(?:Usage: bpftool|unrecognized option|unknown command)\b', text, re.I):
            category = 'invalid_invocation'
    reason = data['explicit_verifier_evidence']
    output = [reason] if reason != 'unknown' and category not in ('ambiguous', 'map_pin_failure', 'program_pin_failure', 'installation_failure') else []
    return category, reason if category not in ('map_pin_failure', 'program_pin_failure', 'installation_failure') else 'unknown', data['subject'], data['errno'], output


def _run(args, *, binary=False, raw_dir=None):
    if not binary:
        return subprocess.run(args, text=True, capture_output=True, timeout=2, check=False)
    # bpftool -d can emit a large verifier trace; never buffer it in memory.
    heads = {1: bytearray(), 2: bytearray()}
    tails = {1: bytearray(), 2: bytearray()}
    counts = {1: 0, 2: 0}
    deadline = time.monotonic() + 2
    timed_out = False
    with ExitStack() as stack, selectors.DefaultSelector() as selector:
        raw_files = {}
        if raw_dir is not None:
            for fd, name in ((1, 'bpftool.stdout'), (2, 'bpftool.stderr')):
                handle = os.open(Path(raw_dir)/name,
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600)
                raw_files[fd] = stack.enter_context(os.fdopen(handle, 'wb'))
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for fd in (1, 2):
            selector.register(proc.stdout if fd == 1 else proc.stderr, selectors.EVENT_READ, fd)
        try:
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0 and not timed_out:
                    proc.kill()
                    timed_out = True
                    deadline = time.monotonic() + 1  # drain the owned child only
                    remaining = 1
                if timed_out and remaining <= 0:
                    break  # an unrelated descendant may hold a pipe open
                for key, _ in selector.select(max(0, remaining)):
                    fd = key.data
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    counts[fd] += len(chunk)
                    if fd in raw_files:
                        raw_files[fd].write(chunk)
                    needed = max(0, 4096 - len(heads[fd]))
                    heads[fd].extend(chunk[:needed])
                    tails[fd] = (tails[fd] + chunk)[-4096:]
        finally:
            if proc.poll() is None:
                if not timed_out:
                    try:
                        proc.wait(timeout=max(0, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        timed_out = True
                else:
                    proc.kill()
            proc.wait()
            proc.stdout.close()
            proc.stderr.close()
    def sampled(fd):
        if counts[fd] <= 8192:
            return bytes(heads[fd] + tails[fd][-(counts[fd] - len(heads[fd])):]) if counts[fd] > len(heads[fd]) else bytes(heads[fd])
        return bytes(heads[fd]) + b'\n' + bytes(tails[fd])
    stats = dict(stdout_bytes=counts[1], stderr_bytes=counts[2],
                 stdout_truncated=counts[1] > 8192, stderr_truncated=counts[2] > 8192)
    if timed_out:
        error = subprocess.TimeoutExpired(args, 2, output=sampled(1), stderr=sampled(2))
        error.stream_stats = stats
        raise error
    result = subprocess.CompletedProcess(args, proc.returncode, sampled(1), sampled(2))
    result.stream_stats = stats
    return result


def _cleanup(pin):
    # Refuse unexpected pins rather than recursively deleting bpffs.
    owned = []
    for kind, names in (('progs', set(PROGRAMS)), ('maps', set(MAP_ABI))):
        leaf = pin/kind
        if leaf.exists():
            children = list(leaf.iterdir())
            if any(x.name not in names or not x.is_file() for x in children):
                raise RuntimeError('unknown_pin')
            owned.append((leaf, children))
    for leaf, children in owned:
        for child in children:
            child.unlink()
        leaf.rmdir()
    if pin.exists():
        pin.rmdir()


def probe(obj, evidence, pin, *, source):
    """Compile, load/pin, inspect exact ABI; always persist sanitized result."""
    obj, evidence, pin, source = map(Path, (obj, evidence, pin, source))
    record = dict(failing_subprocess='none', failing_executable='none',
                  failing_operation='none', argv=[], exit_code=None, load_exit_code=None,
                  category='not_run',
                  verifier_reason='unknown', verifier_output=[], subject='unknown',
                  errno='unknown', map_pinning_status='BLOCKED', verifier_load='BLOCKED',
                  cleanup='NOT_RUN', stdout_bytes=0, stderr_bytes=0,
                  stdout_truncated=False, stderr_truncated=False,
                  output_truncated=False, verifier_log_present=False, loader_messages=[],
                  explicit_verifier_evidence='unknown', permission_error_evidence='unknown',
                  map_pinning_evidence=[], ambiguous_or_unknown=True, diagnostic_tokens=[])
    code = 1
    owned_pin_directory = False
    try:
        pin.mkdir(mode=0o700)
        owned_pin_directory = True
        (pin/'maps').mkdir(mode=0o700)
        (pin/'progs').mkdir(mode=0o700)
        compile_cmd = ['clang', '-O2', '-g', '-target', 'bpf',
                       '-I/usr/include/x86_64-linux-gnu', '-c', str(source), '-o', str(obj)]
        record['failing_subprocess'] = 'clang -O2 -g -target bpf <source> -o <object>'
        record['failing_executable'], record['failing_operation'] = 'clang', 'compile bpf object'
        record['argv'] = ['clang', '-O2', '-g', '-target', 'bpf', '-I<include>',
                          '-c', '<source>', '-o', '<object>']
        built = _run(compile_cmd)
        record['exit_code'] = built.returncode
        if built.returncode:
            record['category'] = 'compile_failed'
            return code
        args = ['bpftool', '-d', 'prog', 'loadall', str(obj), str(pin/'progs'),
                'type', 'classifier', 'pinmaps', str(pin/'maps')]
        record['failing_subprocess'] = COMMAND
        record['failing_executable'], record['failing_operation'] = 'bpftool', 'prog loadall'
        record['argv'] = list(LOAD_ARGV)
        loaded = _run(args, binary=True, raw_dir=evidence.parent)
        record['exit_code'] = loaded.returncode
        record['load_exit_code'] = loaded.returncode
        output = _load_diagnostics(record, loaded.stdout, loaded.stderr,
                                   getattr(loaded, 'stream_stats', None))
        if loaded.returncode:
            err_text = _stream_sample(loaded.stderr)[2]
            out_text = _stream_sample(loaded.stdout)[2]
            (record['category'], record['verifier_reason'], record['subject'],
             record['errno'], record['verifier_output']) = classify(err_text, out_text)
            structured = _loadall_diagnostic(err_text, out_text, bounded=True, exit_code=loaded.returncode,
                stats={key: record[key] for key in ('stdout_bytes', 'stderr_bytes',
                       'stdout_truncated', 'stderr_truncated')})
            for key in ('explicit_verifier_evidence', 'permission_error_evidence',
                        'map_pinning_evidence', 'ambiguous_or_unknown', 'diagnostic_tokens'):
                record[key] = structured[key]
            record['map_pinning_status'] = ('FAIL' if record['category'] in
                                            ('map_pin_failure', 'program_pin_failure')
                                            else 'UNVERIFIED')
            record['verifier_load'] = 'FAIL' if record['category'] == 'verifier_rejected' else 'BLOCKED'
            return code
        # A successful loadall still requires the expected named pins and ABI.
        for name, (key, value, entries) in MAP_ABI.items():
            path = pin/'maps'/name
            if not path.is_file():
                record['category'] = 'missing_map_pin'
                record['failing_subprocess'] = 'none'
                record['failing_executable'], record['failing_operation'] = 'none', 'none'
                record['argv'] = []
                record['exit_code'] = None
                return code
            record['failing_subprocess'] = 'bpftool -j map show pinned <map>'
            record['failing_executable'], record['failing_operation'] = 'bpftool', 'map show pinned'
            record['argv'] = ['bpftool', '-j', 'map', 'show', 'pinned', '<map>']
            info = _run(['bpftool', '-j', 'map', 'show', 'pinned', str(path)])
            record['exit_code'] = info.returncode
            if info.returncode:
                record['category'] = 'map_inspection_failed'
                return code
            data = json.loads(info.stdout)
            if (data.get('type') != 'array' or
                (data.get('bytes_key', data.get('key')),
                 data.get('bytes_value', data.get('value')),
                 data.get('max_entries')) != (key, value, entries)):
                record['category'] = 'map_abi_mismatch'
                record['map_pinning_status'] = 'FAIL'
                return code
        for name in PROGRAMS:
            path = pin/'progs'/name
            if not path.is_file():
                record['category'] = 'missing_program_pin'
                record['failing_subprocess'] = 'none'
                record['failing_executable'], record['failing_operation'] = 'none', 'none'
                record['argv'] = []
                record['exit_code'] = None
                return code
            record['failing_subprocess'] = 'bpftool -j prog show pinned <prog>'
            record['failing_executable'], record['failing_operation'] = 'bpftool', 'prog show pinned'
            record['argv'] = ['bpftool', '-j', 'prog', 'show', 'pinned', '<prog>']
            info = _run(['bpftool', '-j', 'prog', 'show', 'pinned', str(path)])
            record['exit_code'] = info.returncode
            if info.returncode or json.loads(info.stdout).get('type') != 'sched_cls':
                record['category'] = 'program_inspection_failed'
                return code
        record.update(category='none', map_pinning_status='PASS', verifier_load='PASS',
                      failing_subprocess='none', failing_executable='none',
                      failing_operation='none', argv=[])
        code = 0
        return code
    except subprocess.TimeoutExpired as error:
        if record['failing_subprocess'] == COMMAND:
            output = _load_diagnostics(record, error.stdout, error.stderr,
                              getattr(error, 'stream_stats', None))
            err_text = _stream_sample(error.stderr)[2]
            out_text = _stream_sample(error.stdout)[2]
            structured = _loadall_diagnostic(err_text, out_text, bounded=True,
                stats={key: record[key] for key in ('stdout_bytes', 'stderr_bytes',
                       'stdout_truncated', 'stderr_truncated')})
            for key in ('explicit_verifier_evidence', 'permission_error_evidence',
                        'map_pinning_evidence', 'diagnostic_tokens'):
                record[key] = structured[key]
        record['category'] = 'timeout'
        record['exit_code'] = None
        return 1
    except FileExistsError:
        record['category'] = 'pin_directory_exists'
        record['exit_code'] = None
        return 1
    except OSError:
        record['category'] = 'launch_or_filesystem_error'
        record['exit_code'] = None
        return 1
    except (ValueError, KeyError, TypeError):
        record['category'] = 'inspection_parse_error'
        return 1
    finally:
        if owned_pin_directory:
            try:
                _cleanup(pin)
                record['cleanup'] = 'PASS'
            except (OSError, RuntimeError):
                record['cleanup'] = 'FAIL'
                if record['category'] == 'none':
                    record['category'] = 'cleanup_failed'
        # Evidence path is on the dedicated volume; no raw subprocess output.
        evidence.write_text(json.dumps(record, sort_keys=True) + '\n')
        if record['cleanup'] == 'FAIL' and record['category'] == 'cleanup_failed':
            raise RuntimeError('isolated cleanup failed') from None


def check_container():
    return (os.environ.get('DL_IPSEC_ISOLATED') == '1' and
            os.path.ismount('/lab/private') and
            Path('/lab/src/scripts/ipsec-dual/kernel_gate_v2.bpf.c').is_file())


def mount_is_private():
    """Check propagation of the parent mount before adding bpffs in this namespace."""
    candidates = []
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields = line.split()
        mountpoint = fields[4].replace('\\040', ' ')
        if '/sys/fs/bpf' == mountpoint or '/sys/fs/bpf'.startswith(mountpoint.rstrip('/') + '/'):
            candidates.append((len(mountpoint), fields[6:fields.index('-')]))
    return bool(candidates) and not any(
        token.startswith(('shared:', 'master:', 'propagate_from:'))
        for token in max(candidates)[1])


def main():
    if not check_container():
        raise SystemExit('isolated loader prerequisites unavailable')
    root = EVIDENCE_ROOT
    root.mkdir(mode=0o700, exist_ok=False)
    report = root/'report.json'
    def mount_failure(category, exit_code=None):
        report.write_text(json.dumps(dict(failing_subprocess='mount -t bpf',
            exit_code=exit_code, load_exit_code=None, category=category,
            verifier_reason='unknown', verifier_output=[], map_pinning_status='BLOCKED',
            verifier_load='BLOCKED', cleanup='NOT_RUN')) + '\n')
        return 1
    try:
        if not mount_is_private():
            return mount_failure('mount_propagation_unverified')
    except (OSError, ValueError, IndexError):
        return mount_failure('mount_propagation_unverified')
    # bpffs exists only inside the disposable container's mount namespace.
    try:
        mounted = subprocess.run(['mount', '-t', 'bpf', 'bpf', '/sys/fs/bpf'],
                                 capture_output=True, text=True, check=False, timeout=2)
    except subprocess.TimeoutExpired:
        return mount_failure('mount_timeout')
    except OSError:
        return mount_failure('mount_launch_failed')
    if mounted.returncode:
        return mount_failure('bpffs_mount_failed', mounted.returncode)
    return probe(root/'gate.o', report, Path('/sys/fs/bpf/mesh-loader-only'),
                 source=Path('/lab/src/scripts/ipsec-dual/kernel_gate_v2.bpf.c'))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('isolated-loader-probe-failed', file=sys.stderr)
        sys.exit(1)
