"""Container-only P0 entry point; raw diagnostics stay on the private evidence volume."""
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

from loader_only_probe import check_container, mount_is_private


def main():
    if not check_container() or os.geteuid() != 0:
        raise RuntimeError('approved isolated container and private tmpfs required')
    os.umask(0o077)
    root = Path('/lab/evidence')
    original_run = subprocess.run
    failures, nft_reads = [], []

    def captured_run(*args, **kwargs):
        result = original_run(*args, **kwargs)
        argv = result.args
        if isinstance(argv, list) and 'nft' in argv and '-j' in argv and result.returncode == 0:
            path = root/('nft-%03d.local.json' % len(nft_reads))
            path.write_text(result.stdout)
            nft_reads.append(path.name)
        if result.returncode:
            index = len(failures)
            for stream in ('stdout', 'stderr'):
                data = getattr(result, stream, None)
                if data is not None:
                    (root/('failed-%02d.' % index+stream)).write_bytes(
                        data.encode() if isinstance(data, str) else data)
            failures.append({'executable': argv[0], 'exit_code': result.returncode,
                             'frames': [{'file': Path(f.filename).name, 'function': f.name,
                                         'line': f.lineno} for f in traceback.extract_stack()[-5:]]})
            (root/'failed-commands.local.json').write_text(json.dumps(failures, indent=2))
        return result

    subprocess.run = captured_run
    import isolated_enforcement as runner
    cleanup = []
    original_cleanup = runner.complete_cleanup

    def recorded_cleanup(actions, primary):
        wrapped = []
        for name, action in actions:
            def perform(name=name, action=action):
                try:
                    result = action()
                    cleanup.append({'stage': name, 'status': 'PASS'})
                    return result
                except BaseException:
                    cleanup.append({'stage': name, 'status': 'FAIL'})
                    raise
                finally:
                    (root/'cleanup.json').write_text(json.dumps(cleanup))
            wrapped.append((name, perform))
        return original_cleanup(wrapped, primary)

    runner.complete_cleanup = recorded_cleanup
    try:
        if not mount_is_private():
            raise RuntimeError('bpffs parent mount propagation is not private')
        original_run(['mount', '-t', 'bpf', 'bpf', '/sys/fs/bpf'], check=True, capture_output=True)
        original_run(['clang', '-O2', '-g', '-target', 'bpf', '-I/usr/include/x86_64-linux-gnu',
                      '-c', '/lab/src/scripts/ipsec-dual/kernel_gate_v2.bpf.c',
                      '-o', '/lab/evidence/gate.o'], check=True, capture_output=True)
        sys.argv = ['isolated_enforcement.py', '--object', '/lab/evidence/gate.o',
                    '--evidence', '/lab/evidence/packet', '--classpath',
                    '/lab/java/test-classes:/lab/java/classes:/lab/java/lib/*']
        scenario = os.environ.get('DL_P1_SCENARIO')
        sys.argv += ['--security-p1', scenario] if scenario else ['--functional-p0']
        runner.main()
    except BaseException as exc:
        (root/'exception.local.txt').write_text(''.join(traceback.format_exception(exc)))
        if isinstance(exc, (subprocess.CalledProcessError, subprocess.TimeoutExpired)):
            for stream in ('stdout', 'stderr'):
                data = getattr(exc, stream, None)
                if data is not None:
                    (root/('exception.local.'+stream)).write_bytes(data.encode() if isinstance(data, str) else data)
        raise
    finally:
        observed = {}
        for label, argv in [('namespaces', ['ip', 'netns', 'list']),
                            ('pins', ['find', '/sys/fs/bpf', '-mindepth', '1', '-maxdepth', '3', '-print'])]:
            result = original_run(argv, capture_output=True, text=True)
            observed[label] = {'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr}
        (root/'post-cleanup.json').write_text(json.dumps(observed))
        subprocess.run = original_run


if __name__ == '__main__':
    main()
