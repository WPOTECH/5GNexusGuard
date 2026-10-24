"""Test-only separate supervisor using the unchanged Controller, Publisher and FreshHealth.

Initial credentials arrive on stdin, never argv or evidence. AA, Java and charon
remain in the parent/other processes. SIGKILL cannot execute a revoke handler.
"""
import base64
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time

from cryptography.hazmat.primitives import serialization
from kernel_gate_publisher_v2 import AUTH, HEALTH, FreshHealth, Publisher, command
from loader_only_probe import check_container
from native import NAMES
from native_control_v2 import Controller, atomic_private_write


def inner_command(argv, *, input=None):
    if argv[0] == 'bpftool':
        return command(argv, input=input)
    if argv[0] == 'tc':
        return command(['nsenter', '--net=/run/netns/'+NAMES['i'], '--', *argv], input=input)
    return command(['ip', 'netns', 'exec', NAMES['i'], *argv], input=input)


def main():
    if not check_container() or os.geteuid() != 0:
        raise RuntimeError('approved isolated container required')
    os.umask(0o077)
    cfg = json.loads(sys.stdin.readline())
    signer = serialization.load_der_private_key(base64.b64decode(cfg.pop('signer')), None)
    directory = Path(cfg['directory'])
    c = Controller(directory, cfg['scope'], bytes.fromhex(cfg['operator']),
                   bytes.fromhex(cfg['node']), signer, cfg['url'], cfg['ca'], cfg['cert'],
                   cfg['key'], bytes.fromhex(cfg['aa_key']))
    del signer
    health = FreshHealth(cfg['pids'], 'wg-inner', 'resource', NAMES['e'], NAMES['o'],
                         NAMES['i'], vici_dir=Path(cfg['vici']))
    p = Publisher(c, inner_command, cfg['pin'], 'wg-inner', 'resource', health=health)
    # Parent already installed and verified TC/maps while denied. This process
    # never calls install(), adopts a grant, or writes direct permits.
    from independent_kernel_p1 import assert_hooks, kernel_snapshot
    snapshot = kernel_snapshot(p, inner_command)
    assert_hooks(snapshot)
    if any(row['value']['epoch'] or row['value']['deadline_ns'] for row in snapshot['maps'].values()):
        raise RuntimeError('supervisor handoff requires zero maps, never a restored grant')
    p.installed = True
    original_run = subprocess.run
    failures = 0

    def captured_run(*args, **kwargs):
        nonlocal failures
        try:
            return original_run(*args, **kwargs)
        except subprocess.CalledProcessError as exc:
            argv = exc.cmd
            if isinstance(argv, list) and argv[:3] == ['bpftool', 'map', 'update']:
                for name in ('stdout', 'stderr'):
                    data = getattr(exc, name, None)
                    if data is not None:
                        (Path(cfg['audit']).parent/('map-update-failed-%03d.' % failures+name)).write_bytes(
                            data.encode() if isinstance(data, str) else data)
                failures += 1
            raise
    subprocess.run = captured_run
    original_update = p._update
    audit = Path(cfg['audit'])
    error = None

    def update(path, value):
        layout = AUTH if Path(path).name == 'auth_map' else HEALTH
        fields = layout.unpack(value)
        row = {'map': Path(path).name, 'epoch': fields[0], 'deadline_ns': fields[1],
               'boottime_ns': time.clock_gettime_ns(time.CLOCK_BOOTTIME), 'success': False}
        try:
            result = original_update(path, value)
            row['success'] = True
            return result
        finally:
            with audit.open('a') as stream:
                stream.write(json.dumps(row)+'\n')
    p._update = update

    def tick():
        nonlocal error
        try:
            published = p.tick()
            error = None
            return published
        except Exception as exc:
            error = {'type': type(exc).__name__, 'message': str(exc)}
            return False

    def state(status, published=False):
        return {'pid': os.getpid(), 'start': FreshHealth._start(os.getpid()),
                'session': c.session, 'generation': c.admission.generation,
                'status': status, 'admission_state': c.admission.status,
                'deadline_ns': c.admission.deadline,
                'revocation_uncertain': p.revocation_uncertain, 'published': published,
                'last_error': error, 'challenge': json.loads((directory/'challenge.json').read_text())}

    print(json.dumps(state(c.step())), flush=True)
    try:
        while True:
            ready, _, _ = select.select([sys.stdin], [], [], .08)
            if not ready:
                tick()
                continue
            line = sys.stdin.readline()
            if not line:
                break
            request = json.loads(line)
            action = request['action']
            if action == 'submit':
                atomic_private_write(directory/'inbox.json', json.dumps(request['item']).encode())
                status = c.step()
                published = tick()
            elif action in ('state', 'reconcile'):
                status = c.step()
                published = tick() if action == 'reconcile' else False
            else:
                raise ValueError('unknown supervisor test operation')
            print(json.dumps(state(status, published)), flush=True)
    finally:
        try:
            p.revoke()
        finally:
            subprocess.run = original_run


if __name__ == '__main__':
    main()
