#!/usr/bin/env python3
"""Launch functional P0 or one approved P1 category; retain raw evidence outside Git."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-approved', action='store_true')
    parser.add_argument('--evidence', required=True, type=Path)
    parser.add_argument('--java', required=True, type=Path,
                        help='scratch directory containing classes/, test-classes/, lib/')
    parser.add_argument('--image', default='dl-ipsec-isolated-evidence:probe')
    parser.add_argument('--p1-scenario', choices=('expiry', 'revoke', 'charon_crash'),
                        help='run one P1 category instead of functional P0; requires explicit scoped approval')
    args = parser.parse_args()
    if not args.parent_approved:
        parser.error('explicit runtime approval is required; the flag alone is not approval')
    repo = Path(__file__).resolve().parents[2]
    if not args.evidence.is_absolute():
        parser.error('new absolute evidence path outside repository required')
    root = args.evidence.resolve()
    if root == repo or repo in root.parents or root.exists():
        parser.error('new evidence directory outside repository required')
    java = args.java.resolve(strict=True)
    for name in ('classes', 'test-classes', 'lib'):
        if not (java/name).is_dir():
            parser.error('Java classes, test-classes and dependency lib directories required')
    os.umask(0o077)
    root.mkdir(mode=0o700)
    name = 'mesh-p0-'+secrets.token_hex(6)
    volume = name+'-evidence'
    argv = ['docker', 'create', '--name', name, '--network', 'none', '--cap-drop', 'ALL']
    for cap in ('NET_ADMIN', 'NET_RAW', 'BPF', 'PERFMON', 'SYS_ADMIN',
                'NET_BIND_SERVICE', 'SETUID', 'SETGID'):
        argv += ['--cap-add', cap]
    argv += ['--security-opt', 'apparmor=unconfined', '--pids-limit', '256', '--memory', '2g',
             '-e', 'DL_IPSEC_ISOLATED=1', '--mount', f'type=bind,src={repo},dst=/lab/src,readonly',
             '--mount', f'type=bind,src={java},dst=/lab/java,readonly',
             '--mount', f'type=volume,src={volume},dst=/lab/evidence',
             '--mount', 'type=tmpfs,dst=/lab/private,tmpfs-mode=0700', '-w', '/lab/src',
             args.image, '/usr/bin/python3', '-B', '/lab/src/scripts/ipsec-dual/p0_container.py']
    if args.p1_scenario:
        argv[2:2] = ['-e', 'DL_P1_SCENARIO='+args.p1_scenario]
    (root/'invocation.local.json').write_text(json.dumps(argv)+'\n')
    (root/'ownership.local.json').write_text(json.dumps({'container': name, 'volume': volume})+'\n')

    def run(command, label):
        with (root/(label+'.stdout')).open('xb') as out, (root/(label+'.stderr')).open('xb') as err:
            return subprocess.run(command, stdout=out, stderr=err).returncode

    if run(argv, 'create'):
        print('P0 blocked: container creation failed; inspect local evidence.', file=sys.stderr)
        return 1
    print(('P1 '+args.p1_scenario if args.p1_scenario else 'P0')+' evidence: '+str(root), flush=True)
    code = run(['docker', 'start', '-a', name], 'container')
    copied = run(['docker', 'cp', name+':/lab/evidence/.', str(root/'captured')], 'copy')
    if copied == 0:
        for path in (root/'captured').rglob('*'):
            path.chmod(0o700 if path.is_dir() else 0o600)
        (root/'captured').chmod(0o700)
    removed = run(['docker', 'rm', name], 'remove-container')
    volume_removed = run(['docker', 'volume', 'rm', volume], 'remove-volume') if copied == removed == 0 else None
    status = {'container_exit': code, 'copy_exit': copied, 'container_cleanup_exit': removed,
              'volume_cleanup_exit': volume_removed}
    passed = code == copied == removed == volume_removed == 0
    if passed:
        try:
            observed = json.loads((root/'captured/post-cleanup.json').read_text())
            cleanup = json.loads((root/'captured/cleanup.json').read_text())
            report = json.loads((root/('captured/packet/p1.json' if args.p1_scenario
                                      else 'captured/packet/p0.json')).read_text())
            scenario_passed = (report['status'] == 'PASS' and
                               report.get('scenario') == args.p1_scenario) if args.p1_scenario else (
                               report['status'] == report['active_grant']['status'] == 'PASS' and
                               bool(report['active_packet_evidence']))
            passed = (scenario_passed and
                      {row['stage'] for row in cleanup} == {'ticker', 'issuer', 'fixture', 'server', 'topology', 'pins'} and
                      all(row['status'] == 'PASS' for row in cleanup) and
                      set(observed) == {'namespaces', 'pins'} and
                      all(row['exit_code'] == 0 and not row['stdout'].strip() and not row['stderr'].strip()
                          for row in observed.values()))
        except (OSError, ValueError, KeyError, TypeError):
            passed = False
    if args.p1_scenario:
        status['P1_SCENARIO'] = args.p1_scenario
        status['P1_SCENARIO_RESULT'] = 'PASS' if passed else 'FAIL'
    else:
        status['PROTOTYPE_P0'] = 'WORKING' if passed else 'PARTIAL'
    (root/'acceptance.json').write_text(json.dumps(status, indent=2)+'\n')
    print(json.dumps(status))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
