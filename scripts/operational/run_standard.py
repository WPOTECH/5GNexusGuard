#!/usr/bin/env python3
"""Explicitly approved, single isolated STANDARD packet run with the built product JAR."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess

IMAGE='dl-ipsec-isolated-evidence:probe'
IMAGE_ID='sha256:ecd5c54a5243526f0fde27f061fca30a13e5911e855f6108b348f4b8787ce54e'
CAPS=('NET_ADMIN','NET_RAW','BPF','PERFMON','SYS_ADMIN','NET_BIND_SERVICE','SETUID','SETGID')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--parent-approved',action='store_true');p.add_argument('--jar',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True);args=p.parse_args()
    if not args.parent_approved:p.error('explicit operator approval required')
    if not Path('/sys/module/wireguard').is_dir():p.error('WireGuard must already be available; host module loading is not authorized by this runner')
    repo=Path(__file__).resolve().parents[2];evidence=args.evidence.resolve();jar=args.jar.resolve()
    if not jar.is_file() or evidence.exists() or not evidence.is_absolute() or evidence==repo or repo in evidence.parents:p.error('existing JAR and fresh private external evidence directory required')
    if subprocess.check_output(['docker','image','inspect',IMAGE,'--format','{{.Id}}'],text=True).strip()!=IMAGE_ID:p.error('reviewed image identity differs')
    os.umask(0o077);evidence.mkdir(mode=0o700);name='mesh-p2-standard-'+secrets.token_hex(8)
    argv=['docker','create','--name',name,'--network','none','--cap-drop','ALL']
    for cap in CAPS:argv+=['--cap-add',cap]
    argv+=['--security-opt','apparmor=unconfined','--pids-limit','256','--memory','2g','-e','DL_IPSEC_ISOLATED=1',
           '--mount','type=bind,src='+str(repo)+',dst=/lab/src,readonly',
           '--mount','type=bind,src='+str(jar)+',dst=/lab/application.jar,readonly',
           '--mount','type=tmpfs,dst=/lab/private,tmpfs-mode=0700',
           '-w','/lab/src',IMAGE,'python3','-B','/lab/src/scripts/operational/standard_packet.py']
    (evidence/'invocation.local.json').write_text(json.dumps(argv,indent=2))
    created=False
    try:
        subprocess.run(argv,check=True,stdout=subprocess.DEVNULL);created=True
        with (evidence/'container.local.log').open('wb') as log:run=subprocess.run(['docker','start','-a',name],stdout=log,stderr=log,timeout=240)
        subprocess.run(['docker','cp',name+':/lab/evidence/.',str(evidence)],check=True,capture_output=True)
        state=json.loads(subprocess.check_output(['docker','inspect','--format','{{json .State}}',name],text=True))
        if run.returncode or state['ExitCode'] or state.get('OOMKilled'):raise RuntimeError('STANDARD packet test failed; inspect private evidence')
        report=json.loads((evidence/'standard-result.local.json').read_text())
        if report['status']!='PASS' or not report['cleanup'] or any(r['status']!='PASS' for r in report['cleanup']):raise RuntimeError('STANDARD qualification incomplete')
    finally:
        if created:
            subprocess.run(['docker','rm','-fv',name],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    print(json.dumps({'P2_STANDARD_COMPATIBILITY':'PASS'}))


if __name__=='__main__':main()
