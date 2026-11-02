#!/usr/bin/env python3
"""Approved installed-service acceptance in a new NIC-free overlay, never a libvirt VM.

Packages/dependencies must already exist locally. The observer provisions test
PKI, approves exact scoped grants and observes services; it does not implement
or replace their transport, signer, AA, supervisor or kernel gate.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tarfile


def qualification(result):
    guest=result.get('guest_result',{})
    required=('persisted live Java identity','mTLS node key matches actual Java identity',
        'authorized installed nested TCP','direct underlay physical bypass denial',
        'established and new TCP denied after signed disconnect','revocation denial before original expiry',
        'old TCP denied after installed service stop','owned namespaces and pins removed',
        'restart stays denied before fresh operator recovery','fresh authority restores installed protected TCP')
    clean=[value for name,value in guest.get('checks',{}).items() if name.startswith('clean capture ')]
    return (len(clean)==14 and all(value=='PASS' for value in clean)
        and set(guest.get('packet_counts',{}))=={'initial','recovery-'}
        and result.get('qemu_exit_code')==0 and result.get('guest_stopped') is True
        and result.get('host_configuration_unchanged') is True and guest.get('status')=='PASS'
        and all(guest.get('checks',{}).get(name)=='PASS' for name in required)
        and not guest.get('namespaces_after','missing').strip() and guest.get('pins_after') is False
        and result.get('baseline_disk_unchanged') is True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--parent-approved',action='store_true')
    for name in ('disk','base','native','dependencies','evidence'):
        parser.add_argument('--'+name,required=True,type=Path)
    args=parser.parse_args()
    if not args.parent_approved:parser.error('explicit scoped runtime approval required')
    repo=Path(__file__).resolve().parents[2]
    p=args.evidence.resolve()
    if not args.evidence.is_absolute() or p.exists() or p==repo or repo in p.parents or ',' in str(p):
        parser.error('fresh absolute private evidence path outside repository required')
    disk=args.disk.resolve(strict=True)
    if not disk.is_file() or ',' in str(disk):parser.error('local stopped baseline disk required')
    for path,name in ((args.base,'defenderlink-mesh'),(args.native,'defenderlink-native-prototype')):
        if not path.is_file() or subprocess.check_output(['dpkg-deb','-f',str(path),'Package'],text=True).strip()!=name:
            parser.error('explicit matching base and native add-on packages required')
    deps=sorted(args.dependencies.glob('*.deb'))
    if not deps:parser.error('prepared offline dependency directory required')
    os.umask(0o077);p.mkdir(mode=0o700);seed=p/'seed';seed.mkdir(mode=0o700)
    for path,name in ((args.base,'base.deb'),(args.native,'native.deb')):shutil.copy2(path,seed/name)
    (seed/'dependencies').mkdir(mode=0o700)
    for path in deps:shutil.copy2(path,seed/'dependencies'/path.name)
    hashes={}
    for path in seed.rglob('*.deb'):
        subprocess.run(['dpkg-deb','--fsys-tarfile',str(path)],check=True,stdout=subprocess.DEVNULL)
        hashes[str(path.relative_to(seed))]=hashlib.sha256(path.read_bytes()).hexdigest()
    (seed/'package-hashes.json').write_text(json.dumps(hashes,indent=2))
    shutil.copy2(Path(__file__).with_name('installed_dual_operator.py'),seed/'deploy.py')
    (seed/'echo.py').write_text('''import socketserver
class Handler(socketserver.BaseRequestHandler):
 def handle(self):
  while True:
   data=self.request.recv(4096)
   if not data:return
   self.request.sendall(data)
socketserver.ThreadingTCPServer(('10.80.0.2',8080),Handler).serve_forever()
''')
    (seed/'meta-data').write_text('instance-id: nexusguard-installed-dual-'+secrets.token_hex(8)+'\nlocal-hostname: guard-installed-dual\n')
    (seed/'user-data').write_text('''#cloud-config
package_update: false
package_upgrade: false
runcmd:
  - [mkdir, -p, /mnt/p2]
  - [mount, -o, ro, /dev/sr0, /mnt/p2]
  - [python3, /mnt/p2/deploy.py]
''')
    subprocess.run(['xorriso','-as','mkisofs','-quiet','-o',str(p/'seed.iso'),'-V','cidata','-J','-r',str(seed)],check=True)
    before_hash=hashlib.sha256(disk.read_bytes()).hexdigest()
    (p/'build-input.local.json').write_text(json.dumps(dict(baseline_disk=str(disk),baseline_sha256=before_hash,
        git_head=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip(),packages=hashes),indent=2))
    subprocess.run(['qemu-img','create','-f','qcow2','-F','qcow2','-b',str(disk),str(p/'guest.qcow2')],check=True)
    sys.path.insert(0,str(repo/'scripts/ipsec-dual/reboot_vm'))
    from run_guest import host_snapshot,configured_network,quit_owned_guest
    before=host_snapshot();(p/'host-before-launch.local.json').write_text(json.dumps(before,indent=2))
    command=['qemu-system-x86_64','-enable-kvm','-machine','q35','-cpu','host','-smp','4','-m','4096',
        '-display','none','-no-reboot','-drive','file='+str(p/'guest.qcow2')+',if=virtio,format=qcow2',
        '-drive','file='+str(p/'seed.iso')+',media=cdrom,readonly=on','-nic','none',
        '-serial','file:'+str(p/'serial.local.log'),'-qmp','unix:'+str(p/'qmp.sock')+',server=on,wait=off',
        '-device','virtio-rng-pci']
    (p/'qemu-invocation.local.json').write_text(json.dumps(command,indent=2))
    child=None;result={'status':'FAIL'}
    try:
        with (p/'qemu.stderr.local.log').open('wb') as log:
            child=subprocess.Popen(command,stdout=log,stderr=log)
            result['qemu_pid']=child.pid;result['qemu_exit_code']=child.wait(timeout=600)
        raw=(p/'serial.local.log').read_text(errors='replace')
        encoded=raw.split('P2_VM_EVIDENCE_BEGIN\n',1)[1].split('P2_VM_EVIDENCE_END',1)[0].strip()
        archive=base64.b64decode(encoded,validate=True)
        if len(archive)>32*1024*1024:raise ValueError('evidence transport size exceeded')
        output=p/'guest-evidence';output.mkdir(mode=0o700)
        with tarfile.open(fileobj=io.BytesIO(archive),mode='r:gz') as tar:tar.extractall(output,filter='data')
        result['guest_result']=json.loads((output/'result.local.json').read_text())
    except Exception as exc:result['failure']={'type':type(exc).__name__,'message':str(exc)}
    finally:
        if child and child.poll() is None:quit_owned_guest(p/'qmp.sock',child)
        result['guest_stopped']=child is not None and child.poll() is not None
        if child:result['qemu_exit_code']=child.returncode
        after=host_snapshot();(p/'host-after.local.json').write_text(json.dumps(after,indent=2))
        result['raw_host_snapshots_equal']=before==after
        result['host_configuration_unchanged']=configured_network(before)==configured_network(after)
        result['baseline_disk_unchanged']=hashlib.sha256(disk.read_bytes()).hexdigest()==before_hash
        if qualification(result):result['status']='PASS'
        (p/'result.local.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(dict(P2_INSTALLED_NATIVE=result['status'],evidence=str(p))))
    return 0 if result['status']=='PASS' else 1


if __name__=='__main__':sys.exit(main())
