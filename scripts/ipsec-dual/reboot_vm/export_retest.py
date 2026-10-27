#!/usr/bin/env python3
"""One operational export retest. Never invokes P1 packet or authorization cases.

Prepare clones ONLY the recorded disposable lab disk and updates its private
control agent. Run boots that clone with no NIC; fixed actions are status/export.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time

if __package__:
    from .run_guest import Control, KERNEL, KERNEL_SHA256, host_snapshot, configured_network, quit_owned_guest
else:
    from run_guest import Control, KERNEL, KERNEL_SHA256, host_snapshot, configured_network, quit_owned_guest


def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
    return digest.hexdigest()


def prepare(source, directory, evidence):
    if directory.exists() or directory==source or source in directory.parents:
        raise ValueError('new separate private directory required')
    manifest=json.loads((source/'manifest.json').read_text())
    prior=json.loads((evidence/'result.local.json').read_text())
    if (manifest['directory']!=str(source) or not prior.get('guest_stopped') or
            prior.get('qemu_exit_code')!=0 or prior.get('packet_checks')!='PASS'):
        raise ValueError('only the stopped, recorded disposable reboot lab may be cloned')
    if (source/'qemu.pid').exists():raise ValueError('prior VM may be active')
    if sha(source/'initramfs.cpio.gz')!=manifest['initramfs_sha256']:
        raise ValueError('original prepared appliance integrity differs')
    if sha(KERNEL)!=KERNEL_SHA256:raise ValueError('staged trusted kernel differs')
    if shutil.disk_usage(directory.parent).free<20*1024**3:raise ValueError('20 GiB spare required')
    directory.mkdir(mode=0o700)
    # Private test disk only, no access to libvirt storage or any existing VM.
    subprocess.run(['cp','--sparse=always',str(source/'state.raw'),str(directory/'state.raw')],check=True)
    (directory/'state.raw').chmod(0o600)
    shutil.copyfile(KERNEL,directory/'vmlinuz');(directory/'vmlinuz').chmod(0o600)
    # The source is this lab's own hash-verified curated archive, not an
    # untrusted installation image; extract only into a fresh private directory.
    with tempfile.TemporaryDirectory(prefix='mesh-export-bootstrap-') as temporary:
        root=Path(temporary)
        unzip=subprocess.Popen(['gzip','-dc',str(source/'initramfs.cpio.gz')],stdout=subprocess.PIPE)
        with (directory/'cpio-extract.local.log').open('wb') as log:
            extract=subprocess.run(['cpio','-id','--no-absolute-filenames','--no-preserve-owner'],
                                   cwd=root,stdin=unzip.stdout,stdout=log,stderr=log)
        unzip.stdout.close()
        if unzip.wait() or extract.returncode:raise ValueError('offline appliance extraction failed')
        shutil.copyfile(Path(__file__).with_name('guest_agent.py'),root/'opt/mesh/guest_agent.py')
        names=[b'.']+[str(p.relative_to(root)).encode() for p in root.rglob('*')]
        with (directory/'initramfs.cpio.gz').open('wb') as stream:
            cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=root,
                                  stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            gzip=subprocess.Popen(['gzip','-1'],stdin=cpio.stdout,stdout=stream);cpio.stdout.close()
            cpio.stdin.write(b'\0'.join(names)+b'\0');cpio.stdin.close()
            errors=cpio.stderr.read();cpio.wait()
            if gzip.wait() or cpio.returncode:raise ValueError('updated offline appliance packing failed')
    meta=dict(lab_id=manifest['lab_id'],source=str(source),directory=str(directory),
              purpose='EXPORT_ONLY_NO_PACKET_CASES',kernel_sha256=KERNEL_SHA256,
              initramfs_sha256=sha(directory/'initramfs.cpio.gz'),
              agent_sha256=sha(Path(__file__).with_name('guest_agent.py')),
              source_disk_sha256=sha(directory/'state.raw'))
    (directory/'export-manifest.local.json').write_text(json.dumps(meta,indent=2))
    # Explicit expected evidence comes from the independently audited first run.
    audit=json.loads((evidence/'offline-audit.local.json').read_text())
    (directory/'expected-artifacts.local.json').write_text(json.dumps(audit['artifact_sha256'],indent=2))
    print(json.dumps({'prepared':str(directory),'purpose':meta['purpose'],'cpus':4,'memory_mib':6144,'network':'NONE'}))


def verify_export(archive_bytes,expected):
    # Read only; never extract paths/symlinks from the guest's tar on the host.
    with tarfile.open(fileobj=io.BytesIO(archive_bytes),mode='r:gz') as archive:
        members=archive.getmembers();names=[m.name for m in members]
        if len(names)!=len(set(names)):raise ValueError('duplicate export members')
        for name in names:
            p=Path(name)
            if p.is_absolute() or '..' in p.parts:raise ValueError('unsafe export path')
        checked=0
        for name,digest in expected.items():
            # These two files legitimately change when the guest agent/daemon
            # starts. Original copies remain in the first qualification evidence.
            if name in ('evidence/dockerd.local.log','evidence/guest-agent.local.log'):continue
            member=archive.getmember(name)
            if not member.isfile() or member.size>16*1024**2:raise ValueError('export member ABI/size differs')
            stream=archive.extractfile(member)
            if hashlib.sha256(stream.read()).hexdigest()!=digest:raise ValueError('retained packet artifact changed')
            checked+=1
    return checked


def execute(directory):
    meta=json.loads((directory/'export-manifest.local.json').read_text())
    if meta['directory']!=str(directory) or meta['purpose']!='EXPORT_ONLY_NO_PACKET_CASES':raise ValueError('wrong lab')
    for name,key in (('vmlinuz','kernel_sha256'),('initramfs.cpio.gz','initramfs_sha256'),('state.raw','source_disk_sha256')):
        if sha(directory/name)!=meta[key]:raise ValueError('prepared export lab changed')
    if (directory/'qemu.pid').exists() or (directory/'export-result.local.json').exists():raise ValueError('one execution only')
    before=host_snapshot();(directory/'host-before.local.json').write_text(json.dumps(before,indent=2))
    argv=['qemu-system-x86_64','-nodefaults','-no-user-config','-machine','q35,accel=kvm',
          '-cpu','host','-smp','4','-m','6144','-name','mesh-p2-export-'+meta['lab_id'][:8],
          '-kernel',str(directory/'vmlinuz'),'-initrd',str(directory/'initramfs.cpio.gz'),
          '-append','console=ttyS0 init=/init panic=-1 apparmor=0',
          '-drive','file='+str(directory/'state.raw')+',format=raw,if=virtio,cache=writeback',
          '-nic','none','-display','none','-monitor','none','-serial','file:'+str(directory/'serial.local.log'),
          '-qmp','unix:'+str(directory/'qmp.sock')+',server=on,wait=off',
          '-device','virtio-serial-pci','-chardev','socket,id=ctl,path='+str(directory/'control.sock')+',server=on,wait=off',
          '-device','virtserialport,chardev=ctl,name=org.5gnexus.reboot-control','-pidfile',str(directory/'qemu.pid')]
    (directory/'qemu-invocation.local.json').write_text(json.dumps(argv,indent=2))
    report={'status':'FAIL','purpose':meta['purpose']};process=None
    control=Control(directory/'control.sock',meta['lab_id'])
    try:
        with (directory/'qemu.stderr.local.log').open('wb') as log:process=subprocess.Popen(argv,stdout=log,stderr=log)
        end=time.monotonic()+180
        while True:
            if process.poll() is not None:raise RuntimeError('owned export guest exited')
            try:
                state=control.ask('status',timeout=2)
                if state['boot_count']<3:raise ValueError('not a retained-state operational reboot')
                report['boot_id']=state['boot_id'];report['boot_count']=state['boot_count'];break
            except (OSError,EOFError,TimeoutError):
                control.close()
                if time.monotonic()>end:raise TimeoutError('export guest readiness timed out')
                time.sleep(.2)
        begin=time.monotonic_ns();reply=control.ask('export',timeout=30)
        payload=base64.b64decode(reply['evidence_tar_base64'],validate=True)
        (directory/'evidence.local.tar.gz').write_bytes(payload)
        report.update(export_elapsed_ns=time.monotonic_ns()-begin,export_bytes=len(payload),
                      matched_original_artifacts=verify_export(payload,json.loads((directory/'expected-artifacts.local.json').read_text())),
                      export_sha256=hashlib.sha256(payload).hexdigest(),export='PASS')
    except BaseException as exc:
        report['failure']={'type':type(exc).__name__,'message':str(exc)};raise
    finally:
        control.close()
        if process is not None and process.poll() is None:
            try:quit_owned_guest(directory/'qmp.sock',process)
            except Exception as exc:
                report['shutdown_error']=type(exc).__name__;process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        report['guest_stopped']=process is not None and process.poll() is not None
        report['qemu_exit_code']=process.returncode if process is not None else None
        after=host_snapshot();(directory/'host-after.local.json').write_text(json.dumps(after,indent=2))
        report['raw_host_snapshots_equal']=configured_network(before)==configured_network(after)
        if report.get('export')=='PASS' and report['guest_stopped'] and report['qemu_exit_code']==0 and not report.get('shutdown_error'):
            report['status']='PASS'
        (directory/'export-result.local.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2))
    if report['status']!='PASS':raise RuntimeError('export operational retest incomplete')


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='action',required=True)
    prep=sub.add_parser('prepare');prep.add_argument('--source',type=Path,required=True);prep.add_argument('--evidence',type=Path,required=True);prep.add_argument('--directory',type=Path,required=True)
    run=sub.add_parser('run');run.add_argument('--directory',type=Path,required=True);run.add_argument('--parent-approved',action='store_true')
    args=p.parse_args();os.umask(0o077)
    if args.action=='prepare':prepare(args.source.resolve(),args.directory.resolve(),args.evidence.resolve())
    elif not args.parent_approved:p.error('fresh explicit operator approval required')
    else:execute(args.directory.resolve())


if __name__=='__main__':main()
