#!/usr/bin/env python3
"""Run one approved, offline, disposable KVM reboot lab; never manage libvirt VMs."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import time

KERNEL=Path('/home/wpotech/.hermes/cache/scratch/mesh-reboot-kernel-stage/vmlinuz')
KERNEL_SHA256='9f55ef7253055a9cf68f8a04323c93dead2fca617386d842fbde9ca7b178b27e'


def host_snapshot():
    def read(argv):return subprocess.check_output(argv,text=True).strip()
    return {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'links':read(['ip','-j','link','show']),
            'addresses':read(['ip','-j','address','show']),
            'routes':read(['ip','-j','route','show','table','all']),
            'rules':read(['ip','-j','rule','show']),
            'vms':read(['virsh','-c','qemu:///system','list','--all'])}


def configured_network(snapshot):
    # Interface counters and address lifetimes advance without configuration writes.
    result={k:snapshot[k] for k in ('boot_id','routes','rules','vms')}
    for name in ('links','addresses'):
        rows=json.loads(snapshot[name])
        for row in rows:
            row.pop('stats64',None);row.pop('stats',None)
            for addr in row.get('addr_info',[]):
                addr.pop('valid_life_time',None);addr.pop('preferred_life_time',None)
        result[name]=rows
    return result


def qualification_complete(report):
    return (report.get('packet_checks')=='PASS' and report.get('evidence_exported') is True and
            report.get('guest_stopped') is True and report.get('qemu_exit_code')==0 and
            not report.get('shutdown_error') and report.get('host_network_unchanged') is True and
            report.get('after',{}).get('cleanup')=='PASS')


class Control:
    def __init__(self,path,lab):self.path=path;self.lab=lab;self.socket=None;self.buffer=b''
    def close(self):
        if self.socket:self.socket.close()
        self.socket=None;self.buffer=b''
    def ask(self,action,timeout=10):
        if self.socket is None:
            self.socket=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.socket.connect(str(self.path))
        self.socket.sendall((json.dumps(dict(lab_id=self.lab,action=action))+'\n').encode())
        end=time.monotonic()+timeout
        while b'\n' not in self.buffer:
            if not select.select([self.socket],[],[],max(0,end-time.monotonic()))[0]:raise TimeoutError('guest control reply timed out')
            chunk=self.socket.recv(65536)
            if not chunk:raise EOFError('guest control disconnected')
            self.buffer+=chunk
            if len(self.buffer)>128*1024**2:raise RuntimeError('guest reply exceeds evidence limit')
        line,self.buffer=self.buffer.split(b'\n',1);reply=json.loads(line)
        if 'error' in reply:raise RuntimeError('guest action failed: '+reply['error'])
        if reply['lab_id']!=self.lab:raise RuntimeError('guest lab identity mismatch')
        return reply


def quit_owned_guest(path,process):
    if process.poll() is not None:return
    # This socket is inside our fresh mode-0700 directory and belongs to the
    # process launched below. No libvirt domain or host process lookup is used.
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as qmp:
        qmp.settimeout(5);qmp.connect(str(path))
        with qmp.makefile('rwb',buffering=0) as stream:
            json.loads(stream.readline())
            for command in ('qmp_capabilities','quit'):
                stream.write((json.dumps({'execute':command})+'\n').encode())
                while True:
                    reply=json.loads(stream.readline())
                    if 'return' in reply:break
                    if 'error' in reply:raise RuntimeError('owned VM QMP cleanup failed')
    process.wait(timeout=15)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory',type=Path,required=True)
    parser.add_argument('--parent-approved',action='store_true')
    args=parser.parse_args()
    if not args.parent_approved:parser.error('explicit operator approval required')
    os.umask(0o077)
    directory=args.directory.resolve();manifest=json.loads((directory/'manifest.json').read_text())
    if manifest['directory']!=str(directory) or manifest['state']!='PREPARED_KERNEL_COPY_AND_BOOT_REQUIRE_APPROVAL':
        parser.error('fresh prepared disposable lab required')
    if directory.stat().st_uid!=os.getuid() or directory.stat().st_mode&0o077:
        parser.error('private owned directory required')
    if hashlib.sha256(KERNEL.read_bytes()).hexdigest()!=KERNEL_SHA256:
        parser.error('staged kernel differs from inspected local kernel')
    image=directory/'initramfs.cpio.gz'
    if hashlib.sha256(image.read_bytes()).hexdigest()!=manifest['initramfs_sha256']:
        parser.error('prepared initramfs integrity mismatch')
    if (directory/'qemu.pid').exists():parser.error('refusing reused VM runtime')
    shutil.copyfile(KERNEL,directory/'vmlinuz');(directory/'vmlinuz').chmod(0o600)
    before=host_snapshot();(directory/'host-before.local.json').write_text(json.dumps(before,indent=2))
    argv=['qemu-system-x86_64','-nodefaults','-no-user-config','-machine','q35,accel=kvm',
          '-cpu','host','-smp','4','-m','6144','-name','mesh-reboot-'+manifest['lab_id'][:12],
          '-kernel',str(directory/'vmlinuz'),'-initrd',str(image),
          '-append','console=ttyS0 init=/init panic=-1 apparmor=0',
          '-drive','file='+str(directory/'state.raw')+',format=raw,if=virtio,cache=writeback',
          '-nic','none','-display','none','-monitor','none',
          '-serial','file:'+str(directory/'serial.local.log'),
          '-qmp','unix:'+str(directory/'qmp.sock')+',server=on,wait=off',
          '-device','virtio-serial-pci','-chardev','socket,id=ctl,path='+str(directory/'control.sock')+',server=on,wait=off',
          '-device','virtserialport,chardev=ctl,name=org.5gnexus.reboot-control',
          '-pidfile',str(directory/'qemu.pid')]
    (directory/'qemu-invocation.local.json').write_text(json.dumps(argv,indent=2))
    report={'status':'FAIL','kernel_sha256':KERNEL_SHA256,'baseline':manifest['git_commit']}
    control=Control(directory/'control.sock',manifest['lab_id']);process=None
    def status_wait(predicate,timeout):
        end=time.monotonic()+timeout
        while time.monotonic()<end:
            if process.poll() is not None:raise RuntimeError('owned QEMU exited; inspect private serial/stderr logs')
            try:state=control.ask('status',timeout=2)
            except (OSError,TimeoutError,EOFError):control.close();time.sleep(.2);continue
            if predicate(state):return state
            for phase,code in state.get('jobs',{}).items():
                if code is not None and code!=0:raise RuntimeError('guest '+phase+' test failed (exit '+str(code)+'); inspect exported private evidence')
            time.sleep(.05)
        raise TimeoutError('guest phase did not reach required checkpoint')
    try:
        with (directory/'qemu.stderr.local.log').open('wb') as log:process=subprocess.Popen(argv,stdout=log,stderr=log)
        report['pid']=process.pid
        initial=status_wait(lambda s:s['boot_count']==1,180)
        report['first_boot']=initial
        control.ask('before')
        ready=status_wait(lambda s:'before-ready.json' in s,180)
        report['before']=ready['before-ready.json']
        report['reboot_request']=control.ask('reboot');control.close()
        next_boot=status_wait(lambda s:s['boot_count']==2,180)
        if next_boot['boot_id']==initial['boot_id']:raise RuntimeError('kernel boot identity unchanged')
        report['second_boot']=next_boot
        control.ask('after')
        done=status_wait(lambda s:s.get('jobs',{}).get('after')==0 and 'after-result.json' in s,180)
        report['after']=done['after-result.json']
        if report['after']['status']!='PASS':raise RuntimeError('post-reboot packet verdict failed')
        report['packet_checks']='PASS'
    except BaseException as exc:
        report['failure']={'type':type(exc).__name__,'message':str(exc)}
        raise
    finally:
        try:
            if process is not None and process.poll() is None:
                try:
                    exported=control.ask('export',timeout=30)
                    (directory/'evidence.local.tar.gz').write_bytes(base64.b64decode(exported['evidence_tar_base64'],validate=True))
                    report['evidence_exported']=True
                except Exception as exc:report['evidence_export_error']=type(exc).__name__
                try:quit_owned_guest(directory/'qmp.sock',process)
                except Exception as exc:
                    report['shutdown_error']=type(exc).__name__
                    # Popen identifies exactly our child, never an existing VM.
                    process.terminate()
                    try:process.wait(timeout=10)
                    except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
                report['guest_stopped']=process.poll() is not None
                report['qemu_exit_code']=process.returncode
        finally:
            control.close()
            after=host_snapshot();(directory/'host-after.local.json').write_text(json.dumps(after,indent=2))
            report['host_network_unchanged']=configured_network(before)==configured_network(after)
            if qualification_complete(report):
                report['status']='PASS'
            (directory/'result.local.json').write_text(json.dumps(report,indent=2))
            print(json.dumps({k:report[k] for k in ('status','host_network_unchanged')},sort_keys=True))
    if report['status']!='PASS':raise RuntimeError('VM qualification incomplete; inspect private result and evidence')


if __name__=='__main__':main()
