"""Private virtio-serial management for only this disposable VM lab."""
import base64
import ctypes
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time

BASE=Path('/state')
IMAGE='dl-ipsec-isolated-evidence:probe'
IMAGE_ID='sha256:ecd5c54a5243526f0fde27f061fca30a13e5911e855f6108b348f4b8787ce54e'
CAPS=('NET_ADMIN','NET_RAW','BPF','PERFMON','SYS_ADMIN','NET_BIND_SERVICE','SETUID','SETGID')


def boot_id():return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def write_json(channel, item):
    pending=memoryview((json.dumps(item)+'\n').encode())
    while pending:
        written=channel.write(pending)
        if not written or written>len(pending):raise OSError('guest control short-write failure')
        pending=pending[written:]


def docker_ready():
    for _ in range(60):
        r=subprocess.run(['docker','info'],capture_output=True)
        if r.returncode==0:return
        (BASE/'evidence/docker-readiness.local.stderr').write_bytes(r.stderr)
        time.sleep(1)
    raise RuntimeError('guest Docker daemon unavailable')


def main():
    os.umask(0o077)
    lab=Path('/etc/mesh-lab-id').read_text().strip()
    if boot_id()==Path('/etc/mesh-host-boot-id').read_text().strip():
        raise RuntimeError('refusing operation on host kernel')
    if (BASE/'.mesh-lab-id').read_text().strip()!=lab:raise RuntimeError('wrong guest state disk')
    if {p.name for p in Path('/sys/class/net').iterdir()}!={'lo'}:
        raise RuntimeError('guest unexpectedly has a network adapter')
    docker_ready()
    probe=subprocess.run(['docker','image','inspect',IMAGE],capture_output=True)
    if probe.returncode:
        with Path('/opt/mesh/test-image.tar').open('rb') as stream:
            subprocess.run(['docker','load'],stdin=stream,check=True,stdout=subprocess.DEVNULL)
    actual=subprocess.check_output(['docker','image','inspect',IMAGE,'--format','{{.Id}}'],text=True).strip()
    if actual!=IMAGE_ID:raise RuntimeError('guest test image differs from reviewed image')
    count_file=BASE/'boot-count'
    count=int(count_file.read_text())+1 if count_file.exists() else 1
    count_file.write_text(str(count)+'\n')
    info=dict(lab_id=lab,boot_id=boot_id(),boot_count=count,uptime=Path('/proc/uptime').read_text().split()[0])
    (BASE/'evidence'/f'boot-{count}.json').write_text(json.dumps(info))
    os.sync()
    paths=[]
    for _ in range(60):
        paths=[p for p in Path('/sys/class/virtio-ports').glob('*/name')
               if p.read_text().strip()=='org.5gnexus.reboot-control']
        if paths:break
        time.sleep(1)
    if len(paths)!=1:raise RuntimeError('private virtio control channel absent')
    port=Path('/dev')/paths[0].parent.name
    jobs={}
    with port.open('r+b',buffering=0) as channel:
        while True:
            line=channel.readline()
            if not line:time.sleep(.05);continue
            request=json.loads(line)
            try:
                if request.get('lab_id')!=lab:raise ValueError('lab identity mismatch')
                action=request['action'];answer=dict(info,action=action)
                if action=='status':
                    answer['jobs']={k:p.poll() for k,p in jobs.items()}
                    for name in ('before-ready.json','after-result.json'):
                        p=BASE/'evidence'/name
                        if p.exists():answer[name]=json.loads(p.read_text())
                elif action in ('before','after'):
                    if action in jobs:raise ValueError('phase already started this boot')
                    if (action=='before' and count!=1) or (action=='after' and count<2):raise ValueError('wrong boot for phase')
                    args=['docker','run','--rm','--name','mesh-reboot-'+action,'--network','none','--cap-drop','ALL']
                    for cap in CAPS:args+=['--cap-add',cap]
                    args+=['--security-opt','apparmor=unconfined','--pids-limit','256','--memory','2g',
                           '-e','DL_IPSEC_ISOLATED=1','-e','MESH_REBOOT_PHASE='+action,
                           '--mount','type=bind,src=/opt/mesh/src,dst=/lab/src,readonly',
                           '--mount','type=bind,src=/opt/mesh/java,dst=/lab/java,readonly',
                           '--mount','type=bind,src=/state/private,dst=/lab/reboot-private',
                           '--mount','type=bind,src=/state/evidence,dst=/lab/evidence',
                           '--mount','type=tmpfs,dst=/lab/private,tmpfs-mode=0700',
                           '-w','/lab/src',IMAGE,'/usr/bin/python3','-B',
                           '/lab/src/scripts/ipsec-dual/reboot_vm/reboot_container.py']
                    (BASE/'evidence'/f'{action}-invocation.local.json').write_text(json.dumps(args))
                    with (BASE/'evidence'/f'{action}-console.local.log').open('wb') as log:
                        jobs[action]=subprocess.Popen(args,stdout=log,stderr=log)
                    answer['pid']=jobs[action].pid
                elif action=='reboot':
                    ready=BASE/'evidence/before-ready.json'
                    if count!=1 or not ready.exists() or json.loads(ready.read_text())['boot_id']!=boot_id():
                        raise ValueError('authorized pre-reboot checkpoint absent')
                    os.sync()
                    checkpoint=json.loads(ready.read_text())
                    if time.clock_gettime_ns(time.CLOCK_BOOTTIME)>=checkpoint['grant']['deadline_ns']:
                        raise ValueError('authorization already expired before guest reboot')
                    write_json(channel,dict(answer,rebooting=True,
                        reboot_request_boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME)))
                    rc=ctypes.CDLL(None,use_errno=True).reboot(0x01234567)
                    raise RuntimeError('guest reboot syscall returned '+str(rc))
                elif action=='export':
                    memory=io.BytesIO()
                    with tarfile.open(fileobj=memory,mode='w:gz') as archive:
                        archive.add(BASE/'evidence',arcname='evidence')
                    answer['evidence_tar_base64']=base64.b64encode(memory.getvalue()).decode()
                else:raise ValueError('unknown fixed lab operation')
                write_json(channel,answer)
            except Exception as exc:
                write_json(channel,{'error':type(exc).__name__+': '+str(exc)})


if __name__=='__main__':main()
