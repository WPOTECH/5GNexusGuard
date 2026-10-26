#!/usr/bin/env python3
"""Prepare an offline disposable VM from local public binaries and reviewed assets.

No sudo, host mount, libvirt mutation, VM launch or reboot is performed here.
The unreadable host kernel is copied separately only after explicit approval.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile

IMAGE = 'dl-ipsec-isolated-evidence:probe'
IMAGE_ID = 'sha256:ecd5c54a5243526f0fde27f061fca30a13e5911e855f6108b348f4b8787ce54e'
KERNEL = '7.0.0-38-generic'


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('--java', required=True, type=Path)
    parser.add_argument('--rebuild-bootstrap', action='store_true',
                        help='rebuild only initramfs after a stopped pre-authorization bootstrap failure')
    args = parser.parse_args()
    os.umask(0o077)
    repo = Path(__file__).resolve().parents[3]
    directory = args.directory.resolve()
    if (directory.exists() and not args.rebuild_bootstrap) or repo == directory or repo in directory.parents:
        parser.error('new private directory outside repository required')
    if shutil.disk_usage(directory.parent).free < 15*1024**3:
        parser.error('at least 15 GiB free space required before preparation')
    image = run(['docker','image','inspect',IMAGE,'--format','{{.Id}}'], capture_output=True, text=True).stdout.strip()
    if image != IMAGE_ID:
        parser.error('reviewed image identity differs')
    for name in ('classes','test-classes','lib'):
        if not (args.java/name).is_dir(): parser.error('compiled scratch Java stage required')
    if args.rebuild_bootstrap:
        previous=json.loads((directory/'manifest.json').read_text())
        failed=json.loads((directory/'result.local.json').read_text())
        if (failed['status']!='FAIL' or not failed.get('guest_stopped') or
                'first_boot' in failed or not failed.get('host_network_unchanged')):
            parser.error('only stopped pre-authorization bootstrap failure may rebuild')
        if previous['directory']!=str(directory) or previous['git_commit']!=run(
                ['git','rev-parse','HEAD'],cwd=repo,capture_output=True,text=True).stdout.strip():
            parser.error('bootstrap lab identity or baseline differs')
        nonce=previous['lab_id']
        archive=directory/'bootstrap-failure-1';archive.mkdir(mode=0o700)
        for name in ('manifest.json','result.local.json','serial.local.log','qemu.stderr.local.log',
                     'host-before.local.json','host-after.local.json','qemu-invocation.local.json'):
            if (directory/name).exists():shutil.copy2(directory/name,archive/name)
        (directory/'initramfs.cpio.gz').rename(archive/'initramfs.cpio.gz')
    else:
        directory.mkdir(mode=0o700)
        nonce = secrets.token_hex(16)
    manifest = dict(lab_id=nonce, directory=str(directory), kernel=KERNEL, image=IMAGE_ID,
                    memory_mib=6144, cpus=4, disk_bytes=12*1024**3,
                    host_boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    git_commit=run(['git','rev-parse','HEAD'],cwd=repo,capture_output=True,text=True).stdout.strip(),
                    state='PREPARING', network='NONE', existing_vm_disks_used=False)
    (directory/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    with tempfile.TemporaryDirectory(prefix='mesh-guest-build-') as temporary:
        root = Path(temporary)/'root'; root.mkdir()
        for name in ('usr/bin','usr/sbin','usr/lib','usr/lib64','etc','dev','proc','sys','run','tmp','state','opt/mesh'):
            (root/name).mkdir(parents=True,exist_ok=True)
        for name,target in (('bin','usr/bin'),('sbin','usr/sbin'),('lib','usr/lib'),('lib64','usr/lib64')):
            (root/name).symlink_to(target)
        seen=set()
        def copy_file(source):
            source=Path(source)
            key=str(source)
            if key in seen: return
            seen.add(key)
            destination=root/key.lstrip('/')
            destination.parent.mkdir(parents=True,exist_ok=True)
            if source.is_symlink():
                if not destination.exists() and not destination.is_symlink():
                    destination.symlink_to(os.readlink(source))
                copy_file(source.resolve())
                return
            shutil.copy2(source,destination)
            with source.open('rb') as stream: magic=stream.read(4)
            if magic != b'\x7fELF': return
            deps=subprocess.run(['ldd',str(source)],capture_output=True,text=True)
            for path in re.findall(r'(?:=>\s*)?(/[^\s()]+)',deps.stdout):
                if Path(path).is_file(): copy_file(path)
        binaries=['/usr/bin/bash','/usr/bin/python3','/usr/bin/docker','/usr/bin/dockerd',
                  '/usr/bin/containerd','/usr/bin/containerd-shim-runc-v2','/usr/bin/runc',
                  '/usr/bin/docker-proxy','/usr/bin/ctr','/usr/libexec/docker/docker-init',
                  '/usr/bin/mount','/usr/bin/umount','/usr/bin/mkdir','/usr/bin/chmod','/usr/bin/ln',
                  '/usr/bin/cat','/usr/bin/sleep','/usr/bin/sync','/usr/bin/hostname',
                  '/usr/sbin/ip','/usr/sbin/modprobe']
        for path in binaries: copy_file(path)
        stdlib=Path('/usr/lib/python3.14')
        shutil.copytree(stdlib,root/str(stdlib).lstrip('/'),dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns('__pycache__'))
        for path in stdlib.rglob('*.so'): copy_file(path)
        shutil.copytree(Path('/lib/modules')/KERNEL,root/'usr/lib/modules'/KERNEL,symlinks=True)
        (root/'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/bin/false\n')
        (root/'etc/group').write_text('root:x:0:\nnogroup:x:65534:\n')
        (root/'etc/hosts').write_text('127.0.0.1 localhost mesh-reboot-lab\n')
        (root/'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\nhosts: files\n')
        (root/'etc/os-release').write_text('NAME="Disposable mesh reboot test appliance"\nID=mesh-reboot-lab\n')
        (root/'etc/mesh-lab-id').write_text(nonce+'\n')
        (root/'etc/mesh-host-boot-id').write_text(manifest['host_boot_id']+'\n')
        bootdir=Path(__file__).resolve().parent
        shutil.copy2(bootdir/'guest_init.sh',root/'init'); (root/'init').chmod(0o755)
        shutil.copy2(bootdir/'guest_agent.py',root/'opt/mesh/guest_agent.py')
        source=root/'opt/mesh/src'; source.mkdir(parents=True)
        tracked=run(['git','ls-files','-z','--','scripts/ipsec-dual'],cwd=repo,capture_output=True).stdout.split(b'\0')
        extras=[str(p.relative_to(repo)) for p in bootdir.glob('*.py')]+[str((bootdir/'guest_init.sh').relative_to(repo))]
        paths=sorted({p.decode() for p in tracked if p}|set(extras))
        hashes={}
        for relative in paths:
            p=repo/relative
            if not p.is_file() or p.suffix in ('.o','.pyc'):continue
            dst=source/relative;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dst)
            hashes[relative]=hashlib.sha256(p.read_bytes()).hexdigest()
        manifest['source_hashes']=hashes
        shutil.copytree(args.java,root/'opt/mesh/java')
        with (root/'opt/mesh/test-image.tar').open('wb') as image_file:
            run(['docker','save',IMAGE],stdout=image_file)
        state=directory/'state.raw'
        if not args.rebuild_bootstrap:
            seed=Path(temporary)/'state-seed';seed.mkdir()
            (seed/'.mesh-lab-id').write_text(nonce+'\n')
            with state.open('xb') as stream:stream.truncate(manifest['disk_bytes'])
            run(['mkfs.ext4','-q','-F','-L','mesh-reboot','-d',str(seed),str(state)])
            state.chmod(0o600)
        names=[b'.']+[str(p.relative_to(root)).encode() for p in root.rglob('*')]
        with (directory/'initramfs.cpio.gz').open('xb') as archive:
            cpio=subprocess.Popen(['cpio','--null','-o','--format=newc','--owner=0:0'],cwd=root,
                                  stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            gzip=subprocess.Popen(['gzip','-1'],stdin=cpio.stdout,stdout=archive)
            cpio.stdout.close()
            cpio.stdin.write(b'\0'.join(names)+b'\0')
            cpio.stdin.close()
            errors=cpio.stderr.read()
            cpio.wait()
            gzip_code=gzip.wait()
            if cpio.returncode or gzip_code:
                raise RuntimeError('initramfs creation failed: '+errors.decode(errors='replace')[-300:])
    manifest['state']='PREPARED_KERNEL_COPY_AND_BOOT_REQUIRE_APPROVAL'
    manifest['initramfs_sha256']=hashlib.sha256((directory/'initramfs.cpio.gz').read_bytes()).hexdigest()
    (directory/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'directory':str(directory),'state':manifest['state'],'cpus':4,'memory_mib':6144,'network':'NONE'}))


if __name__=='__main__':main()
