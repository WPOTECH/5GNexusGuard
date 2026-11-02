"""Install narrow include references without replacing operator policy content."""
import fcntl
import os
from pathlib import Path
import stat
import subprocess


def include(path, line):
    path=Path(path)
    for parent in path.parents:
        st=parent.lstat()
        if (not stat.S_ISDIR(st.st_mode) or parent.resolve()!=parent or st.st_uid!=0
                or st.st_mode&0o022 and not st.st_mode&stat.S_ISVTX):
            raise ValueError('unsafe AppArmor policy ancestor')
    fd=os.open(path,os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o644)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        st=os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_nlink!=1 or st.st_mode&0o022 or st.st_size>65536:
            raise ValueError('unsafe AppArmor local policy')
        data=path.read_bytes()
        if line.encode() not in data.splitlines():
            data=b'\n'+line.encode()+b'\n'
            while data:
                written=os.write(fd,data)
                if written<=0:raise OSError('short policy write')
                data=data[written:]
            os.fsync(fd)
    finally:os.close(fd)


def main():
    if os.geteuid()!=0:raise ValueError('root package configuration required')
    root=Path('/etc/apparmor.d')
    for profile,fragment in (('usr.lib.ipsec.charon','5gnexusguard-native-charon'),('usr.sbin.swanctl','5gnexusguard-native-swanctl')):
        if not (root/profile).is_file():raise ValueError('required strongSwan profile missing')
        include(root/'local'/profile,'#include if exists <local/'+fragment+'>')
        subprocess.run(['apparmor_parser','-r',str(root/profile)],check=True)


if __name__=='__main__':main()
