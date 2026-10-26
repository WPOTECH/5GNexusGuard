#!/bin/bash
# PID 1 in a new, NIC-free guest, never executed on Polaris.
set -eu
[ "$$" = 1 ] || exit 91
[ -f /etc/mesh-lab-id ] || exit 92
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export DOCKER_HOST=unix:///run/docker.sock
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /sys/fs/cgroup
mount -t devpts devpts /dev/pts
mount -t cgroup2 none /sys/fs/cgroup
mount --make-rprivate /
mount -t tmpfs -o mode=0755 tmpfs /run
mount -t tmpfs -o mode=1777 tmpfs /tmp
ln -sf /proc/self/fd /dev/fd
ln -sf /proc/self/fd/0 /dev/stdin
ln -sf /proc/self/fd/1 /dev/stdout
ln -sf /proc/self/fd/2 /dev/stderr
hostname mesh-reboot-disposable
for module in virtio_pci virtio_blk virtio_console ext4 veth tun wireguard nf_tables xfrm_user esp4 xfrm4_tunnel; do
  modprobe "$module" || true
done
for n in {1..60}; do [ -b /dev/vda ] && break; sleep 1; done
mount -t ext4 /dev/vda /state
[ "$(cat /state/.mesh-lab-id)" = "$(cat /etc/mesh-lab-id)" ] || exit 90
mkdir -p /state/evidence /state/private /state/docker
chmod 700 /state/evidence /state/private
ip link set lo up
dockerd --host=unix:///run/docker.sock --pidfile=/run/docker.pid --exec-root=/run/docker \
  --data-root=/state/docker --storage-driver=vfs --bridge=none --iptables=false --ip6tables=false \
  --ip-forward=false --ip-masq=false --userland-proxy=false --exec-opt native.cgroupdriver=cgroupfs \
  --log-level=warn >/state/evidence/dockerd.local.log 2>&1 &
python3 /opt/mesh/guest_agent.py >/state/evidence/guest-agent.local.log 2>&1 &
while :; do sleep 3600 & wait "$!"; done
