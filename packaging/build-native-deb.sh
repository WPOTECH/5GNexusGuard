#!/usr/bin/env bash
# Isolated-service add-on only; no activation, credentials or production admission.
set -euo pipefail
umask 077
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:?usage: build-native-deb.sh NEW_ABSOLUTE_OUTPUT_DIRECTORY}
[[ $out = /* && ! -e $out && $out != "$repo/"* ]] || exit 2
out=$(realpath -m "$out")
[[ $out != "$repo" && $out != "$repo/"* && ! -e $out ]] || exit 2
mkdir -m 700 "$out"
image=dl-ipsec-isolated-evidence:probe
[[ $(docker image inspect "$image" --format '{{.Id}}') = sha256:ecd5c54a5243526f0fde27f061fca30a13e5911e855f6108b348f4b8787ce54e ]] || exit 2
root="$out/package"
mkdir -p "$root/DEBIAN" "$root/opt/defenderlink/native" "$root/usr/lib/systemd/system" "$root/etc/apparmor.d/local"
for module in native config issuance_v2 admission_v2 authorization_aa_v2 native_control_v2 kernel_gate_publisher_v2 external_gateway; do
 install -m 0644 "$repo/scripts/ipsec-dual/$module.py" "$root/opt/defenderlink/native/$module.py"
done
install -m 0644 "$repo/packaging/linux/native_runtime.py" "$root/opt/defenderlink/native/installed_runtime.py"
install -m 0644 "$repo/packaging/linux/native_apparmor.py" "$root/opt/defenderlink/native/apparmor_setup.py"
cat >"$root/etc/apparmor.d/local/5gnexusguard-native-charon" <<'EOF'
# Dedicated root-private installed transport state; no unrelated key access.
/var/lib/defenderlink-native/transport-*/{e,o}/strongswan.conf r,
/var/lib/defenderlink-native/transport-*/{e,o}/vici rw,
EOF
cat >"$root/etc/apparmor.d/local/5gnexusguard-native-swanctl" <<'EOF'
/var/lib/defenderlink-native/transport-*/{e,o}/swanctl.conf r,
/var/lib/defenderlink-native/transport-*/{e,o}/{private,x509,x509ca}/ r,
/var/lib/defenderlink-native/transport-*/{e,o}/{private,x509,x509ca}/* r,
/var/lib/defenderlink-native/transport-*/{e,o}/vici rw,
EOF
install -m 0644 "$repo"/packaging/systemd/defenderlink-native-*.service "$root/usr/lib/systemd/system/"
docker run --rm --network none --cap-drop ALL --user "$(id -u):$(id -g)" \
 --mount "type=bind,src=$repo/scripts/ipsec-dual,dst=/source,readonly" \
 --mount "type=bind,src=$root/opt/defenderlink/native,dst=/output" \
 "$image" clang -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu \
 -c /source/kernel_gate_v2.bpf.c -o /output/kernel_gate_v2.bpf.o
version="1.0.0+p2.git$(git -C "$repo" rev-parse --short HEAD)"
arch=$(dpkg --print-architecture)
cat >"$root/DEBIAN/control" <<EOF
Package: defenderlink-native-prototype
Version: $version
Section: net
Priority: optional
Architecture: $arch
Depends: defenderlink-mesh, python3-cryptography, iproute2, wireguard-tools, strongswan-charon, strongswan-swanctl, libstrongswan-standard-plugins, nftables, bpftool, iputils-ping, apparmor
Maintainer: WPO Tech <support@wpotech.com>
Description: 5GNexusGuard explicitly provisioned isolated native services
 Explicit isolated KVM guest only. Production admission remains disabled.
EOF
cat >"$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = configure ]; then
 for path in /etc/defenderlink/native /var/lib/defenderlink-native; do
  if [ -e "$path" ] || [ -L "$path" ]; then
   [ ! -L "$path" ] && [ -d "$path" ] && [ "$(stat -c %u "$path")" = 0 ] && [ "$(stat -c %a "$path")" = 700 ] || exit 1
  else
   install -d -m 0700 -o root -g root "$path"
  fi
 done
 python3 /opt/defenderlink/native/apparmor_setup.py
 systemctl daemon-reload
fi
EOF
cat >"$root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = remove ] || [ "$1" = upgrade ]; then
 for role in supervisor exporter aa; do
  systemctl stop "defenderlink-native-$role.service"
 done
fi
EOF
cat >"$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = remove ] || [ "$1" = purge ]; then
 for profile in usr.lib.ipsec.charon usr.sbin.swanctl; do
  if [ -f "/etc/apparmor.d/$profile" ]; then
   apparmor_parser -r "/etc/apparmor.d/$profile"
  fi
 done
 systemctl daemon-reload
fi
EOF
chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"
find "$root" -type d -exec chmod 0755 {} +
file="$out/defenderlink-native-prototype_${version}_${arch}.deb"
dpkg-deb --build --root-owner-group "$root" "$file" >"$out/build.local.log" 2>&1
sha256sum "$file" >"$out/SHA256SUMS"
printf 'Built %s\n' "$file"
