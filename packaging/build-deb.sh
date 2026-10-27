#!/usr/bin/env bash
# Build outside the checkout; never rebuild the frontend or touch target/.
set -euo pipefail
umask 077
repo=$(cd "$(dirname "$0")/.." && pwd)
out=${1:?usage: packaging/build-deb.sh NEW_ABSOLUTE_OUTPUT_DIRECTORY}
[[ $out = /* && ! -e $out ]] || { echo 'new absolute output directory required' >&2; exit 2; }
out=$(realpath -m "$out")
[[ $out != "$repo" && $out != "$repo/"* ]] || exit 2
mkdir -m 700 "$out"
python3 - "$repo" "$out/source" <<'PY'
import shutil,sys
from pathlib import Path
repo,dst=map(Path,sys.argv[1:]);dst.mkdir(mode=0o700)
shutil.copy2(repo/'pom.xml',dst/'pom.xml')
for name in ('src','scripts'):
 shutil.copytree(repo/name,dst/name,ignore=shutil.ignore_patterns('__pycache__','*.o'))
PY
mvn -o -B -f "$out/source/pom.xml" -DskipTests -Dquarkus.package.jar.type=uber-jar package >"$out/maven.local.log" 2>&1
jar="$out/source/target/defenderlink-mesh-1.0.0-SNAPSHOT-runner.jar"
[[ -f $jar ]] || { echo 'application runner JAR was not produced' >&2; exit 1; }
version="1.0.0+p2.git$(git -C "$repo" rev-parse --short HEAD)"
arch=$(dpkg --print-architecture)
root="$out/package"
mkdir -p "$root/DEBIAN" "$root/opt/defenderlink/lib" "$root/opt/defenderlink/libexec" \
  "$root/usr/bin" "$root/usr/lib/systemd/system" "$root/etc/defenderlink"
install -m 0644 "$jar" "$root/opt/defenderlink/lib/defenderlink-mesh.jar"
install -m 0755 "$repo/packaging/linux/runtime.py" "$root/opt/defenderlink/libexec/runtime.py"
install -m 0644 "$repo/packaging/systemd/defenderlink-mesh.service" "$root/usr/lib/systemd/system/defenderlink-mesh.service"
cat >"$root/usr/bin/5gnexus" <<'EOF'
#!/bin/sh
exec /usr/bin/python3 /opt/defenderlink/libexec/runtime.py "$@"
EOF
chmod 0755 "$root/usr/bin/5gnexus"
python3 - "$repo" "$root" <<'PY'
import importlib.util,json,sys
from pathlib import Path
repo,root=map(Path,sys.argv[1:])
spec=importlib.util.spec_from_file_location('runtime',repo/'packaging/linux/runtime.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
p=root/'etc/defenderlink/node.json';p.write_text(json.dumps(m.DEFAULT,indent=2)+'\n');p.chmod(0o644)
PY
cat >"$root/DEBIAN/control" <<EOF
Package: defenderlink-mesh
Version: $version
Section: net
Priority: optional
Architecture: $arch
Depends: openjdk-25-jre-headless | openjdk-24-jre-headless, python3 (>= 3.10), iproute2, wireguard-tools
Maintainer: WPO Tech <support@wpotech.com>
Description: 5GNexusGuard experimental Linux operational prototype
 STANDARD node runtime; native production admission remains disabled.
EOF
cat >"$root/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -eu
if [ "$1" = configure ]; then
 getent group defenderlink >/dev/null || groupadd --system defenderlink
 id -u defenderlink >/dev/null 2>&1 || useradd --system --gid defenderlink --no-create-home --home-dir /var/lib/defenderlink --shell /usr/sbin/nologin defenderlink
 # Refuse silently migrating/adopting old deployment state or credential trees.
 for path in /var/lib/defenderlink /etc/wireguard/defenderlink; do
  if [ -e "$path" ] || [ -L "$path" ]; then
   [ ! -L "$path" ] && [ -d "$path" ] && [ "$(stat -c %U "$path")" = defenderlink ] && [ "$(stat -c %a "$path")" = 700 ] || {
    echo 'Existing state requires explicit ownership migration; no data was changed.' >&2; exit 1;
   }
  else
   install -d -m 0700 -o defenderlink -g defenderlink "$path"
  fi
 done
 if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
fi
# No automatic start/enable, global Java setcap, module load, or network writes.
EOF
cat >"$root/DEBIAN/preinst" <<'EOF'
#!/bin/sh
set -eu
# Abort before unpacking/replacing an old installation with incompatible state.
for path in /var/lib/defenderlink /etc/wireguard/defenderlink; do
 if [ -e "$path" ] || [ -L "$path" ]; then
  [ ! -L "$path" ] && [ -d "$path" ] && [ "$(stat -c %U "$path")" = defenderlink ] && [ "$(stat -c %a "$path")" = 700 ] || {
   echo 'Existing state requires explicit ownership migration before installation.' >&2; exit 1;
  }
 fi
done
EOF
cat >"$root/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -eu
if { [ "$1" = remove ] || [ "$1" = upgrade ]; } && [ -d /run/systemd/system ]; then
 systemctl stop defenderlink-mesh.service
fi
EOF
cat >"$root/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -eu
# Identity, ledger, runtime ownership records and WG configurations are retained.
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
EOF
printf '/etc/defenderlink/node.json\n' >"$root/DEBIAN/conffiles"
chmod 0755 "$root/DEBIAN/preinst" "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm"
find "$root" -type d -exec chmod 0755 {} +
file="$out/defenderlink-mesh_${version}_${arch}.deb"
dpkg-deb --build --root-owner-group "$root" "$file" >"$out/dpkg.local.log" 2>&1
sha256sum "$file" >"$out/SHA256SUMS"
printf 'Built %s\n' "$file"
