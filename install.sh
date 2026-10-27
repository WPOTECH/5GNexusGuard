#!/usr/bin/env bash
# Explicit local package installation. Does not start services or alter networking.
set -euo pipefail
package=''
install_deps=false
while (($#)); do
 case "$1" in
  --package) package=${2:?local .deb required}; shift 2 ;;
  --install-deps) install_deps=true; shift ;;
  *) echo 'usage: install.sh --package /absolute/package.deb [--install-deps]' >&2; exit 2 ;;
 esac
done
[[ $EUID = 0 ]] || { echo 'Run the reviewed installer as root on the intended target.' >&2; exit 77; }
[[ $package = /* && -f $package && ! -L $package ]] || { echo 'An explicit local regular .deb is required.' >&2; exit 2; }
[[ $(dpkg-deb -f "$package" Package) = defenderlink-mesh ]] || exit 2
# --no-download makes dependency availability an explicit offline installation gate.
if $install_deps; then
 apt-get install -y "$package"
else
 apt-get --no-download install -y "$package"
fi
printf '%s\n' 'Installed without starting. Review /etc/defenderlink/node.json; run 5gnexus diagnostics, then 5gnexus start.'
