#!/usr/bin/env bash
set -euo pipefail
# This is a guard against accidental execution, not a substitute for parent approval.
if [[ ${1:-} != --parent-approved ]]; then
  echo 'Not run: obtain parent approval, then pass --parent-approved and an absolute evidence directory.' >&2
  exit 77
fi
out=${2:?absolute evidence directory outside repository required}
repo=$(cd "$(dirname "$0")/../.." && pwd)
[[ $out = /* && ! -e $out ]] || { echo 'Evidence destination must be new and absolute' >&2; exit 2; }
resolved=$(realpath -m "$out")
[[ $resolved != "$repo" && $resolved != "$repo/"* ]] || exit 2
mkdir -m 700 "$resolved"
cd "$repo"
docker build -f scripts/ipsec-dual/Dockerfile -t defenderlink-ipsec-lab . >"$resolved/build.log" 2>&1
name="dl-ipsec-$(date +%s)-$$"
cleanup() { docker rm -fv "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
# No host network, devices, socket, mounts, published ports, or privileged flag.
# SYS_ADMIN: named netns/private mounts; NET_RAW: captures; NET_BIND_SERVICE: IKE.
# SETUID/SETGID: tcpdump drops credentials (even with -Z root); NET_ADMIN: WG/XFRM/nft.
docker create --name "$name" --network none --cap-drop ALL \
  --cap-add NET_ADMIN --cap-add NET_RAW --cap-add SYS_ADMIN --cap-add NET_BIND_SERVICE --cap-add SETUID --cap-add SETGID \
  --security-opt no-new-privileges --security-opt apparmor=unconfined \
  --read-only --tmpfs /tmp:rw,nosuid,nodev --tmpfs /run:rw,nosuid,nodev \
  defenderlink-ipsec-lab >"$resolved/container-id.txt"
# /evidence is an anonymous Docker volume, retained until evidence is copied.
docker start -a "$name" >"$resolved/gates.log" 2>&1 || true
docker inspect "$name" >"$resolved/container.json"
docker image inspect defenderlink-ipsec-lab >"$resolved/image.json"
docker cp "$name:/evidence/." "$resolved/" || true
code=$(docker inspect --format '{{.State.ExitCode}}' "$name")
cat "$resolved/gates.log"
exit "$code"
