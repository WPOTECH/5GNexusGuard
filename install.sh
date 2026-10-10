#!/usr/bin/env bash
# =============================================================================
# 5GNexusGuard — Universal Installer
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/flyingwest/defenderlink-mesh/main/install.sh | sudo bash
#
# Or with options:
#   curl -fsSL .../install.sh | sudo bash -s -- --endpoint 192.168.1.100:51820 --port 8443
#
# Supports:
#   - Ubuntu 20.04+ / Debian 11+  (.deb)
#   - RHEL / Rocky / AlmaLinux 8+ (.rpm)
#   - Any Linux with Java 24+     (tarball fallback)
# =============================================================================
set -euo pipefail

# ── Config ────────────────────────────────────────────────────────────────
VERSION="${DL_VERSION:-1.0.0}"
GITHUB_REPO="flyingwest/defenderlink-mesh"
BASE_URL="https://github.com/${GITHUB_REPO}/releases/download/v${VERSION}"
REQUESTED_ENDPOINT="${DL_ENDPOINT:-}"
REQUESTED_PORT="${DL_PORT:-8443}"

# ── Colors ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

step()  { echo -e "\n${BOLD}${CYAN}▶ $*${NC}"; }
ok()    { echo -e "${GREEN}✓ $*${NC}"; }
warn()  { echo -e "${YELLOW}⚠ $*${NC}"; }
info()  { echo -e "  $*"; }
fail()  { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }

# ── Banner ────────────────────────────────────────────────────────────────
echo -e "${BOLD}"
cat << 'BANNER'
  ____       __               _           __    _      __
 / __ \___  / /__ ___  ___  (_)__ ____  / /   (_)__  / /__
/ /_/ / -_) / -_) _ \/ _ \/ / -_) __/ / /   / / _ \/ '/
\____/\__/_/\__/_//_/_//_/_/\__/_/    /_/___/_/_//_/\_/
                                         /___/
  Mesh — Zero Trust Overlay Network
BANNER
echo -e "${NC}"
echo -e "  Version: ${BOLD}v${VERSION}${NC}"
echo -e "  Repo:    https://github.com/${GITHUB_REPO}"
echo ""

# ── Root check ────────────────────────────────────────────────────────────
[ "$EUID" -eq 0 ] || fail "This installer must be run as root. Use: sudo bash"

# ── Parse args ────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --endpoint) REQUESTED_ENDPOINT="$2"; shift 2 ;;
    --port)     REQUESTED_PORT="$2";     shift 2 ;;
    --version)  VERSION="$2";            shift 2 ;;
    *) warn "Unknown argument: $1"; shift ;;
  esac
done

# ── Detect OS and package format ─────────────────────────────────────────
step "Detecting system"

OS_ID=""
PKG_FORMAT=""
DEB_ARCH=""
RPM_ARCH=""
TAR_ARCH=""

if [ -f /etc/os-release ]; then
  . /etc/os-release
  OS_ID="${ID:-unknown}"
fi

MACHINE=$(uname -m)
case "$MACHINE" in
  x86_64)  DEB_ARCH="amd64"; RPM_ARCH="x86_64"; TAR_ARCH="x86_64" ;;
  aarch64) DEB_ARCH="arm64"; RPM_ARCH="aarch64"; TAR_ARCH="arm64"  ;;
  armv7l)  DEB_ARCH="armhf"; RPM_ARCH="armhf";   TAR_ARCH="armv7l" ;;
  *) fail "Unsupported architecture: $MACHINE" ;;
esac

case "$OS_ID" in
  ubuntu|debian|raspbian|linuxmint|pop)
    PKG_FORMAT="deb"
    info "Detected: ${OS_ID} (Debian-based) — using .deb"
    ;;
  rhel|centos|rocky|almalinux|fedora|ol)
    PKG_FORMAT="rpm"
    info "Detected: ${OS_ID} (RHEL-based) — using .rpm"
    ;;
  *)
    PKG_FORMAT="tarball"
    warn "Unknown distro '${OS_ID}' — falling back to tarball install"
    ;;
esac

ok "System: ${OS_ID} / ${MACHINE}"

# ── Check Java ────────────────────────────────────────────────────────────
step "Checking Java"

JAVA_OK=false
if command -v java >/dev/null 2>&1; then
  JAVA_VER=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d. -f1)
  if [ "${JAVA_VER:-0}" -ge 21 ] 2>/dev/null; then
    ok "Java ${JAVA_VER} found"
    JAVA_OK=true
  else
    warn "Java ${JAVA_VER} found but version 21+ required"
  fi
fi

if [ "$JAVA_OK" = false ]; then
  info "Installing Java 21..."
  case "$PKG_FORMAT" in
    deb)
      apt-get update -qq
      apt-get install -y -qq openjdk-21-jre-headless || \
        apt-get install -y -qq default-jre-headless || \
        fail "Could not install Java. Install manually: sudo apt install openjdk-21-jre-headless"
      ;;
    rpm)
      dnf install -y java-21-openjdk-headless 2>/dev/null || \
        yum install -y java-21-openjdk-headless 2>/dev/null || \
        fail "Could not install Java. Install manually: sudo dnf install java-21-openjdk-headless"
      ;;
    *)
      fail "Please install Java 21+ manually then re-run this installer"
      ;;
  esac
  ok "Java installed"
fi

# ── Check WireGuard ───────────────────────────────────────────────────────
step "Checking WireGuard"

if ! command -v wg >/dev/null 2>&1; then
  info "Installing wireguard-tools..."
  case "$PKG_FORMAT" in
    deb)
      apt-get update -qq
      apt-get install -y -qq wireguard-tools
      ;;
    rpm)
      dnf install -y wireguard-tools 2>/dev/null || \
        yum install -y wireguard-tools 2>/dev/null || \
        warn "Could not install wireguard-tools automatically. Install manually."
      ;;
  esac
fi

if command -v wg >/dev/null 2>&1; then
  ok "WireGuard tools: $(wg --version 2>/dev/null | head -1)"
else
  warn "wireguard-tools not found — tunnels will not work until installed"
fi

# Load WireGuard kernel module
if modprobe wireguard 2>/dev/null; then
  ok "WireGuard kernel module loaded"
  echo "wireguard" > /etc/modules-load.d/wireguard.conf
else
  warn "Could not load WireGuard kernel module — may already be built-in or require reboot"
fi

# ── Download & install ────────────────────────────────────────────────────
step "Downloading 5GNexusGuard v${VERSION}"

TMPDIR_INST="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_INST"' EXIT

download_file() {
  local url="$1"
  local dest="$2"
  info "Fetching $(basename $url)..."
  curl -fsSL --progress-bar -o "$dest" "$url" \
    || fail "Download failed: $url\nCheck that v${VERSION} exists at https://github.com/${GITHUB_REPO}/releases"
}

case "$PKG_FORMAT" in
  deb)
    FILENAME="defenderlink-mesh_${VERSION}_${DEB_ARCH}.deb"
    PKG_PATH="${TMPDIR_INST}/${FILENAME}"
    download_file "${BASE_URL}/${FILENAME}" "$PKG_PATH"
    step "Installing .deb package"
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$PKG_PATH"
    ;;

  rpm)
    FILENAME="defenderlink-mesh-${VERSION}-1.${RPM_ARCH}.rpm"
    PKG_PATH="${TMPDIR_INST}/${FILENAME}"
    download_file "${BASE_URL}/${FILENAME}" "$PKG_PATH"
    step "Installing .rpm package"
    dnf install -y "$PKG_PATH" 2>/dev/null || yum install -y "$PKG_PATH"
    ;;

  tarball)
    FILENAME="defenderlink-mesh-${VERSION}-linux-${TAR_ARCH}.tar.gz"
    PKG_PATH="${TMPDIR_INST}/${FILENAME}"
    download_file "${BASE_URL}/${FILENAME}" "$PKG_PATH"
    step "Installing from tarball"
    tar -xzf "$PKG_PATH" -C "$TMPDIR_INST"
    EXTRACT_DIR=$(find "$TMPDIR_INST" -maxdepth 1 -type d -name "defenderlink-mesh-*" | head -1)
    [ -d "$EXTRACT_DIR" ] || fail "Extraction failed"
    bash "${EXTRACT_DIR}/install.sh"
    ;;
esac

ok "5GNexusGuard installed"

# ── Configure endpoint ────────────────────────────────────────────────────
step "Configuring"

CONF="/etc/defenderlink/defenderlink.conf"

# Auto-detect public IP if not provided
if [ -z "$REQUESTED_ENDPOINT" ]; then
  DETECTED_IP=$(hostname -I | awk '{print $1}')
  REQUESTED_ENDPOINT="${DETECTED_IP}:51820"
  info "Auto-detected endpoint: ${REQUESTED_ENDPOINT}"
  info "Override with: --endpoint YOUR_PUBLIC_IP:51820"
fi

# Write JAVA_OPTS with endpoint
if grep -q "^JAVA_OPTS=" "$CONF" 2>/dev/null; then
  sed -i "s|^JAVA_OPTS=.*|JAVA_OPTS=-Dmesh.node.public-endpoint=${REQUESTED_ENDPOINT}|" "$CONF"
else
  echo "JAVA_OPTS=-Dmesh.node.public-endpoint=${REQUESTED_ENDPOINT}" >> "$CONF"
fi

# Set custom port if requested
if [ "$REQUESTED_PORT" != "8443" ]; then
  sed -i "s|^QUARKUS_HTTP_PORT=.*|QUARKUS_HTTP_PORT=${REQUESTED_PORT}|" "$CONF"
fi

ok "Endpoint set to: ${REQUESTED_ENDPOINT}"
ok "Dashboard port: ${REQUESTED_PORT}"

# Fix ownership for root-run service
chown -R root:root /var/lib/defenderlink 2>/dev/null || true
mkdir -p /opt/defenderlink/logs

# ── Enable and start ──────────────────────────────────────────────────────
step "Starting service"

systemctl daemon-reload
systemctl enable defenderlink-mesh
systemctl restart defenderlink-mesh

sleep 3

if systemctl is-active --quiet defenderlink-mesh; then
  ok "defenderlink-mesh is running"
else
  warn "Service may not have started yet — check: journalctl -u defenderlink-mesh -f"
fi

# ── Done ──────────────────────────────────────────────────────────────────
NODE_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║    5GNexusGuard installed successfully!          ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Dashboard:  ${BOLD}http://${NODE_IP}:${REQUESTED_PORT}${NC}"
echo -e "  Endpoint:   ${BOLD}${REQUESTED_ENDPOINT}${NC}"
echo -e "  Logs:       ${BOLD}journalctl -u defenderlink-mesh -f${NC}"
echo -e "  Config:     ${BOLD}/etc/defenderlink/defenderlink.conf${NC}"
echo -e "  Data:       ${BOLD}/var/lib/defenderlink${NC}"
echo ""
echo -e "  Next steps:"
echo -e "  1. Open the dashboard and click ${BOLD}Register Node${NC}"
echo -e "  2. Enter this node's endpoint: ${BOLD}${REQUESTED_ENDPOINT}${NC}"
echo -e "  3. Install on a second machine and register it too"
echo -e "  4. Expose a service → Connect from the other node"
echo ""
echo -e "  Docs: https://github.com/${GITHUB_REPO}"
echo ""
