cat > ~/Desktop/defenderlink-mesh/packaging/build-deb.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

VERSION="1.0.0"
ARCH=$(dpkg --print-architecture 2>/dev/null || echo "amd64")
PKG_NAME="defenderlink-mesh"
PKG_DIR="build/${PKG_NAME}_${VERSION}_${ARCH}"
PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "========================================="
echo " 5GNexusGuard — Package Builder"
echo " Version: ${VERSION}"
echo " Arch:    ${ARCH}"
echo "========================================="

echo "[1/5] Building frontend..."
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run build
cd "$PROJECT_ROOT"

echo "[2/5] Integrating frontend into backend..."
mkdir -p src/main/resources/META-INF/resources
cp -r frontend/dist/* src/main/resources/META-INF/resources/

echo "[3/5] Building Quarkus uber-jar..."
mvn package -DskipTests -Dquarkus.package.jar.type=uber-jar -q

UBER_JAR=$(find target -name "*-runner.jar" | head -1)
if [ ! -f "$UBER_JAR" ]; then
    echo "ERROR: Could not find built JAR."
    exit 1
fi
echo "   Built: $UBER_JAR"

echo "[4/5] Assembling .deb package..."
rm -rf "$PKG_DIR"
mkdir -p "${PKG_DIR}/DEBIAN"
mkdir -p "${PKG_DIR}/opt/defenderlink/bin"
mkdir -p "${PKG_DIR}/opt/defenderlink/lib"
mkdir -p "${PKG_DIR}/opt/defenderlink/conf"
mkdir -p "${PKG_DIR}/var/lib/defenderlink"
mkdir -p "${PKG_DIR}/etc/defenderlink"
mkdir -p "${PKG_DIR}/usr/lib/systemd/system"

cp "$UBER_JAR" "${PKG_DIR}/opt/defenderlink/lib/defenderlink-mesh.jar"

cat > "${PKG_DIR}/opt/defenderlink/bin/defenderlink-mesh" << 'LAUNCHER'
#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
JAVA_OPTS="${JAVA_OPTS:-}"

if [ -d "$SCRIPT_DIR/jre" ]; then
    JAVA="$SCRIPT_DIR/jre/bin/java"
elif command -v java &>/dev/null; then
    JAVA="java"
else
    echo "ERROR: Java 24+ is required. Install with: sudo apt install openjdk-24-jre-headless"
    exit 1
fi

exec "$JAVA" \
    $JAVA_OPTS \
    -Dmesh.data-dir="${MESH_DATA_DIR:-/var/lib/defenderlink}" \
    -jar "$SCRIPT_DIR/lib/defenderlink-mesh.jar" \
    "$@"
LAUNCHER
chmod 755 "${PKG_DIR}/opt/defenderlink/bin/defenderlink-mesh"

mkdir -p "${PKG_DIR}/usr/local/bin"
ln -sf /opt/defenderlink/bin/defenderlink-mesh "${PKG_DIR}/usr/local/bin/defenderlink"

cp packaging/systemd/defenderlink-mesh.service "${PKG_DIR}/usr/lib/systemd/system/"

cat > "${PKG_DIR}/etc/defenderlink/defenderlink.conf" << 'CONF'
# 5GNexusGuard Configuration

# HTTP port (default: 8443)
QUARKUS_HTTP_PORT=8443

# Data directory
MESH_DATA_DIR=/var/lib/defenderlink

# This node's public WireGuard endpoint
# MESH_PUBLIC_ENDPOINT=192.168.x.x:51820

# Additional JVM options
# JAVA_OPTS=-Xmx512m
CONF

cat > "${PKG_DIR}/DEBIAN/control" << CONTROL
Package: ${PKG_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Depends: openjdk-24-jre-headless | openjdk-21-jre-headless, wireguard-tools
Recommends: wireguard
Maintainer: WPO Tech <support@wpotech.com>
Description: 5GNexusGuard - Decentralized Zero Trust Overlay Network
 Peer-to-peer encrypted tunnels with blockchain ledger consensus.
Homepage: https://wpotech.com/defenderlink
CONTROL

cat > "${PKG_DIR}/DEBIAN/postinst" << 'POSTINST'
#!/bin/bash
set -e

if ! id -u defenderlink &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --home-dir /var/lib/defenderlink defenderlink
fi

mkdir -p /opt/defenderlink/logs
chown -R root:root /var/lib/defenderlink
chown -R root:root /opt/defenderlink

if getent group netdev &>/dev/null; then
    usermod -aG netdev defenderlink
fi

JAVA_BIN=$(readlink -f "$(which java)" 2>/dev/null || true)
if [ -f "$JAVA_BIN" ]; then
    setcap 'cap_net_admin,cap_net_raw+ep' "$JAVA_BIN" 2>/dev/null || true
fi

systemctl daemon-reload

echo ""
echo "============================================"
echo " 5GNexusGuard installed successfully!"
echo " Dashboard: http://localhost:8443"
echo " Logs:      journalctl -u defenderlink-mesh -f"
echo "============================================"
POSTINST
# License key — leave empty for free tier (max 3 nodes)
# Get a license at https://defenderlink.io/pricing
# Pro: dl_pro_xxxxxxxxxxxxxxxx  (25 nodes)
# Enterprise: dl_ent_xxxxxxxxxxxxxxxx  (unlimited)
MESH_LICENSE_KEY=

chmod 755 "${PKG_DIR}/DEBIAN/postinst"

cat > "${PKG_DIR}/DEBIAN/prerm" << 'PRERM'
#!/bin/bash
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
    systemctl stop defenderlink-mesh 2>/dev/null || true
    systemctl disable defenderlink-mesh 2>/dev/null || true
fi
PRERM
chmod 755 "${PKG_DIR}/DEBIAN/prerm"

cat > "${PKG_DIR}/DEBIAN/postrm" << 'POSTRM'
#!/bin/bash
set -e
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/defenderlink
    userdel defenderlink 2>/dev/null || true
fi
systemctl daemon-reload
POSTRM
chmod 755 "${PKG_DIR}/DEBIAN/postrm"

cat > "${PKG_DIR}/DEBIAN/conffiles" << 'CONFFILES'
/etc/defenderlink/defenderlink.conf
CONFFILES

echo "[5/5] Building .deb package..."
cd build
dpkg-deb --build --root-owner-group "${PKG_NAME}_${VERSION}_${ARCH}"
cd "$PROJECT_ROOT"

DEB_FILE="build/${PKG_NAME}_${VERSION}_${ARCH}.deb"
DEB_SIZE=$(du -h "$DEB_FILE" | cut -f1)

echo ""
echo "========================================="
echo " BUILD COMPLETE"
echo " Package: ${DEB_FILE}"
echo " Size:    ${DEB_SIZE}"
echo " Install: sudo apt install ./${DEB_FILE}"
echo "========================================="
EOF
chmod +x ~/Desktop/defenderlink-mesh/packaging/build-deb.sh
