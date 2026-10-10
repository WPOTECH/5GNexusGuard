# =============================================================================
# 5GNexusGuard — Docker Image
#
# Build:
#   mvn clean package -DskipTests -Dquarkus.package.jar.type=uber-jar
#   docker build -t wpospace/defenderlink-mesh:1.0.0 .
#
# Run:
#   docker run -d \
#     --name defenderlink-mesh \
#     --network host \
#     --cap-add NET_ADMIN \
#     --cap-add NET_RAW \
#     --sysctl net.ipv4.ip_forward=1 \
#     -v defenderlink-data:/var/lib/defenderlink \
#     -e "JAVA_TOOL_OPTIONS=-Dmesh.node.public-endpoint=YOUR_IP:51820" \
#     wpospace/defenderlink-mesh:1.0.0
#
# Host requirements:
#   - WireGuard kernel module: sudo modprobe wireguard
#   - CAP_NET_ADMIN capability (granted via --cap-add)
# =============================================================================
FROM eclipse-temurin:24-jre-noble

LABEL org.opencontainers.image.title="5GNexusGuard" \
      org.opencontainers.image.description="Decentralized Zero Trust Overlay Network" \
      org.opencontainers.image.vendor="WPO Tech" \
      org.opencontainers.image.source="https://github.com/flyingwest/defenderlink-mesh" \
      org.opencontainers.image.licenses="MIT"

# Install WireGuard CLI tools and networking utilities
# The WireGuard KERNEL MODULE must be loaded on the HOST
RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools \
    iproute2 \
    iptables \
    kmod \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create data directories
RUN mkdir -p /var/lib/defenderlink/identity \
             /var/lib/defenderlink/ledger \
             /var/lib/defenderlink/wg-configs \
             /opt/defenderlink/logs

# Copy the uber-jar
# Build first: mvn clean package -DskipTests -Dquarkus.package.jar.type=uber-jar
COPY target/defenderlink-mesh-*-runner.jar /opt/defenderlink/defenderlink-mesh.jar

# Ports
EXPOSE 8443/tcp
EXPOSE 9450/udp
EXPOSE 51820/udp

# Persist ledger, identity keys, WireGuard configs across container restarts
VOLUME ["/var/lib/defenderlink"]

ENV MESH_DATA_DIR=/var/lib/defenderlink

HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
    CMD curl -f http://localhost:8443/q/health/live || exit 1

ENTRYPOINT ["java", \
    "-Dmesh.data-dir=/var/lib/defenderlink", \
    "-jar", "/opt/defenderlink/defenderlink-mesh.jar"]
