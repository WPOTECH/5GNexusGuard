# 5GNexusGuard

**Decentralized Zero Trust Access (ZTA) Overlay Network**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Java](https://img.shields.io/badge/Java-24-orange.svg)](https://openjdk.org/)
[![Quarkus](https://img.shields.io/badge/Quarkus-3.x-blue.svg)](https://quarkus.io/)
[![WireGuard](https://img.shields.io/badge/WireGuard-✓-88171A.svg)](https://www.wireguard.com/)
[![Docker Pulls](https://img.shields.io/docker/pulls/wpospace/defenderlink-mesh)](https://hub.docker.com/r/wpospace/defenderlink-mesh)
[![Docker Image](https://img.shields.io/docker/v/wpospace/defenderlink-mesh?label=docker)](https://hub.docker.com/r/wpospace/defenderlink-mesh)

5GNexusGuard is an open-source, fully decentralized Zero Trust Access overlay network. No controller. No single point of failure. No cloud dependency. Every node is sovereign.

https://5gnexus.com/

![5GNexusGuard node console — Raft leader status, mesh node list and ledger chain height](docs/dashboard.png)

---

## How It Works

```
    Node A                                   Node B
────────────────                          ────────────
App → 127.0.0.1:14000                    Keycloak → 127.0.0.1:8080
       ↓                                        ↑
  InterceptProxy                          EgressProxy
       ↓                                        ↑
  WireGuard dl-c-keycloak ══════════ WireGuard dl-o-keycloak
  10.200.1.1/30            ChaCha20  10.200.1.2/30
       ↓                  Poly1305         ↑
  Ledger (RocksDB)  ←── Raft ───→  Ledger (RocksDB)
```

### Core Principles

- **No controller** — nodes discover each other via UDP gossip broadcast on the LAN
- **No PKI** — Ed25519 public key IS the node identity. No certificates, no CA, no tokens
- **Per-service tunnel isolation** — each service gets its own WireGuard interface and keypair
- **Blockchain-enforced access control** — service authorization is signed and written to a Merkle-chained ledger replicated across all nodes
- **Raft consensus** — distributed leader election ensures ledger consistency with no master node

---

## Architecture

### Identity Layer
Each node generates an Ed25519 keypair on first boot. The hex-encoded public key is the node ID. No registration with any authority required.

### Ledger Layer
A Merkle-chained blockchain stored in RocksDB. Every node holds a full replica. Entries include:
- `NODE_REGISTER` — node joins the mesh with its endpoints and WireGuard pubkey
- `SERVICE_EXPOSE` — node exposes a local service to specific authorized peers
- `SERVICE_REVOKE` — access revocation, recorded immutably

### Consensus Layer
Simplified Raft protocol over UDP gossip. Leader election, heartbeats, and block proposals. The leader batches pending ledger entries into blocks every 5 seconds.

### Tunnel Layer
When Node A wants to reach a service on Node B:
1. Node A queries its **local ledger** — no network call needed
2. Node A calls `/internal/tunnel/negotiate` on Node B
3. Node B verifies the Ed25519 signature, checks the ledger, creates its WireGuard interface and egress proxy
4. Node A creates its WireGuard interface and intercept proxy
5. The WireGuard Noise IK handshake completes — tunnel is live

---

## Features

| Feature | Status |
|---|---|
| Ed25519 self-sovereign identity | ✅ |
| WireGuard encrypted tunnels (ChaCha20-Poly1305) | ✅ |
| Per-service tunnel isolation | ✅ |
| Merkle-chained blockchain ledger | ✅ |
| Raft consensus (no master) | ✅ |
| UDP gossip peer discovery | ✅ |
| RocksDB persistent ledger | ✅ |
| React dashboard UI | ✅ |
| REST API | ✅ |
| .deb package with systemd service | ✅ |
| Docker / Docker Compose | ✅ |
| K3s + Multus (Kubernetes) | ✅ |
| Multi-node mesh | ✅ |
| Service access revocation | ✅ |

---

## Requirements

- Ubuntu 22.04+ / Debian 11+
- Java 24+
- WireGuard kernel module (`apt install wireguard-tools`)
- Root or `CAP_NET_ADMIN` capability

---

## Installation

See **[INSTALL.md](INSTALL.md)** for the full installation guide covering all methods.

### One-liner (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/flyingwest/defenderlink-mesh/main/install.sh | sudo bash
```

### Docker

```bash
docker pull wpospace/defenderlink-mesh:latest

docker run -d \
  --name defenderlink-mesh \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --sysctl net.ipv4.ip_forward=1 \
  --restart unless-stopped \
  -v defenderlink-data:/var/lib/defenderlink \
  -e "JAVA_TOOL_OPTIONS=-Dmesh.node.public-endpoint=YOUR_IP:51820" \
  wpospace/defenderlink-mesh:latest
```

### Manual .deb

```bash
wget https://github.com/flyingwest/defenderlink-mesh/releases/latest/download/defenderlink-mesh_1.0.0_amd64.deb
sudo apt install -y ./defenderlink-mesh_1.0.0_amd64.deb
```

### Kubernetes (K3s + Multus)

```bash
kubectl apply -k k8s/overlays/polaris
```

See [k8s/README.md](k8s/README.md) for full Kubernetes deployment guide.

### From source

```bash
git clone https://github.com/flyingwest/defenderlink-mesh.git
cd defenderlink-mesh

# Build frontend
cd frontend && npm install && npm run build && cd ..
cp -r frontend/dist/* src/main/resources/META-INF/resources/

# Build uber-jar
mvn package -DskipTests -Dquarkus.package.jar.type=uber-jar

# Run
sudo java -Dmesh.node.public-endpoint=YOUR_IP:51820 \
          -Dmesh.data-dir=/var/lib/defenderlink \
          -jar target/defenderlink-mesh-*-runner.jar
```

---

## Quick Start: Two-Node Setup

**Node A (service owner — exposes Keycloak):**
```bash
# Install and start 5GNexusGuard
# Open http://NODE_A_IP:8443
# Click "Register Node", enter your IP:51820 as endpoint
# Click "Expose Service":
#   Service ID: keycloak
#   Protocol: TCP
#   Local bind: 127.0.0.1:8080
#   Authorized peers: [Node B]
```

**Node B (connector — accesses Keycloak):**
```bash
# Install and start 5GNexusGuard
# Open http://NODE_B_IP:8443
# Click "Register Node"
# Click "Connect" on the keycloak service card
# Access Keycloak at http://127.0.0.1:14000
```

That's it. No VPN configuration. No certificates. No firewall rules beyond UDP 9450 (gossip) and UDP 51820 (WireGuard).

---

## Configuration

`/etc/defenderlink/defenderlink.conf`

```bash
# HTTP port
QUARKUS_HTTP_PORT=8443

# Data directory (ledger, keys, WireGuard configs)
MESH_DATA_DIR=/var/lib/defenderlink

# This node's public WireGuard endpoint — REQUIRED
JAVA_OPTS=-Dmesh.node.public-endpoint=192.168.1.100:51820
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/status` | Node status, Raft state, chain height |
| GET | `/api/nodes` | All mesh nodes (ledger + gossip-discovered) |
| POST | `/api/node/register` | Register this node to the mesh |
| GET | `/api/services` | All services in the mesh |
| POST | `/api/services/expose` | Expose a local service |
| POST | `/api/services/{id}/revoke` | Revoke a service |
| POST | `/api/connect/{serviceId}` | Connect to a remote service |
| GET | `/api/tunnels` | Active WireGuard tunnels |
| DELETE | `/api/tunnels/{serviceId}` | Disconnect a tunnel |
| GET | `/api/ledger/block/{index}` | Get a ledger block by index |

---

## Cryptographic Stack

| Layer | Algorithm |
|---|---|
| Node identity | Ed25519 (BouncyCastle) |
| Tunnel encryption | WireGuard — Noise IK, ChaCha20-Poly1305 |
| Key exchange | Curve25519 (via WireGuard) |
| Ledger integrity | SHA-256 Merkle chain |
| Ledger signing | Ed25519 per-entry signatures |

---

## Roadmap

- [ ] UDP service support
- [ ] Relay node for NAT traversal
- [ ] Multi-hop routing
- [ ] RBAC for service access policies
- [ ] Audit log export
- [ ] Android client
- [ ] ARM64 / Raspberry Pi / Jetson support
- [ ] 5GMedLink integration (private 5G + ZTA)
- [ ] Web-based node enrollment QR code

---

## Contributing

5GNexusGuard is open source and welcomes contributions.
```bash
# Run in dev mode (no WireGuard required for control plane testing)
mvn quarkus:dev
```

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Built With

- [Quarkus](https://quarkus.io/) — supersonic Java framework
- [WireGuard](https://www.wireguard.com/) — modern VPN kernel module
- [RocksDB](https://rocksdb.org/) — embedded persistent key-value store
- [BouncyCastle](https://www.bouncycastle.org/) — cryptography library
- [React](https://react.dev/) + [Vite](https://vitejs.dev/) — dashboard UI

---

*No controller. No cloud. No trust by default.*
