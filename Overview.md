# 5GNexusGuard — Product Overview

**Decentralized Zero Trust Access for Modern Infrastructure**

*WPO Tech · v1.0.0 · MIT License*

---

## What Is 5GNexusGuard?

5GNexusGuard is an open-source, fully decentralized, No Single Point of Failure Zero Trust Access (ZTA) overlay network. It creates encrypted, per-service tunnels between machines — without any central controller, without cloud dependency, and without a single point of failure.

Every node is sovereign. Every connection is verified. Every service is isolated.

It is designed for infrastructure engineers, healthcare IT teams, and security-conscious organizations who need to connect services across machines securely — without the complexity, cost, or cloud lock-in of commercial ZTA products like Tailscale, Zscaler, or Cloudflare Access.

---

## The Problem It Solves

Traditional network security relies on perimeter defense — a firewall keeps the bad actors out, and everything inside is trusted. This model has three fatal flaws:

1. **Perimeter breaches are catastrophic** — once inside, an attacker moves freely
2. **Remote work and cloud destroyed the perimeter** — there is no inside anymore
3. **Flat networks mean lateral movement** — one compromised service reaches all others

Existing ZTA solutions solve these problems but introduce new ones:
- **Tailscale** requires a coordination server they control
- **Zscaler** costs hundreds of thousands per year and routes your traffic through their cloud
- **Cloudflare Access** ties you to Cloudflare's infrastructure
- All of them require trusting a third party with your network topology

5GNexusGuard solves the original problem without introducing the new ones.

---

## How It Works

5GNexusGuard creates a mesh of nodes. Each node is a machine running the 5GNexusGuard service. Nodes discover each other automatically via UDP gossip broadcast. Access control is governed by a blockchain ledger replicated across every node — no central database, no controller, no cloud call required.

When a connection is needed between two services on different machines, 5GNexusGuard negotiates a dedicated WireGuard tunnel for that specific service. The tunnel is encrypted with ChaCha20-Poly1305 — the same cryptography used by Signal and WireGuard itself.

```
┌─────────────────────────────────────────────────────────────────┐
│                          5GNexusGuard                           │
├────────────────────────┬────────────────────────────────────────┤
│     Node A (Polaris)   │           Node B (VM / Edge)           │
│                        │                                        │
│  App                   │                        Keycloak :8080  │
│   │                    │                              ↑         │
│   ▼                    │                         EgressProxy    │
│  127.0.0.1:14000       │                              ↑         │
│   │                    │                    WireGuard dl-o-*    │
│  InterceptProxy        │                              ↑         │
│   │                    │    ChaCha20-Poly1305          │         │
│  WireGuard dl-c-* ─────┼──────────────────────────────┘         │
│                        │                                        │
│  Ledger (RocksDB) ◄────┼──── Raft Consensus ────► Ledger        │
│  Ed25519 Identity      │         UDP Gossip         Ed25519      │
└────────────────────────┴────────────────────────────────────────┘
```

### The Five Layers

**1. Identity Layer**
Each node generates an Ed25519 keypair on first boot. The hex-encoded public key is the node ID. There is no certificate authority, no PKI, no registration with any external service. Your cryptographic identity is yours.

**2. Discovery Layer**
Nodes broadcast their presence via UDP gossip on port 9450. On a LAN, nodes discover each other within seconds. No DNS, no seed server, no coordination service required.

**3. Ledger Layer**
Access control is written to a Merkle-chained blockchain stored in RocksDB on every node. Every service exposure, every authorization, every revocation is a signed ledger entry replicated across the mesh. The ledger is immutable, auditable, and tamper-evident.

**4. Consensus Layer**
A simplified Raft protocol ensures all nodes agree on the ledger state. One leader is elected, proposes blocks every 5 seconds, and replicates them to all peers. If the leader fails, a new one is elected automatically.

**5. Tunnel Layer**
When Node A needs to reach a service on Node B, it reads its local ledger (no network call), verifies it is authorized, and negotiates a WireGuard tunnel directly with Node B. The tunnel is per-service — `dl-c-keycloak`, `dl-c-postgres`, `dl-c-redis` are separate interfaces with separate keys. Compromise of one tunnel exposes nothing else.

---

## Key Features

### Zero Controller
There is no coordination server, no cloud backend, no single point of failure. Remove any node from the mesh — including the one that registered everything — and the mesh continues operating. Every node has the full ledger.

### Self-Sovereign Identity
Your Ed25519 public key is your identity. No certificate authority can revoke it. No third party issues it. No external service validates it. Node-to-node authentication uses cryptographic signatures verified directly against the ledger.

### Per-Service Tunnel Isolation
Each service gets its own WireGuard interface and its own keypair. This is a fundamental architectural difference from most VPN-based ZTA products which give you one tunnel for everything. With 5GNexusGuard, an attacker who compromises one service tunnel gains access to exactly one service — nothing else.

### Blockchain Access Ledger
Service authorization is not stored in a database that can be modified quietly. It is written to a Merkle-chained ledger with cryptographic signatures. Every access grant and every revocation is permanently recorded and verifiable. You can audit the complete history of who authorized what and when.

### WireGuard Encryption
All tunnel traffic is encrypted using WireGuard's Noise IK protocol with ChaCha20-Poly1305 authenticated encryption. WireGuard is a modern, minimal, audited VPN protocol built into the Linux kernel. It is faster and more secure than OpenVPN or IPSec.

### Open Source — MIT License
The complete source code is on GitHub. You can read it, audit it, modify it, and run it forever at no cost. There are no telemetry calls, no phone-home, no usage tracking. What runs on your infrastructure stays on your infrastructure.

---

## Example Use Cases

### Example 1 — Secure Database Access Across Machines

**Scenario:** Your application server needs to reach a PostgreSQL database on a separate machine. Opening port 5432 to the network is a security risk.

**Without 5GNexusGuard:**
```
App Server ──── TCP :5432 ──────────────► PostgreSQL Server
                (exposed on network, firewall rules required)
```

**With 5GNexusGuard:**
```
App Server
  App ──► 127.0.0.1:14001 (InterceptProxy)
            │
            └──► WireGuard tunnel (ChaCha20-Poly1305)
                    │
                    └──► 10.200.1.2:15101 (EgressProxy)
                              │
                              └──► 127.0.0.1:5432 (PostgreSQL)
```

PostgreSQL never listens on the network. The tunnel only exists between the two authorized nodes. No firewall rules needed beyond WireGuard UDP 51820.

**Setup:**
```bash
# On database server — expose the service
# Dashboard → Expose Service
# Service ID: postgres
# Local bind: 127.0.0.1:5432
# Authorized peers: [app-server-node-id]

# On app server — connect
# Dashboard → Connect → postgres
# PostgreSQL now available at 127.0.0.1:14001
```

---

### Example 2 — Healthcare IoT Device Access

**Scenario:** Medical devices on a hospital floor need to send data to an internal analytics service. The devices are on a private 5G network (5GMedLink). The analytics service is on a separate server.

**With 5GNexusGuard + 5GMedLink:**
- Each device runs 5GNexusGuard as a node
- The analytics server exposes its API through the mesh
- Data flows encrypted through WireGuard tunnels
- Access is controlled by the blockchain ledger — only authorized device IDs can connect
- Every access attempt is recorded immutably in the ledger for compliance audit

No VPN client needed on each device. No exposed ports. Full audit trail.

---

### Example 3 — Zero Trust Remote Access

**Scenario:** A developer needs to access an internal Keycloak admin panel from home without exposing it to the internet.

**Setup:**
```bash
# On the office server running Keycloak
# Dashboard → Register Node (endpoint: office-server-public-ip:51820)
# Dashboard → Expose Service
# Service ID: keycloak
# Local bind: 127.0.0.1:8080
# Authorized peers: [developer-laptop-node-id]

# On developer laptop at home
# Install 5GNexusGuard
curl -fsSL https://raw.githubusercontent.com/flyingwest/defenderlink-mesh/main/install.sh | sudo bash
# Dashboard → Register Node
# Dashboard → Connect → keycloak
# Open browser → http://127.0.0.1:14000/admin/
```

Keycloak is never exposed to the internet. The developer's laptop is verified by Ed25519 signature against the ledger. The connection is encrypted end-to-end with WireGuard.

---

### Example 4 — Multi-Site Mesh

**Scenario:** Three sites — headquarters, a branch office, and a cloud VM — need to share internal services securely.

```
HQ (192.168.1.x)          Branch (192.168.2.x)       Cloud VM
┌──────────────┐           ┌──────────────┐           ┌──────────────┐
│  5GNexusGuard│◄──gossip──►  5GNexusGuard│◄──gossip──►  5GNexusGuard│
│  Node: hq    │           │  Node: branch│           │  Node: cloud │
│              │           │              │           │              │
│  Keycloak    │           │  App Server  │           │  Analytics   │
│  :8080       │           │  :3000       │           │  :9000       │
└──────────────┘           └──────────────┘           └──────────────┘
       │                          │                          │
       └──────────── Raft Consensus — shared ledger ─────────┘
```

Each site exposes its services to specific authorized peers. All traffic between sites flows through encrypted WireGuard tunnels. The ledger on every node knows the complete access policy. If the cloud VM goes offline, HQ and branch continue communicating — no central coordinator to fail.

---

## Benefits Summary

| Benefit | Description |
|---|---|
| **No cloud dependency** | Runs 100% on your infrastructure. No traffic routed through third-party servers. |
| **No single point of failure** | Every node has the full ledger. Lose any node — the mesh continues. |
| **Immutable audit trail** | Every authorization is permanently recorded in the blockchain ledger. |
| **Minimal attack surface** | WireGuard has ~4,000 lines of code vs OpenVPN's ~100,000. Less code = less to attack. |
| **Per-service isolation** | Compromise of one tunnel exposes exactly one service, nothing more. |
| **Open source** | Full source on GitHub. Audit it yourself. No hidden telemetry. |
| **Low resource usage** | Runs on a Raspberry Pi. ~256MB RAM, minimal CPU. |
| **Fast setup** | Two nodes talking in under 5 minutes from a bare Ubuntu server. |

---

## Comparison with Alternatives

| | 5GNexusGuard | Tailscale | Zscaler | Cloudflare Access |
|---|---|---|---|---|
| Open source | ✅ Full | ⚠️ Client only | ❌ | ❌ |
| No controller | ✅ | ❌ | ❌ | ❌ |
| No cloud dependency | ✅ | ❌ | ❌ | ❌ |
| Self-sovereign identity | ✅ | ❌ | ❌ | ❌ |
| Blockchain ledger | ✅ | ❌ | ❌ | ❌ |
| Per-service isolation | ✅ | ⚠️ Partial | ✅ | ✅ |
| WireGuard | ✅ | ✅ | ❌ | ❌ |
| Free tier | ✅ 3 nodes | ✅ 3 users | ❌ | ✅ Limited |
| Production price | $79/mo flat | $6/user/mo | $$$$ | $$ |

---

## Installation

### One-liner (Ubuntu / Debian)

```bash
curl -fsSL https://raw.githubusercontent.com/flyingwest/defenderlink-mesh/main/install.sh | sudo bash
```

### Docker

```bash
docker run -d \
  --name defenderlink-mesh \
  --network host \
  --cap-add NET_ADMIN \
  -v defenderlink-data:/var/lib/defenderlink \
  -e "JAVA_TOOL_OPTIONS=-Dmesh.node.public-endpoint=YOUR_IP:51820" \
  wpospace/defenderlink-mesh:latest
```

### Kubernetes (K3s + Multus)

```bash
kubectl apply -k k8s/overlays/your-node
```

See [INSTALL.md](INSTALL.md) for all installation methods.

---

## Pricing

| Tier | Price | Nodes | Support |
|---|---|---|---|
| **Community** | Free forever | 3 nodes | GitHub Issues |
| **Professional** | $79/month | 25 nodes | Priority email (24h SLA) |
| **Enterprise** | Custom | Unlimited | Dedicated engineer + custom SLA |

The core is always free and open source under the MIT license. The subscription covers production support, not the software itself.

→ [Start Free 14-Day Trial](https://defenderlink.io/pricing)

---

## Technical Specifications

| Component | Technology |
|---|---|
| Runtime | Java 24, Quarkus 3.x |
| Storage | RocksDB (embedded) |
| Consensus | Raft (custom implementation) |
| Discovery | UDP gossip broadcast |
| Encryption | WireGuard — Noise IK, ChaCha20-Poly1305 |
| Identity | Ed25519 (BouncyCastle) |
| Ledger | SHA-256 Merkle chain |
| API | REST (Quarkus RESTEasy Reactive) |
| Dashboard | React 18 + Vite |
| Package | .deb (systemd), Docker, Kubernetes |
| Platforms | Ubuntu 20.04+, Debian 11+, any Linux with WireGuard |
| Architecture | x86-64, ARM64 |

---

## Links

- **Website:** https://defenderlink.io
- **GitHub:** https://github.com/wpotech/defenderlink-mesh
- **Docker:** https://hub.docker.com/r/wpospace/defenderlink-mesh
- **Install guide:** [INSTALL.md](INSTALL.md)
- **Pricing:** https://defenderlink.io/pricing
- **Support:** support@wpotech.com
- **Enterprise sales:** sales@wpotech.com

---

*No controller. No cloud. No trust by default.*

*© 2026 WPO Tech. MIT License.*
