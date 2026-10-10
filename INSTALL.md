# 5GNexusGuard — Installation Guide

Three ways to install 5GNexusGuard. Choose what fits your environment.

---

## Method 1 — One-Line Install (Recommended)

Supports Ubuntu 20.04+, Debian 11+, RHEL/Rocky/AlmaLinux 8+.

```bash
curl -fsSL https://raw.githubusercontent.com/flyingwest/defenderlink-mesh/main/install.sh | sudo bash
```

With options:

```bash
# Set your public WireGuard endpoint explicitly
curl -fsSL .../install.sh | sudo bash -s -- \
  --endpoint 192.168.5.104:51820 \
  --port 8443
```

The script will:
- Detect your OS and architecture
- Install Java 21+ and wireguard-tools if missing
- Download and install the correct package from GitHub Releases
- Load the WireGuard kernel module and persist it across reboots
- Auto-detect your LAN IP as the WireGuard endpoint
- Enable and start the systemd service

---

## Method 2 — Manual .deb Install (Ubuntu / Debian)

### Prerequisites

```bash
# Java 21+
sudo apt install openjdk-21-jre-headless -y

# WireGuard
sudo apt install wireguard wireguard-tools -y
sudo modprobe wireguard
echo "wireguard" | sudo tee /etc/modules-load.d/wireguard.conf
```

### Install

Download the latest `.deb` from [GitHub Releases](https://github.com/flyingwest/defenderlink-mesh/releases):

```bash
wget https://github.com/flyingwest/defenderlink-mesh/releases/latest/download/defenderlink-mesh_1.0.0_amd64.deb
sudo apt install -y ./defenderlink-mesh_1.0.0_amd64.deb
```

### Configure

```bash
sudo nano /etc/defenderlink/defenderlink.conf
```

Add your node's public endpoint:

```bash
JAVA_OPTS=-Dmesh.node.public-endpoint=192.168.5.104:51820
```

### Start

```bash
sudo chown -R root:root /var/lib/defenderlink
sudo systemctl enable --now defenderlink-mesh
sudo systemctl status defenderlink-mesh
```

### Verify

```bash
# Service status
sudo systemctl status defenderlink-mesh

# Live logs
journalctl -u defenderlink-mesh -f

# Dashboard
curl http://localhost:8443/api/status
```

---

## Method 3 — Docker / Docker Compose

### Prerequisites

```bash
# Docker
curl -fsSL https://get.docker.com | sh

# WireGuard kernel module on the HOST
sudo modprobe wireguard
echo "wireguard" | sudo tee /etc/modules-load.d/wireguard.conf
```

> **Note:** The Docker container uses the host kernel's WireGuard module.
> The module must be loaded on the host — the container only needs the CLI tools.

### Single node with Docker

```bash
docker run -d \
  --name defenderlink-mesh \
  --network host \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --restart unless-stopped \
  -v defenderlink-data:/var/lib/defenderlink \
  -e "JAVA_TOOL_OPTIONS=-Dmesh.node.public-endpoint=192.168.5.104:51820" \
  wpospace/defenderlink-mesh:latest
```

```bash
# Logs
docker logs -f defenderlink-mesh

# Dashboard
open http://localhost:8443

# Stop
docker stop defenderlink-mesh

# Wipe ledger (fresh start)
docker stop defenderlink-mesh && docker volume rm defenderlink-data
```

### Two nodes with Docker Compose

Clone the repo:

```bash
git clone https://github.com/flyingwest/defenderlink-mesh.git
cd defenderlink-mesh
```

Start both nodes:

```bash
POLARIS_IP=192.168.5.104 VM_IP=192.168.4.94 \
  docker compose up -d

# Polaris dashboard: http://localhost:8443
# VM dashboard:     http://localhost:8444
```

Watch logs:

```bash
docker compose logs -f
```

Stop:

```bash
docker compose down
```

### Build the image yourself

```bash
# Build the JAR first
mvn clean package -DskipTests -Dquarkus.package.jar.type=uber-jar

# Build the Docker image
docker build -t wpospace/defenderlink-mesh:1.0.0 .

# Push to DockerHub (replace with your account)
docker push wpospace/defenderlink-mesh:1.0.0
```

---

## Method 4 — K3s + Multus (Kubernetes)

For K3s clusters with Multus CNI. Gives each pod its own WireGuard-capable
network interface without `hostNetwork: true`.

### Prerequisites

```bash
# K3s
curl -sfL https://get.k3s.io | sh -

# Multus
kubectl apply -f https://raw.githubusercontent.com/k8s-sigs/multus-cni/master/deployments/multus-daemonset.yml

# WireGuard on each node
sudo modprobe wireguard
echo "wireguard" | sudo tee /etc/modules-load.d/wireguard.conf
```

### Configure

Edit `k8s/base/network-attachment.yaml` — set `master` to your host NIC:

```bash
# Find your host NIC name
ip link show | grep -E "^[0-9]+:" | grep -v lo
```

Edit `k8s/overlays/polaris/kustomization.yaml` — set your node hostname:

```bash
kubectl get nodes
```

Edit `k8s/overlays/polaris/configmap.yaml` — set your node's public endpoint:

```yaml
data:
  java-opts: "-Dmesh.node.public-endpoint=192.168.5.104:51820"
```

### Deploy

```bash
# Deploy to Polaris node
kubectl apply -k k8s/overlays/polaris

# Deploy to VM node
kubectl apply -k k8s/overlays/vm

# Watch pods
kubectl -n defenderlink get pods -w

# Access dashboard
kubectl -n defenderlink port-forward svc/defenderlink-mesh 8443:8443
```

See [k8s/README.md](k8s/README.md) for full Kubernetes documentation.

---

## Post-Install: First Two-Node Setup

After installing on two machines:

**On Machine A (service owner):**
1. Open `http://MACHINE_A_IP:8443`
2. Click **Register Node** → enter your endpoint (`192.168.x.x:51820`)
3. Click **Expose Service** → fill in service ID, protocol, local bind, authorized peers

**On Machine B (connector):**
1. Open `http://MACHINE_B_IP:8443`
2. Click **Register Node** → enter your endpoint
3. Wait for gossip discovery (~5 seconds) — Machine A appears as ONLINE
4. Click **Connect** on the service card

The WireGuard tunnel comes up automatically. Traffic flows encrypted between the two nodes.

---

## Configuration Reference

`/etc/defenderlink/defenderlink.conf`

| Variable | Default | Description |
|---|---|---|
| `QUARKUS_HTTP_PORT` | `8443` | Dashboard and API port |
| `MESH_DATA_DIR` | `/var/lib/defenderlink` | Ledger, keys, WireGuard configs |
| `JAVA_OPTS` | — | JVM options — **set your endpoint here** |

**Required for tunnels to work:**

```bash
JAVA_OPTS=-Dmesh.node.public-endpoint=YOUR_IP:51820
```

---

## Uninstall

```bash
# Stop and remove service
sudo systemctl stop defenderlink-mesh
sudo apt remove defenderlink-mesh -y        # Debian/Ubuntu
# sudo dnf remove defenderlink-mesh -y     # RHEL/Rocky

# Remove data (WARNING: wipes ledger and identity keys)
sudo rm -rf /var/lib/defenderlink

# Docker
docker stop defenderlink-mesh
docker rm defenderlink-mesh
docker volume rm defenderlink-data

# K3s
kubectl delete -k k8s/overlays/polaris
kubectl delete -k k8s/overlays/vm
kubectl -n defenderlink delete pvc defenderlink-data
```

---

## Troubleshooting

### Service won't start

```bash
journalctl -u defenderlink-mesh -n 50 --no-pager
```

Common causes:
- `/var/lib/defenderlink` not owned by root → `sudo chown -R root:root /var/lib/defenderlink`
- `/opt/defenderlink/logs` missing → `sudo mkdir -p /opt/defenderlink/logs`
- Wrong Java version → `java -version` (needs 21+)

### Tunnel fails — `Operation not permitted`

```bash
# Verify WireGuard module is loaded
lsmod | grep wireguard

# Load it
sudo modprobe wireguard
```

### Tunnel fails — `Unable to find port of endpoint`

The `JAVA_OPTS` endpoint is missing or malformed. Check:

```bash
grep JAVA_OPTS /etc/defenderlink/defenderlink.conf
# Must be: JAVA_OPTS=-Dmesh.node.public-endpoint=YOUR_IP:51820
```

### Nodes not discovering each other

```bash
# Check gossip UDP 9450 is not firewalled
sudo ufw allow 9450/udp
sudo ufw allow 51820/udp
sudo ufw allow 8443/tcp
```

### Signature verification fails (403)

Both nodes must be registered in the same ledger. After wiping the ledger,
re-register both nodes via the dashboard.
