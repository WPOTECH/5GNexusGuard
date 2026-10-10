# 5GNexusGuard — Kubernetes / Docker Deployment

Deployment manifests for 5GNexusGuard on K3s with Multus CNI.

## Directory Structure

```
k8s/
├── Dockerfile                    # Container image
├── docker-compose.yml            # Local two-node testing
├── netplan/
│   └── 60-defenderlink.yaml     # Host netplan config for WireGuard routing
└── base/                         # Kustomize base
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── network-attachment.yaml  # Multus NetworkAttachmentDefinition
│   ├── daemonset.yaml
│   └── service-pvc.yaml
└── overlays/
    ├── polaris/                  # Polaris node (192.168.5.104)
    │   ├── kustomization.yaml
    │   ├── configmap.yaml
    │   └── patch-multus.yaml
    └── vm/                       # VM node (192.168.4.94)
        ├── kustomization.yaml
        ├── configmap.yaml
        └── patch-multus.yaml
```

---

## Prerequisites

### 1. K3s with Multus

```bash
# Install K3s
curl -sfL https://get.k3s.io | sh -

# Install Multus
kubectl apply -f https://raw.githubusercontent.com/k8s-sigs/multus-cni/master/deployments/multus-daemonset.yml
```

### 2. WireGuard kernel module on each node

```bash
# Load now
sudo modprobe wireguard

# Persist across reboots
echo "wireguard" | sudo tee /etc/modules-load.d/wireguard.conf

# Verify
lsmod | grep wireguard
```

### 3. Netplan (optional but recommended)

```bash
sudo cp netplan/60-defenderlink.yaml /etc/netplan/
# Edit master interface name if needed
sudo netplan apply
```

---

## Build the Docker Image

```bash
# Build the JAR first
mvn clean package -DskipTests -Dquarkus.package.jar.type=uber-jar

# Build and push image
docker build -t wpospace/defenderlink-mesh:1.0.0 -f k8s/Dockerfile .
docker push wpospace/defenderlink-mesh:1.0.0

# Or load locally for K3s
docker save wpospace/defenderlink-mesh:1.0.0 | sudo k3s ctr images import -
```

---

## Deploy with Kustomize

### Update node names first

Get your actual K3s node names:
```bash
kubectl get nodes
```

Edit `overlays/polaris/kustomization.yaml` and `overlays/vm/kustomization.yaml`
and replace `kubernetes.io/hostname` values with your actual node names.

### Update host NIC name

Check your host interface name:
```bash
ip link show | grep -v lo | grep UP
```

Edit `base/network-attachment.yaml` and replace `"master": "eth0"` with your interface.

### Deploy Polaris node

```bash
kubectl apply -k k8s/overlays/polaris
```

### Deploy VM node

```bash
kubectl apply -k k8s/overlays/vm
```

### Verify

```bash
# Watch pods come up
kubectl -n defenderlink get pods -w

# Check Multus attached both interfaces (eth0 + wg-ext)
kubectl -n defenderlink exec -it $(kubectl -n defenderlink get pod -o name | head -1) \
    -- ip addr show

# Check WireGuard
kubectl -n defenderlink exec -it POD_NAME -- wg show

# Access dashboard
kubectl -n defenderlink port-forward svc/defenderlink-mesh 8443:8443
# Open http://localhost:8443
```

---

## Local Testing with Docker Compose

Test two nodes on the same machine:

```bash
# Load WireGuard module
sudo modprobe wireguard

# Build image
docker build -t wpospace/defenderlink-mesh:1.0.0 -f k8s/Dockerfile .

# Start both nodes
POLARIS_IP=192.168.5.104 VM_IP=192.168.4.94 docker compose -f k8s/docker-compose.yml up -d

# Watch logs
docker logs -f defenderlink-polaris
docker logs -f defenderlink-vm

# Polaris dashboard: http://localhost:8443
# VM dashboard:     http://localhost:8444
```

---

## How Multus Works Here

```
K3s Node
├── eth0 (host NIC — 192.168.5.104)
│   └── macvlan → wg-ext (inside pod)
│       └── WireGuard interfaces created here
│           ├── dl-c-keycloak (10.200.1.1/30)
│           └── dl-o-postgres (10.200.2.1/30)
└── flannel0 (K3s pod network)
    └── eth0 (inside pod — 10.42.x.x)
        └── Dashboard :8443, Gossip :9450
```

The pod gets **two network interfaces**:
- `eth0` — K3s/Flannel pod network for dashboard and gossip
- `wg-ext` — Multus macvlan directly on the host NIC for WireGuard

WireGuard UDP packets arrive on the real host IP (`192.168.5.104:51820`)
via the `wg-ext` interface. No `hostNetwork: true` needed.

---

## Troubleshooting

### Pod stuck in Init

```bash
kubectl -n defenderlink describe pod POD_NAME
# Check: wireguard-module-loader init container logs
kubectl -n defenderlink logs POD_NAME -c wireguard-module-loader
```

WireGuard module may not be available. On the node:
```bash
sudo apt install wireguard
sudo modprobe wireguard
```

### Multus interface not attached

```bash
# Check Multus is running
kubectl -n kube-system get pods | grep multus

# Check NetworkAttachmentDefinition exists
kubectl -n defenderlink get network-attachment-definitions

# Check pod annotation
kubectl -n defenderlink get pod POD_NAME -o jsonpath='{.metadata.annotations}'
```

### WireGuard handshake not completing

```bash
# Check both sides have the correct endpoint
kubectl -n defenderlink exec POD_NAME -- wg show

# Verify UDP 51820 is reachable between nodes
kubectl -n defenderlink exec POD_NAME -- nc -u -z 192.168.4.94 51820
```

### Permission denied on ip link

```bash
# Verify NET_ADMIN capability is present
kubectl -n defenderlink exec POD_NAME -- cat /proc/self/status | grep Cap
# CapEff should include 0x0000000000003000 (NET_ADMIN + NET_RAW)
```

---

## Security Notes

- Only the `wireguard-module-loader` init container runs privileged — and only to `modprobe wireguard`
- The main container has only `NET_ADMIN` and `NET_RAW` — not full privileges
- All other capabilities are dropped (`drop: ALL`)
- The WireGuard private keys are stored in the `defenderlink-data` PVC — back it up
- Ledger data (node identities, service records) is in the same PVC

---

## Wipe and Reset

```bash
# Stop and delete everything
kubectl delete -k k8s/overlays/polaris
kubectl delete -k k8s/overlays/vm

# Delete PVC (WARNING: wipes ledger and keys)
kubectl -n defenderlink delete pvc defenderlink-data

# Redeploy fresh
kubectl apply -k k8s/overlays/polaris
kubectl apply -k k8s/overlays/vm
```
