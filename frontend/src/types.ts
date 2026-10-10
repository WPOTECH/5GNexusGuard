/* ═══════════════════════════════════════════════════════════════════════════
   5GNexusGuard — Type Definitions
   ═══════════════════════════════════════════════════════════════════════════ */

export interface NodeRecord {
  nodeId: string;
  wireguardPubkey: string;
  endpoints: string[];
  capabilities: string[];
  displayName: string;
  registeredAt: string;
  active: boolean;
  online: boolean;   // live gossip status — true = seen in last 30s
  registered: boolean;  // ← NEW
}

export interface ServicePolicy {
  encrypted: boolean;
  maxBandwidth: string | null;
  maxConcurrentConns: number | null;
  expiresAt: string | null;
}

export interface ServiceRecord {
  serviceId: string;
  ownerNodeId: string;
  protocol: string;
  localBind: string;
  assignedPort: number;
  allowedNodes: string[];
  policy: ServicePolicy | null;
  exposedAt: string;
  active: boolean;
}

export interface ActiveTunnel {
  serviceId: string;
  ifName: string;
  localIp: string;
  localPublicKey: string;
  listenPort: number;
  peerNodeId: string;
  role: string;
  egressPort: number;
  peerTunnelIp: string;
  interceptLocalPort: number;
  state: string;
  error: string | null;
  up: boolean;
}

export interface MeshStatus {
  nodeId: string;
  shortId: string;
  raftState: 'LEADER' | 'FOLLOWER' | 'CANDIDATE';
  raftTerm: number;
  leader: string;
  chainHeight: number;
  knownPeers: number;
  registeredNodes: number;
  activeServices: number;
  activeTunnels: number;
}

export interface Block {
  index: number;
  hash: string;
  prevHash: string;
  merkleRoot: string;
  authorNodeId: string;
  authorSignature: string;
  entries: LedgerEntry[];
  timestamp: string;
}

export interface LedgerEntry {
  type: string;
  authorNodeId: string;
  timestamp: string;
  [key: string]: unknown;
}

export interface PeerInfo {
  nodeId: string;
  address: string;
  port: number;
  pubkey: string;
  lastSeen: number;
}

// Request types
export interface RegisterRequest {
  displayName?: string;
  endpoints: string[];
  capabilities: string[];
}

export interface ExposeRequest {
  serviceId: string;
  protocol: string;
  localBind: string;
  allowedNodes: string[];
}

export interface RevokeRequest {
  reason: string;
}

export interface ConnectResponse {
  status: string;
  serviceId: string;
  localEndpoint: string;
  tunnelInterface: string;
  remoteEndpoint: string;
}

export type ViewId = 'overview' | 'nodes' | 'services' | 'tunnels' | 'ledger';
