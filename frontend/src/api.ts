import type {
  MeshStatus, NodeRecord, ServiceRecord, ActiveTunnel,
  Block, PeerInfo, RegisterRequest, ExposeRequest,
  RevokeRequest, ConnectResponse,
} from './types';

const BASE = '/api';

async function get<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.json();
}

async function del<T>(path: string): Promise<T> {
  const res = await fetch(BASE + path, { method: 'DELETE' });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(err.error || `HTTP ${res.status}`);
  }
  return res.status === 204 ? ({} as T) : res.json();
}

export const api = {
  // Status
  getStatus: () => get<MeshStatus>('/status'),
  getIdentity: () => get<{ nodeId: string; publicKey: string }>('/identity'),

  // Nodes
  listNodes: () => get<NodeRecord[]>('/nodes'),
  registerNode: (req: RegisterRequest) => post<{ status: string }>('/node/register', req),
  deregisterNode: () => post<{ status: string }>('/node/deregister'),

  // Services
  listServices: () => get<ServiceRecord[]>('/services'),
  listAccessible: () => get<ServiceRecord[]>('/services/accessible'),
  listExposed: () => get<ServiceRecord[]>('/services/exposed'),
  exposeService: (req: ExposeRequest) => post<{ status: string; serviceId: string; assignedPort: number }>('/services/expose', req),
  revokeService: (id: string, req: RevokeRequest) => post<{ status: string }>(`/services/${id}/revoke`, req),

  // Tunnels
  listTunnels: () => get<Record<string, ActiveTunnel>>('/tunnels'),
  connect: (serviceId: string) => post<ConnectResponse>(`/connect/${encodeURIComponent(serviceId)}`),
  disconnect: (serviceId: string) => post<{ status: string }>(`/disconnect/${encodeURIComponent(serviceId)}`),

  // Ledger
  getBlock: (index: number) => get<Block>(`/ledger/block/${index}`),
  getLedgerInfo: () => get<{ height: number; lastBlockHash: string }>('/ledger/info'),

  // Peers
  listPeers: () => get<PeerInfo[]>('/peers'),

  // Delete actions
  removeNode:    (nodeId: string) =>
      del<{ status: string }>(`/nodes/${nodeId}`),
  deleteTunnel:  (serviceId: string) =>
      del<{ status: string }>(`/tunnels/${encodeURIComponent(serviceId)}`),

};
