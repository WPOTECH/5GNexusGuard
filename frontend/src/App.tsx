import React, { useState, useEffect, useCallback } from 'react';
import { T, GLOBAL_CSS } from './theme';
import { api } from './api';
import type { MeshStatus, NodeRecord, ServiceRecord, ActiveTunnel, Block, ViewId } from './types';
import { short } from './utils';
import {
  ScanlineOverlay, Indicator, Badge, StatBox, SectionHeader,
  Btn, Card, Empty, Toast,
} from './components';
import { NodeCard } from './NodeCard';
import { ServiceCard } from './ServiceCard';
import { TunnelCard } from './TunnelCard';
import { RegisterNodeModal, ExposeServiceModal } from './Modals';

const VIEWS: { id: ViewId; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'nodes', label: 'Nodes' },
  { id: 'services', label: 'Services' },
  { id: 'tunnels', label: 'Tunnels' },
  { id: 'ledger', label: 'Ledger' },
];



export default function App() {
  const [view, setView] = useState<ViewId>('overview');
  const [status, setStatus] = useState<MeshStatus | null>(null);
  const [nodes, setNodes] = useState<NodeRecord[]>([]);
  const [services, setServices] = useState<ServiceRecord[]>([]);
  const [tunnels, setTunnels] = useState<Record<string, ActiveTunnel>>({});
  const [blocks, setBlocks] = useState<Block[]>([]);
  const [toast, setToast] = useState<{ msg: string; type: 'success' | 'error'; k: number } | null>(null);
  const [showRegister, setShowRegister] = useState(false);
  const [showExpose, setShowExpose] = useState(false);
  const [registeringNodeId, setRegisteringNodeId] = useState<string | null>(null);

  const notify = useCallback((msg: string, type: 'success' | 'error' = 'success') => {
    setToast({ msg, type, k: Date.now() });
  }, []);

  /* ═══ Data fetching ═══ */
  const refresh = useCallback(async () => {
    const [st, nd, sv, tn] = await Promise.allSettled([
      api.getStatus(), api.listNodes(), api.listServices(), api.listTunnels(),
    ]);
    if (st.status === 'fulfilled') setStatus(st.value);
    if (nd.status === 'fulfilled') {
      const val = nd.value;
      setNodes(Array.isArray(val) ? val : Object.values(val as Record<string, NodeRecord>));
    }
    if (sv.status === 'fulfilled') {
      const val = sv.value;
      setServices(Array.isArray(val) ? val : Object.values(val as Record<string, ServiceRecord>));
    }
    if (tn.status === 'fulfilled') setTunnels(tn.value || {});
  }, []);

  useEffect(() => {
    refresh();
    const iv = setInterval(refresh, 5000);
    return () => clearInterval(iv);
  }, [refresh]);

  const loadBlocks = useCallback(async () => {
    const height = status?.chainHeight || 0;
    const bs: Block[] = [];
    for (let i = Math.max(0, height - 19); i <= height; i++) {
      try { bs.push(await api.getBlock(i)); } catch { /* skip */ }
    }
    setBlocks(bs.reverse());
  }, [status?.chainHeight]);

  useEffect(() => { if (view === 'ledger') loadBlocks(); }, [view, loadBlocks]);

  /* ═══ Actions ═══ */
  const handleRegister = async (data: Parameters<typeof api.registerNode>[0]) => {
    try {
      await api.registerNode(data);
      notify('Node registration submitted to ledger');
      setShowRegister(false);
      setRegisteringNodeId(null);
      refresh();
    } catch (e: any) {
      notify(e.message, 'error');
    }
  };

  const handleRegisterNode = useCallback((nodeId: string) => {
    setRegisteringNodeId(nodeId);
    setShowRegister(true);
  }, []);

  const handleExpose = async (data: Parameters<typeof api.exposeService>[0]) => {
    const res = await api.exposeService(data);
    notify(`Service "${data.serviceId}" exposed on port ${res.assignedPort}`);
    refresh();
  };

  const handleConnect = async (svcId: string) => {
    try {
      const res = await api.connect(svcId);
      notify(`Connected to ${svcId} at ${res.localEndpoint}`);
      refresh();
    } catch (e: any) {
      notify(e.message || 'Connection failed', 'error');
    }
  };

  const handleRevoke = async (svcId: string) => {
    await api.revokeService(svcId, { reason: 'manual revocation' });
    notify('Service revoked from ledger');
    refresh();
  };

  const handleRemoveNode = useCallback(async (nodeId: string) => {
    try {
      await api.removeNode(nodeId);
      notify('Node removed');
      refresh();
    } catch (e: any) {
      notify(e.message, 'error');
    }
  }, [notify, refresh]);

  const handleDisconnect = useCallback(async (serviceId: string) => {
    try {
      await api.deleteTunnel(serviceId);
      notify('Tunnel disconnected');
      refresh();
    } catch (e: any) {
      notify(e.message, 'error');
    }
  }, [notify, refresh]);

  /* ═══ Derived state ═══ */
  const tunnelArr = Object.entries(tunnels);
  const activeNodes = nodes.filter(n => n.active).length;
  const activeSvcs = services.filter(s => s.active).length;
  const activeTunnels = tunnelArr.filter(([, t]) => t.state === 'ACTIVE').length;
  const myNodeId = status?.nodeId || '';

  const raftColor = status?.raftState === 'LEADER' ? T.accent
    : status?.raftState === 'CANDIDATE' ? T.warn : T.info;

  return (
    <div style={{ fontFamily: T.font, background: T.bg0, color: T.text, minHeight: '100vh', fontSize: 12, lineHeight: 1.5 }}>
      <style>{GLOBAL_CSS}</style>
      <ScanlineOverlay />

      {/* ═══════════════════════════════════════ HEADER ═══ */}
      <header style={{
        background: T.bg1, borderBottom: `1px solid ${T.border}`, padding: '0 24px',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: 52,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 30, height: 30, borderRadius: 4,
            background: `linear-gradient(135deg,${T.accent} 0%,${T.accentDim} 100%)`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 13, fontWeight: 700, color: '#000', fontFamily: T.display,
          }}>5G</div>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: T.textHi, fontFamily: T.display, letterSpacing: 0.5 }}>
              5GNexusGuard
            </div>
            <div style={{ fontSize: 9, color: T.textDim, letterSpacing: 2.5, textTransform: 'uppercase' }}>
              Decentralized zero trust overlay
            </div>
          </div>
        </div>
        {status && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, fontSize: 10, color: T.textDim }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
              <Indicator color={raftColor} pulse={status.raftState === 'LEADER'} />
              Raft: {status.raftState}
            </span>
            <span>Term {status.raftTerm}</span>
            <span>Leader: {status.leader === 'none' ? '\u2014' : short(status.leader)}</span>
            <span style={{ color: T.textDim }}>|</span>
            <span>Node: {status.shortId}</span>
          </div>
        )}
      </header>

      <div style={{ display: 'flex', minHeight: 'calc(100vh - 52px)' }}>

        {/* ═══════════════════════════════════════ SIDEBAR ═══ */}
        <nav style={{
          width: 180, background: T.bg1, borderRight: `1px solid ${T.border}`,
          padding: '16px 0', flexShrink: 0,
        }}>
          {VIEWS.map(v => (
            <button key={v.id} onClick={() => setView(v.id)} style={{
              display: 'block', width: '100%', padding: '10px 20px', border: 'none',
              textAlign: 'left', fontSize: 11, fontFamily: T.font,
              fontWeight: view === v.id ? 600 : 400, letterSpacing: 0.8,
              textTransform: 'uppercase',
              background: view === v.id ? T.accentBg : 'transparent',
              color: view === v.id ? T.accent : T.textDim,
              borderLeft: view === v.id ? `2px solid ${T.accent}` : '2px solid transparent',
            }}>{v.label}</button>
          ))}

          <div style={{ borderTop: `1px solid ${T.border}`, margin: '16px 20px', opacity: 0.5 }} />

          <div style={{ padding: '0 16px', display: 'flex', flexDirection: 'column', gap: 6 }}>
            <Btn variant="primary" small onClick={() => setShowRegister(true)} style={{ width: '100%' }}>
              Register Node
            </Btn>
            <Btn small onClick={() => setShowExpose(true)} style={{ width: '100%' }}>
              Expose Service
            </Btn>
          </div>

          {/* Sidebar stats */}
          <div style={{ padding: '20px 16px 0', fontSize: 10, color: T.textDim }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span>Nodes</span><span style={{ color: T.accent }}>{activeNodes}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span>Services</span><span style={{ color: T.info }}>{activeSvcs}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span>Tunnels</span><span style={{ color: T.purple }}>{activeTunnels}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span>Chain</span><span style={{ color: T.warn }}>#{status?.chainHeight ?? 0}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Peers</span><span style={{ color: T.accentDim }}>{status?.knownPeers ?? 0}</span>
            </div>
          </div>
        </nav>

        {/* ═══════════════════════════════════════ MAIN CONTENT ═══ */}
        <main style={{ flex: 1, padding: 24, maxWidth: 1200, overflow: 'auto' }}>

          {/* ═══ OVERVIEW ═══ */}
          {view === 'overview' && (
            <>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(170px,1fr))', gap: 12, marginBottom: 24 }}>
                <StatBox icon={'\u25C9'} label="Nodes" value={activeNodes} accent={T.accent} />
                <StatBox icon={'\u2630'} label="Services" value={activeSvcs} accent={T.info} />
                <StatBox icon={'\u2550'} label="Tunnels" value={activeTunnels} accent={T.purple} />
                <StatBox icon={'\u26D3'} label="Chain" value={`#${status?.chainHeight ?? 0}`} accent={T.warn} />
                <StatBox icon={'\u2637'} label="Gossip Peers" value={status?.knownPeers ?? 0} accent={T.accentDim} />
                <StatBox icon={'\u2694'} label="Raft" value={status?.raftState ?? '\u2014'} accent={raftColor} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div>
                  <SectionHeader title="Mesh nodes">
                    <Btn small variant="ghost" onClick={() => setView('nodes')}>View all</Btn>
                  </SectionHeader>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {nodes.slice(0, 4).map(n => <NodeCard
                                                  key={n.nodeId}
                                                  node={n}
                                                  onRemove={handleRemoveNode}
                                                  onRegister={handleRegisterNode}
                                                  isSelf={n.nodeId === status?.nodeId}
                                                />)}
                    {nodes.length === 0 && <Empty text="No nodes registered. Register this node to join the mesh." />}
                  </div>
                </div>
                <div>
                  <SectionHeader title="Active services">
                    <Btn small variant="ghost" onClick={() => setView('services')}>View all</Btn>
                  </SectionHeader>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {services.filter(s => s.active).slice(0, 4).map(s => (
                      <ServiceCard key={s.serviceId} svc={s} isMine={s.ownerNodeId === myNodeId}
                        onConnect={handleConnect} onRevoke={handleRevoke} />
                    ))}
                    {services.filter(s => s.active).length === 0 && <Empty text="No services exposed yet." />}
                  </div>
                </div>
              </div>
              {tunnelArr.length > 0 && (
                <div style={{ marginTop: 20 }}>
                  <SectionHeader title="Active tunnels">
                    <Btn small variant="ghost" onClick={() => setView('tunnels')}>View all</Btn>
                  </SectionHeader>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(380px,1fr))', gap: 12 }}>
                    {tunnelArr.slice(0, 4).map(([id, t]) => (
                      <TunnelCard key={id} id={id} tunnel={t} onDisconnect={handleDisconnect} />
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {/* ═══ NODES ═══ */}
          {view === 'nodes' && (
            <>
              <SectionHeader title={`Mesh nodes (${nodes.length})`}>
                <Btn small variant="primary" onClick={() => setShowRegister(true)}>+ Register</Btn>
              </SectionHeader>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(380px,1fr))', gap: 12 }}>
                {nodes.map(n => (
                                <NodeCard
                                  key={n.nodeId}
                                  node={n}
                                  onRemove={handleRemoveNode}
                                  onRegister={handleRegisterNode}
                                  isSelf={n.nodeId === status?.nodeId}
                                />
                              ))}
              </div>
              {nodes.length === 0 && <Empty text="No nodes registered in the mesh ledger." />}
            </>
          )}

          {/* ═══ SERVICES ═══ */}
          {view === 'services' && (
            <>
              <SectionHeader title={`Services (${services.length})`}>
                <Btn small variant="primary" onClick={() => setShowExpose(true)}>+ Expose Service</Btn>
              </SectionHeader>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(380px,1fr))', gap: 12 }}>
                {services.map(s => (
                  <ServiceCard key={s.serviceId} svc={s} isMine={s.ownerNodeId === myNodeId}
                    onConnect={handleConnect} onRevoke={handleRevoke} />
                ))}
              </div>
              {services.length === 0 && <Empty text="No services in the mesh. Expose a local service to get started." />}
            </>
          )}

          {/* ═══ TUNNELS ═══ */}
          {view === 'tunnels' && (
            <>
              <SectionHeader title={`Active tunnels (${tunnelArr.length})`} />
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(380px,1fr))', gap: 12 }}>
                {tunnelArr.map(([id, t]) => (
                  <TunnelCard key={id} id={id} tunnel={t} onDisconnect={handleDisconnect} />
                ))}
              </div>
              {tunnelArr.length === 0 && <Empty text="No active tunnels. Connect to a service to create one." />}
            </>
          )}

          {/* ═══ LEDGER ═══ */}
          {view === 'ledger' && (
            <>
              <SectionHeader title="Blockchain ledger">
                <Btn small variant="ghost" onClick={loadBlocks}>{'\u21BB'} Refresh</Btn>
              </SectionHeader>

              <Card style={{ padding: 0, overflow: 'hidden' }}>
                {/* Table header */}
                <div style={{
                  display: 'grid', gridTemplateColumns: '55px 1fr 120px 80px 65px', gap: 12,
                  padding: '10px 12px', borderBottom: `1px solid ${T.borderHi}`,
                  fontSize: 10, color: T.textDim, textTransform: 'uppercase', letterSpacing: 1, fontWeight: 600,
                }}>
                  <span>Block</span><span>Hash</span><span>Author</span><span>Age</span><span>Entries</span>
                </div>
                {/* Block rows */}
                {blocks.map(b => (
                  <div key={b.index} style={{
                    display: 'grid', gridTemplateColumns: '55px 1fr 120px 80px 65px', gap: 12,
                    padding: '8px 12px', borderBottom: `1px solid ${T.border}`,
                    fontSize: 11, color: T.text, fontFamily: T.font, alignItems: 'center',
                  }}>
                    <span style={{ color: T.accent, fontWeight: 600 }}>#{b.index}</span>
                    <span style={{ color: T.textDim, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {b.hash?.substring(0, 40)}...
                    </span>
                    <span>{short(b.authorNodeId)}</span>
                    <span style={{ fontSize: 10 }}>{new Date(b.timestamp).toLocaleTimeString()}</span>
                    <Badge color={T.purple}>{b.entries?.length || 0} txn</Badge>
                  </div>
                ))}
                {blocks.length === 0 && (
                  <div style={{ padding: 30, textAlign: 'center', color: T.textDim, fontSize: 11 }}>
                    Loading ledger blocks...
                  </div>
                )}
              </Card>

              {/* Crypto stack footer */}
              <div style={{
                marginTop: 20, padding: '16px 20px', background: T.bg1,
                border: `1px solid ${T.border}`, borderRadius: 6,
              }}>
                <div style={{
                  fontSize: 9, color: T.textDim, textTransform: 'uppercase',
                  letterSpacing: 2, marginBottom: 10, fontWeight: 600,
                }}>Cryptographic stack</div>
                <div style={{
                  display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(210px,1fr))',
                  gap: 10, fontSize: 10, color: T.textDim,
                }}>
                  <span><Indicator color={T.accent} /> Identity: Ed25519 (self-sovereign)</span>
                  <span><Indicator color={T.info} /> Tunnel: WireGuard (Noise IK)</span>
                  <span><Indicator color={T.purple} /> Symmetric: ChaCha20-Poly1305</span>
                  <span><Indicator color={T.warn} /> Key exchange: Curve25519 via ledger</span>
                  <span><Indicator color={T.accentDim} /> Chain: SHA-256 Merkle</span>
                  <span><Indicator color={T.danger} /> Consensus: Raft leader election</span>
                </div>
              </div>
            </>
          )}

          {/* ═══ Footer ═══ */}
          <div style={{
            marginTop: 32, padding: '12px 16px', borderTop: `1px solid ${T.border}`,
            display: 'flex', justifyContent: 'space-between', fontSize: 9, color: T.textDim, letterSpacing: 1,
          }}>
            <span>5GNexusGuard v1.0.0</span>
            <span>NO CONTROLLER &middot; NO SPOF &middot; PEER-TO-PEER ENCRYPTED</span>
          </div>
        </main>
      </div>

      {/* ═══ Modals ═══ */}
     <RegisterNodeModal
        isOpen={showRegister}
        onClose={() => { setShowRegister(false); setRegisteringNodeId(null); }}
        onSubmit={handleRegister}
        prefilledNodeId={registeringNodeId}
      />
      <ExposeServiceModal isOpen={showExpose} onClose={() => setShowExpose(false)} onSubmit={handleExpose}
        nodes={nodes} myNodeId={myNodeId} />

      {/* ═══ Toast ═══ */}
      {toast && <Toast message={toast.msg} type={toast.type} onDismiss={() => setToast(null)} key={toast.k} />}
    </div>
  );
}
