import React, { useState } from 'react';
import { Badge, Card, Empty, InfoRow, SectionHeader } from './components';
import { NodeCard } from './NodeCard';
import { TunnelCard } from './TunnelCard';
import { T } from './theme';
import type { ActiveTunnel, NodeRecord, ServiceRecord } from './types';
import { short } from './utils';

interface Props {
  localId: string;
  nodes: NodeRecord[] | null;
  tunnels: Record<string, ActiveTunnel> | null;
  services: ServiceRecord[];
  onRegister: (id: string) => void;
  onRemove: (id: string) => void;
  onDisconnect: (id: string) => void;
}

export function Topology({ localId, nodes, tunnels, services, onRegister, onRemove, onDisconnect }: Props) {
  const [selection, setSelection] = useState<string>();
  const selected = nodes?.find(node => node.nodeId === (selection ?? localId));
  const links = Object.entries(tunnels ?? {});
  const selectedLinks = links.filter(([, link]) => selected &&
    (selected.nodeId === localId || link.peerNodeId === selected.nodeId));
  const permissions = selected?.registered ? services.filter(service => service.active &&
    (service.ownerNodeId === selected.nodeId || service.allowedNodes?.includes(selected.nodeId))) : [];

  return <>
    <SectionHeader title="Mesh topology" />
    <p>Discovery and ledger membership as seen by this node. Links show locally reported STANDARD tunnel state.</p>
    {(!nodes || !tunnels) && <p role="status">Some topology data is unavailable.</p>}
    {nodes && <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
      {nodes.map(node => (
        <button key={node.nodeId} type="button" aria-pressed={selected?.nodeId === node.nodeId}
          onClick={() => setSelection(node.nodeId)}
          style={{ padding: 10, background: T.bg1, color: T.text, border: `1px solid ${selected?.nodeId === node.nodeId ? T.accent : T.border}` }}>
          {node.nodeId === localId ? 'This node' : node.registered ? (node.displayName || short(node.nodeId)) : short(node.nodeId)}
          {' · '}
          {node.registered ? 'Ledger member' : 'Unverified'}
          {' · '}
          {node.online ? 'Seen' : 'Not recently seen'}
        </button>
      ))}
    </div>}
    {tunnels && <Card style={{ marginBottom: 16 }}>
      {links.length === 0 && <Empty text="No local STANDARD tunnel entries." />}
      {links.map(([id, link]) => (
        <div key={id} style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 10, padding: 6 }}>
          <span>This node</span><span aria-hidden="true">←→</span>
          <button type="button" disabled={!nodes?.some(node => node.nodeId === link.peerNodeId)}
            onClick={() => setSelection(link.peerNodeId)}>{short(link.peerNodeId)}</button>
          <span>{link.serviceId}</span>
          <Badge color={link.state === 'ACTIVE' ? T.accent : T.warn}>{link.state || 'Unknown'}</Badge>
        </div>
      ))}
    </Card>}
    {selected && <>
      <NodeCard key={selected.nodeId} node={selected} isSelf={selected.nodeId === localId}
        onRegister={onRegister} onRemove={onRemove} />
      <Card style={{ marginTop: 12, overflowWrap: 'anywhere' }}>
        <InfoRow label="Identity" value={selected.nodeId} />
        <InfoRow label="Ledger service permissions" value={permissions.map(service => service.serviceId).join(', ') || 'None shown'} />
      </Card>
      {selectedLinks.map(([id, link]) => <TunnelCard key={id} tunnel={link} onDisconnect={onDisconnect} />)}
    </>}
  </>;
}
