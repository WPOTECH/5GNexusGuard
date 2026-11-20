import React, { useState } from 'react';
import { T } from './theme';
import { Card, Badge, Indicator, Btn, InfoRow } from './components';
import type { ActiveTunnel } from './types';
import { short } from './utils';

interface Props {
  tunnel: ActiveTunnel;
  onDisconnect: (id: string) => void;
}

export function TunnelCard({ tunnel, onDisconnect }: Props) {
  const [confirmDisc, setConfirmDisc] = useState(false);
  const stColor = tunnel.state === 'ACTIVE' ? T.accent : tunnel.state === 'FAILED' ? T.danger : T.warn;

  return (
    <Card style={{ borderLeft: `2px solid ${stColor}40` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: T.textHi, fontFamily: T.display, marginBottom: 2 }}>
            {tunnel.serviceId}
          </div>
          <div style={{ fontSize: 10, color: T.textDim, fontFamily: T.font }}>
            {tunnel.ifName} · {tunnel.role}
          </div>
        </div>
        <Badge color={stColor}>
          <Indicator color={stColor} pulse={tunnel.state === 'ACTIVE'} />
          {tunnel.state}
        </Badge>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 10 }}>
        <InfoRow label="Local IP" value={tunnel.localIp} />
        <InfoRow label="Peer IP" value={tunnel.peerTunnelIp || '—'} />
        <InfoRow label="Listen port" value={tunnel.listenPort} />
        <InfoRow label="Egress port" value={tunnel.egressPort} />
        <InfoRow label="Connect to" value={tunnel.interceptLocalPort ? `127.0.0.1:${tunnel.interceptLocalPort}` : '—'} />
        <InfoRow label="Peer node" value={short(tunnel.peerNodeId)} />
      </div>

      {tunnel.error && (
        <div style={{
          fontSize: 10, color: T.danger, padding: '6px 8px', borderRadius: 3,
          background: T.dangerBg, marginBottom: 8, wordBreak: 'break-word',
        }}>{tunnel.error}</div>
      )}

      {tunnel.role === 'CONNECTOR' && <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
        {confirmDisc ? (
          <>
            <Btn small variant="ghost" onClick={() => setConfirmDisc(false)}>Cancel</Btn>
            <Btn small variant="danger" onClick={() => { onDisconnect(tunnel.serviceId); setConfirmDisc(false); }}>
              Confirm
            </Btn>
          </>
        ) : (
          <Btn small variant="danger" onClick={() => setConfirmDisc(true)}>Disconnect</Btn>
        )}
      </div>}
    </Card>
  );
}