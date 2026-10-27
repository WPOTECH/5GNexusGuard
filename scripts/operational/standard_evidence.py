"""Offline STANDARD acceptance checks. Never issues network or privilege commands."""
from pathlib import Path
import re
import socket
import struct


def require(condition,message):
    if not condition:raise ValueError(message)


def residual_denial(rows,complete_ns):
    require(rows and any(r['delivered'] and r['verdict_ns']<=complete_ns for r in rows),
            'missing established authorized baseline')
    after=[r for r in rows if r['attempt_ns']>=complete_ns]
    require(after and all(not r['delivered'] for r in after),'post-disconnect forwarding or missing negative probe')
    first=after[0]
    successes=[r for r in rows if r['delivered']]
    return {'last_success_ns':successes[-1]['verdict_ns'],'disconnect_complete_ns':complete_ns,
            'first_denied_attempt_ns':first['attempt_ns'],'first_denied_verdict_ns':first['verdict_ns'],
            'post_disconnect_attempts':len(after),
            'interpretation':'observed probes; pre-completion inflight attempts are separate, no maximum bound claimed'}


def qualification_complete(report):
    return (all(report.get(k)=='PASS' for k in ('discovery_registration','authorized_traffic',
                'authorization_denial','interface_ownership','disconnect','packet_evidence')) and
            report.get('residual_forwarding')=='DENIED' and report.get('owned_processes_stopped') is True and
            len(report.get('cleanup',[]))==2 and all(r['status']=='PASS' for r in report['cleanup']))


def packet_evidence(root,connections):
    from functional_p0 import frames,packet_id
    captures=list(Path(root).rglob('*.capture-status'))
    require(len(captures)==7 and all(re.search(r'^0 packets dropped by kernel$',p.read_text(),re.M) for p in captures),
            'missing capture or kernel capture drops')
    marker=b'5gnexus-p2-standard'
    result={'captures':len(captures),'services':{}}
    for service,c in connections.items():
        path=Path(root)/service
        seen={}
        for side in ('endpoint-wg','owner-wg'):
            records=list(frames(path/(side+'.pcap')))
            require(any(marker in f for _,f in records),'authorized application payload absent on WireGuard interface')
            seen[side]={t for l,f in records if (t:=packet_id(l,f)) is not None and
                        t[1]==c['peerTunnelIp'] and t[3]==c['ownerEgressPort']}
        common=seen['endpoint-wg']&seen['owner-wg']
        require(common,'same protected TCP SYN absent across both WireGuard interfaces')
        result['services'][service]={'matched_syn_flows':len(common)}
    for label in ('endpoint-mgmt','owner-mgmt'):
        encrypted=0
        for link,frame in frames(Path(root)/(label+'.pcap')):
            require(marker not in frame and b'native-dual-packet-evidence:' not in frame,
                    'protected application plaintext escaped onto management underlay')
            offset=14 if link==1 else 0
            if len(frame)<offset+32 or (link==1 and frame[12:14]!=b'\x08\x00'):continue
            ip=frame[offset:]
            if ip[9]!=17:continue
            start=(ip[0]&15)*4
            if len(ip)<start+12:continue
            sport,dport=struct.unpack_from('!HH',ip,start)
            if sport in (51820,51821) and dport in (51820,51821) and ip[start+8:start+12]==b'\x04\x00\x00\x00':encrypted+=1
        require(encrypted>0,'no actual WireGuard transport data on underlay')
        result[label]={'wireguard_transport_packets':encrypted}
    require(any(marker in f for _,f in frames(Path(root)/'protected-application.pcap')),
            'actual protected application did not receive authorized payload')
    return result
