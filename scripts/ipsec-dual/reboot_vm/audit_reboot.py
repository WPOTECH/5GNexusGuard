#!/usr/bin/env python3
"""Offline audit of reboot packet artifacts. Does not launch containers or VMs.

This records scoped packet acceptance separately from a failed automation run;
it never converts unequal host snapshots or an export timeout into runner PASS.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from functional_p0 import frames, packet_id, PROBES
from grant_boundary_diagnostic import assert_packet_boundary
from independent_kernel_p1 import assert_hooks


def require(value,message):
    if not value:raise ValueError(message)


def audit(directory):
    evidence=directory/'evidence'
    run=json.loads((directory/'result.local.json').read_text())
    before,after=run['before'],run['after']
    require(run['first_boot']['boot_id']==before['boot_id'] and
            run['second_boot']['boot_id']==after['boot_id'] and
            before['boot_id']!=after['boot_id'],'distinct actual guest boots absent')
    require(run['guest_stopped'] and run['qemu_exit_code']==0,'owned VM not stopped cleanly')
    require(before['retained']['hashes']==after['retained']['hashes'],'retained state hashes differ')
    require(after['grant']['generation']>before['grant']['generation'] and
            after['grant']['session']!=before['grant']['session'],'fresh session/generation absent')
    require(after['fresh_aa']['generation']>before['retained']['aa_generation'] and
            after['fresh_aa']['epoch']>before['retained']['aa_epoch'],'fresh AA authority absent')
    for kind in ('stale_envelope','replayed_recovery'):
        row=after[kind]
        require(row['status']=='DENIED' and not row['published'] and row['deadline_ns'] is None,
                'stale authority restored admission')
    for row in after['initialized_kernel']['maps'].values():
        require(not row['value']['epoch'] and not row['value']['deadline_ns'],'nonzero new BPF map')
    require(json.loads((evidence/'after-fresh-kernel.local.json').read_text())=={'map':[],'prog':[]},
            'old gate objects survived before new installation')
    result={'packet_qualification':'PASS','runner_status_preserved':run['status'],
            'raw_host_snapshots_equal':run['host_network_unchanged'],
            'guest_boot_ids':[before['boot_id'],after['boot_id']], 'phases':{},
            'aa_whole_store_rollback_protection':'NOT_CLAIMED'}
    for name,report,root in (('before',before,evidence/'packet-before/reboot-before'),
                              ('after',after,evidence/'packet/reboot-after')):
        require(report['status']=='PASS','phase failed')
        for label in ('initialized_kernel','authorized_kernel'):
            assert_hooks(report[label])
        require(report['initialized_kernel']['tc']==report['authorized_kernel']['tc'] and
                report['initialized_kernel']['nft_hooks']==report['authorized_kernel']['nft_hooks'],
                'enforcement hooks changed')
        if name=='after':
            assert_hooks(report['denied_kernel'])
            require(report['denied_kernel']['verdicts']['wg_ingress']['auth_missing']>
                    report['initialized_kernel']['verdicts']['wg_ingress']['auth_missing'],
                    'actual stale authority TC rejection absent')
        counts={}
        for mode in ('established','new'):
            rows=[json.loads(line) for line in (root/'authorized'/mode/'worker.jsonl').read_text().splitlines()]
            require(rows==report['authorized_tcp'][mode] and rows and all(r['delivered'] for r in rows),
                    'authorized worker evidence failed')
            counts[mode]=len(rows)
            for stage in (('pregrant','stale') if name=='after' else ('pregrant',)):
                denied=[json.loads(line) for line in (root/stage/mode/'worker.jsonl').read_text().splitlines()]
                require(denied and not any(r['delivered'] for r in denied),'negative worker delivered')
        assert_packet_boundary(root)
        statuses=list(root.glob('*.capture-status'))
        require(len(statuses)==10 and all(re.search(r'^0 packets dropped by kernel$',p.read_text(),re.M)
                                          for p in statuses),'incomplete physical captures')
        encryption={}
        for label in ('endpoint-public-wire-egress','outer-public-wire-egress'):
            esp=0
            for link,frame in frames(root/(label+'.pcap')):
                require(link==1 and len(frame)>=14,'unexpected public capture')
                require(frame[12:14]!=b'\x86\xdd','IPv6 public egress')
                if frame[12:14]!=b'\x08\x00':continue
                require(len(frame)>=34 and frame[23]==50,'non-ESP public IPv4 egress')
                require(b'native-dual-packet-evidence:' not in frame,'plaintext on public egress')
                esp+=1
            require(esp>0,'no ESP traffic');encryption[label]=esp
        wg=0
        for link,frame in frames(root/'outer-transit.pcap'):
            offset=14 if link==1 else 0
            if len(frame)<offset+28 or (link==1 and frame[12:14]!=b'\x08\x00'):continue
            ip=frame[offset:]
            if ip[9]==17:
                start=(ip[0]&15)*4
                sport,dport=struct.unpack_from('!HH',ip,start)
                if sport==dport==51821:wg+=1
            require(b'native-dual-packet-evidence:' not in frame,'plaintext on WG transit')
        require(wg>0,'WireGuard transit absent')
        for label in ('outer-transit','inner-transit'):
            require(PROBES['underlay'] in {packet_id(l,f) for l,f in frames(root/(label+'.pcap'))},
                    'negative underlay ingress evidence absent')
        for label in ('inner-resource','resource'):
            require(PROBES['underlay'] not in {packet_id(l,f) for l,f in frames(root/(label+'.pcap'))},
                    'underlay bypass delivered')
        for table in ('ipsec_dual','kernel_gate_v2_test'):
            rows=report['packet_deltas']['nft'][table]
            kinds={r['handle']:r['rule_kind'] for r in report['initialized_kernel']['nft'][table]}
            for kind in ('forward','reverse'):
                selected=[r for r in rows if kinds[r['handle']]==kind]
                require(len(selected)==1 and any(n>0 for n in selected[0]['packet_deltas']),
                        'nft interlock positive counters absent')
        drop_handles={r['handle'] for r in report['initialized_kernel']['nft']['ipsec_dual'] if r['rule_kind']=='drop'}
        drops=[r for r in report['packet_deltas']['nft']['ipsec_dual'] if r['handle'] in drop_handles]
        require(len(drops)==1 and drops[0]['packet_deltas']==[1],'nft underlay drop absent')
        result['phases'][name]={'tcp_echoes':counts,'captures':len(statuses),'esp_packets':encryption,'wireguard_transit_packets':wg}
    cleanup=json.loads((evidence/'cleanup.json').read_text())
    require([r['stage'] for r in cleanup]==['ticker','issuer','fixture','server','topology','pins'] and
            all(r['status']=='PASS' for r in cleanup),'cleanup stages incomplete')
    post=json.loads((evidence/'post-cleanup.json').read_text())
    require(set(post)=={'namespaces','pins'} and all(not r['exit_code'] and not r['stdout'].strip() and
            not r['stderr'].strip() for r in post.values()),'namespace/pin cleanup incomplete')
    rows=[json.loads(line) for line in (evidence/'packet-before/reboot-before/supervisor/map-writes.local.jsonl').read_text().splitlines()]
    grant=next(r for r in rows if r['map']=='auth_map' and r['epoch'] and r['success'])
    require(not any(r['success'] and (not r['epoch'] or
            r['map']=='auth_map' and r['deadline_ns']!=grant['deadline_ns'])
            for r in rows if r['boottime_ns']>=grant['boottime_ns']),
            'preboot map cleared or original authorization extended')
    result['preboot_map_audit']={'no_explicit_revoke_after_grant':True,
        'authorization_deadline_ns':grant['deadline_ns'],
        'last_health_write':next(r for r in reversed(rows) if r['map']=='health_map' and r['success']),
        'reboot_request_boottime_ns':run['reboot_request']['reboot_request_boottime_ns']}
    result['artifact_sha256']={str(p.relative_to(directory)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(evidence.rglob('*')) if p.is_file()}
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directory',type=Path)
    args=parser.parse_args();os.umask(0o077)
    result=audit(args.directory)
    (args.directory/'offline-audit.local.json').write_text(json.dumps(result,indent=2))
    print(json.dumps({k:v for k,v in result.items() if k not in ('artifact_sha256','preboot_map_audit')},indent=2))


if __name__=='__main__':main()
