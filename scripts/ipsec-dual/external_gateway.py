"""Explicit socket-only disposable-VM external IPsec adapter; no remote authority."""
import json
import os
from pathlib import Path
import re

from native import Topology, NAMES, command, ns
from kernel_gate_publisher_v2 import FreshHealth, command as health_command


def interfaces(value, links):
    """Bind the two operator-provisioned guest NICs; never accept other links."""
    if not isinstance(value, dict) or set(value) != {'wan', 'lan'}:
        raise ValueError('two explicit external links required')
    expected = {'lo': None}
    for role in ('wan', 'lan'):
        row = value[role]
        if (not isinstance(row, dict) or set(row) != {'name', 'mac'}
                or row['name'] != 'p23-'+role
                or not isinstance(row['mac'], str)
                or not re.fullmatch(r'52:54:00:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}', row['mac'])):
            raise ValueError('explicit pinned disposable NIC required')
        expected[row['name']] = row['mac']
    if value['wan']['mac'] == value['lan']['mac']:
        raise ValueError('distinct NIC identities required')
    actual = {row['ifname']: row.get('address') for row in links}
    # Supervisor moves both NICs into its owned namespaces. Other roles then see lo.
    if actual != {'lo': actual.get('lo')} and (
            set(actual) != set(expected) or any(actual[k] != v for k,v in expected.items() if v)):
        raise ValueError('unexpected guest network adapter')
    if 'lo' not in actual:
        raise ValueError('loopback required')
    return value


class ExternalTopology(Topology):
    def __init__(self, state, credentials, *, isolation_guard, external):
        super().__init__(state, credentials, isolation_guard=isolation_guard)
        self.external = external
        self.moved = []

    def link(self, left, right, name, a, b):
        choice = {('e','o','pub'): ('wan','e',a), ('o','i','transit'): ('lan','i',b)}.get((left,right,name))
        if choice is None:
            return super().link(left,right,name,a,b)
        label, role, address = choice
        row = self.external[label]
        current = json.loads(command('ip','-j','link','show','dev',row['name']))
        if len(current) != 1 or current[0]['address'] != row['mac']:
            raise ValueError('disposable NIC identity changed')
        command('ip','link','set',row['name'],'down')
        command('ip','link','set',row['name'],'netns',NAMES[role])
        self.moved.append((role,row['name'],name,row['mac']))
        ns(role,'ip','link','set',row['name'],'name',name)
        ns(role,'ip','addr','flush','dev',name)
        ns(role,'ip','addr','add',address,'dev',name)
        ns(role,'ip','link','set',name,'up')

    def start_ipsec(self):
        from config import provision_operator
        provision_operator(self.state,self.credentials,roles=('e',))
        self.start_daemon('e')
        self.swan('e','--initiate','--child','inner-transport','--timeout','12')

    def route(self, role, destination, *via):
        if role == 'o':
            return  # The disposable appliance owns its routing, not this namespace.
        return super().route(role,destination,*via)

    def close(self):
        # Restore owned virtual NICs before their namespace disappears. Deny first.
        errors=[]
        for role,original,name,mac in reversed(self.moved):
            try:
                current=json.loads(ns(role,'ip','-j','link','show','dev',name))
                if len(current)!=1 or current[0]['address']!=mac:raise ValueError('NIC ownership changed')
                ns(role,'ip','link','set',name,'down')
                ns(role,'ip','addr','flush','dev',name)
                ns(role,'ip','link','set',name,'name',original)
                ns(role,'ip','link','set',original,'netns',str(os.getpid()))
            except (RuntimeError,ValueError) as error:errors.append(str(error))
        super().close()
        if errors:raise RuntimeError('external NIC cleanup failed: '+repr(errors))


class ExternalHealth(FreshHealth):
    """Local pinned IKE/CHILD + bidirectional ESP progress around fresh inner echo.

    No appliance process, clock or status is trusted as admission authority.
    The endpoint firewall still requires reqid 42 on all WG underlay traffic.
    """
    def __init__(self, pid, endpoint_ns, inner_ns, *, vici_dir, run=health_command):
        self.pids={pid:self._start(pid)}
        self.endpoint_ns=endpoint_ns;self.inner_ns=inner_ns
        self.wg='wg-inner';self.resource='resource';self.run=run
        self.vici_dir=Path(vici_dir)

    def _identities(self):
        return all(self._start(pid)==start and self._namespace(pid,self.endpoint_ns)
                   for pid,start in self.pids.items())

    def _snapshot(self):
        if not self._identities():return None
        for namespace,dst,src in ((self.endpoint_ns,'10.79.0.2','10.79.0.1'),
                                  (self.inner_ns,'10.79.0.1','10.79.0.2')):
            prefix=['ip','netns','exec',namespace]
            route=json.loads(self.run([*prefix,'ip','-j','route','get',dst,'from',src]))
            addresses=json.loads(self.run([*prefix,'ip','-j','addr','show','dev',self.wg]))
            if (len(route)!=1 or route[0].get('dev')!=self.wg or route[0].get('src',src)!=src
                    or len(addresses)!=1 or not any(a.get('family')=='inet' and a.get('local')==src
                        for a in addresses[0].get('addr_info',[]))):return None
        prefix=['ip','netns','exec',self.endpoint_ns]
        status=self.run([*prefix,'swanctl','--list-sas','--uri','unix://'+str(self.vici_dir/'e/vici')])
        status=re.sub(r'(?m)^([ \t]*(?:local|remote)[ \t]+10\.(?:77\.0\.1|78\.0\.2)/32)\[udp/51821\]$',r'\1[17/51821]',status)
        ike=re.findall(r'(?m)^hybrid: #\d+, ESTABLISHED, IKEv2, ([0-9a-f]{16})_i\*? ([0-9a-f]{16})_r\*?$',status)
        child=list(re.finditer(r'(?m)^[ \t]{1,2}inner-transport: #\d+, reqid 42, INSTALLED, TUNNEL, ESP:[^\n]*\n',status))
        if len(ike)!=1 or len(child)!=1 or len(re.findall(r'(?m)^\S+: #',status))!=1:return None
        remainder=status[child[0].end():]
        boundary=re.search(r'(?m)^[ \t]{1,2}\S+: #',remainder)
        section=remainder[:boundary.start() if boundary else None]
        if (not re.search(r'(?m)^    local  10\.77\.0\.1/32\[17/51821\]$',section)
                or not re.search(r'(?m)^    remote 10\.78\.0\.2/32\[17/51821\]$',section)):return None
        spis={direction:re.findall(r'(?m)^    '+direction+r' +([0-9a-f]{8}),',section)
              for direction in ('in','out')}
        if any(len(value)!=1 for value in spis.values()):return None
        raw=self.run([*prefix,'ip','-s','xfrm','state'])
        counts=[]
        for src,dst,direction in (('192.0.2.1','192.0.2.2','out'),('192.0.2.2','192.0.2.1','in')):
            records=[r for r in re.split(r'(?=^src )',raw,flags=re.M)
                if r.startswith('src '+src+' dst '+dst+'\n') and re.search(
                    r'(?m)^\s+proto esp spi 0x[0-9a-f]+\(\d+\) reqid 42\(0x0000002a\) mode tunnel\s*$',r)]
            if len(records)!=1:return None
            spi=re.search(r'proto esp spi 0x([0-9a-f]+)',records[0])
            if not spi or int(spi[1],16)!=int(spis[direction][0],16):return None
            current=re.findall(r'(?m)^\s+lifetime current:\s*\n\s*(\d+)\(bytes\), \d+\(packets\)\s*$',records[0])
            if len(current)!=1:return None
            counts.append(int(current[0]))
        return (tuple(ike)+(spis['in'][0],spis['out'][0]),tuple(counts))
