"""Two real product JVMs in isolated namespaces; no synthetic ledger or wg shim."""
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

from standard_evidence import residual_denial, qualification_complete, packet_evidence


def cmd(args):return subprocess.check_output(args,text=True,stderr=subprocess.PIPE,timeout=15)


def main():
    if not Path('/.dockerenv').exists() or os.environ.get('DL_IPSEC_ISOLATED')!='1' or not os.path.ismount('/lab/private'):
        raise RuntimeError('approved isolated Docker environment required')
    os.umask(0o077)
    root=Path('/lab/evidence');root.mkdir(mode=0o700,exist_ok=True)
    if root.is_symlink() or any(root.iterdir()):raise RuntimeError('fresh container evidence directory required')
    root.chmod(0o700)
    names={r:'p2s-'+r+'-'+secrets.token_hex(4) for r in ('a','b')}
    processes=[];created=[];captures=[];streams=[];report={'status':'FAIL','scenario':'two-product-jvms-standard'}
    def ns(role,args):return cmd(['ip','netns','exec',names[role],*args])
    def api(role,path,body=None,method=None):
        source='import urllib.request,json,sys;req=urllib.request.Request("http://127.0.0.1:8443"+sys.argv[1],data=None if sys.argv[2]=="null" else sys.argv[2].encode(),method=sys.argv[3],headers={"Content-Type":"application/json"});print(urllib.request.urlopen(req,timeout=3).read().decode())'
        response=ns(role,['python3','-c',source,path,json.dumps(body),method or ('POST' if body is not None else 'GET')]);return json.loads(response) if response.strip() else None
    def wait(predicate,label,timeout=30):
        until=time.monotonic()+timeout
        while time.monotonic()<until:
            try:
                value=predicate()
                if value:return value
            except (subprocess.CalledProcessError,KeyError):pass
            time.sleep(.2)
        raise RuntimeError('STANDARD required check timed out: '+label)
    def api_result(role,path,body):
        source='import urllib.request,urllib.error,json,sys\nreq=urllib.request.Request("http://127.0.0.1:8443"+sys.argv[1],data=sys.argv[2].encode(),headers={"Content-Type":"application/json"})\ntry:\n r=urllib.request.urlopen(req,timeout=5);status=r.status;data=r.read()\nexcept urllib.error.HTTPError as e:status=e.code;data=e.read()\nprint(json.dumps({"status":status,"body":json.loads(data)}))'
        return json.loads(ns(role,['python3','-c',source,path,json.dumps(body)]))
    def capture(directory,boundaries):
        from continuous_evidence import CaptureSet
        def spawn(role,interface,direction,pcap,status):
            with status.open('w') as log:
                return subprocess.Popen(['ip','netns','exec',names[role],'tcpdump','-Z','root','-U',
                    '--immediate-mode','-n','-i',interface,'-w',str(pcap)],stdout=subprocess.DEVNULL,stderr=log)
        group=CaptureSet(spawn,boundaries=boundaries);group.start(directory);captures.append(group)
    def kernel(role,interface):
        result={}
        for field in ('listen-port','endpoints','latest-handshakes','transfer'):
            value=ns(role,['/usr/bin/wg','show',interface,field])
            (root/('wg-'+role+'-'+interface+'-'+field+'.local.txt')).write_text(value)
            result[field]=value
        return result
    def network_state(phase):
        for role in names:
            observed={'monotonic_ns':time.monotonic_ns()}
            for label,argv in (
                    ('links',['ip','-j','-d','link','show']),
                    ('addresses',['ip','-j','address','show']),
                    ('routes',['ip','-j','route','show','table','all']),
                    ('listeners',['ss','-H','-lnt']),
                    ('nftables',['nft','-j','list','ruleset']),
                    ('source_validation',['sysctl','-n','net.ipv4.conf.all.rp_filter','net.ipv4.conf.mgmt.rp_filter'])):
                observed[label]=ns(role,argv)
            (root/('network-'+phase+'-'+role+'.local.json')).write_text(json.dumps(observed,indent=2))
    def process(role,argv,label):
        with (root/(label+'.local.log')).open('wb') as log:
            p=subprocess.Popen(['ip','netns','exec',names[role],*argv],stdout=log,stderr=log)
        processes.append((label,p));return p
    def echo(role,port):
        source='import socket,sys;s=socket.create_connection(("127.0.0.1",int(sys.argv[1])),2);s.settimeout(2);p=b"5gnexus-p2-standard";s.sendall(p);assert s.recv(len(p))==p;s.close();print("DELIVERED")'
        return ns(role,['python3','-c',source,str(port)]).strip()=='DELIVERED'
    try:
        existing={r.split()[0] for r in cmd(['ip','netns','list']).splitlines() if r}
        if existing.intersection(names.values()):raise RuntimeError('refusing existing namespace')
        for role,name in names.items():
            cmd(['ip','netns','add',name]);created.append(name);ns(role,['ip','link','set','lo','up'])
        ns('a',['ip','link','add','mgmt','type','veth','peer','name','peer'])
        ns('a',['ip','link','set','peer','netns',names['b']]);ns('b',['ip','link','set','peer','name','mgmt'])
        sys.path.insert(0,'/lab/src/packaging/linux');import runtime
        sys.path.insert(0,'/lab/src/scripts/ipsec-dual')
        from continuous_evidence import TrafficStream
        for role,address in (('a','192.0.2.1'),('b','192.0.2.2')):
            ns(role,['ip','address','add',address+'/30','dev','mgmt']);ns(role,['ip','link','set','mgmt','up'])
            ns(role,['ip','route','add','255.255.255.255/32','dev','mgmt'])
            state=Path('/lab/private')/role;state.mkdir(mode=0o700)
            wg=Path('/etc/wireguard')/names[role];wg.mkdir(parents=True,mode=0o700)
            cfg=dict(runtime.DEFAULT,http_host='0.0.0.0',public_endpoint=address+':51820',heap_mib=256)
            argv=runtime.java_command(cfg,Path('/lab/application.jar'),state,wg)
            process(role,argv[:1]+['-XX:ActiveProcessorCount=2']+argv[1:],'jvm-'+role)
            wait(lambda:api(role,'/api/status'),'JVM readiness '+role)
        capture(root,(('a','mgmt','endpoint-mgmt'),('b','mgmt','owner-mgmt'),('b','lo','protected-application')))
        identities={r:api(r,'/api/identity')['nodeId'] for r in names}
        report['identities']=identities
        wait(lambda:all(api(r,'/api/status')['knownPeers']>=1 for r in names),'real gossip discovery')
        for r in names:api(r,'/api/node/register',{'endpoints':[('192.0.2.1' if r=='a' else '192.0.2.2')+':8443'],'displayName':'P2-'+r})
        wait(lambda:all(api(r,'/api/status')['registeredNodes']==2 for r in names),'replicated node registration')
        report['discovery_registration']='PASS'
        # A regular protected application, separate from both actual JVMs.
        server='import socketserver\nclass H(socketserver.BaseRequestHandler):\n def handle(self):\n  while True:\n   p=self.request.recv(4096)\n   if not p:break\n   self.request.sendall(p)\nsocketserver.ThreadingTCPServer(("127.0.0.1",18080),H).serve_forever()'
        process('b',['python3','-u','-c',server],'protected-application')
        network_state('pre-authorization')
        connections={}
        # These IDs intentionally shared the old sanitizer's first eight chars.
        for service in ('prototype-a','prototype-b'):
            api('b','/api/services/expose',{'serviceId':service,'protocol':'tcp','localBind':'127.0.0.1:18080','allowedNodes':[identities['a']]})
            wait(lambda:any(row['serviceId']==service for row in api('a','/api/services')),'replicated service '+service)
            before=time.monotonic_ns();connection=api('a','/api/connect/'+service,{})
            owner=api('b','/api/tunnels')['owner:'+service+':'+identities['a']]
            connection['ownerIf']=owner['ifName'];connection['ownerEgressPort']=owner['egressPort']
            directory=root/service;directory.mkdir(mode=0o700)
            capture(directory,(('a',connection['tunnelIf'],'endpoint-wg'),('b',owner['ifName'],'owner-wg')))
            wait(lambda:echo('a',int(connection['connectTo'].rsplit(':',1)[1])),'protected echo '+service,10)
            connections[service]=connection;report['connections']=connections
            report.setdefault('establishment_ns',{})[service]=time.monotonic_ns()-before
        if len({c['tunnelIf'] for c in connections.values()})!=len(connections):
            raise RuntimeError('STANDARD interface naming collision between distinct service IDs')
        report['authorized_traffic']='PASS'
        report['wireguard']={}
        ownership={'a':{},'b':{}}
        for service,connection in connections.items():
            a=kernel('a',connection['tunnelIf']);b=kernel('b',connection['ownerIf'])
            local_port=int(a['listen-port']);owner_port=int(b['listen-port'])
            a_endpoints=[row.split()[1] for row in a['endpoints'].splitlines()]
            b_endpoints=[row.split()[1] for row in b['endpoints'].splitlines()]
            if (a_endpoints!=['192.0.2.2:'+str(owner_port)] or b_endpoints!=['192.0.2.1:'+str(local_port)] or
                    not any(int(line.split()[-1])>0 for line in a['latest-handshakes'].splitlines()) or
                    not any(int(line.split()[-1])>0 for line in b['latest-handshakes'].splitlines())):
                raise RuntimeError('kernel WireGuard endpoint/listen-port or handshake mismatch')
            report['wireguard'][service]={'endpoint_listen_port':local_port,'owner_listen_port':owner_port}
            for role,iface in (('a',connection['tunnelIf']),('b',connection['ownerIf'])):
                info=json.loads(ns(role,['ip','-j','link','show','dev',iface]))[0]
                if not info.get('ifalias','').startswith('5gnexus-') or info['ifindex'] in ownership[role].values():
                    raise RuntimeError('kernel interface identity/ownership label is absent or collided')
                ownership[role][iface]=info['ifindex']
        report['interface_ownership']='PASS';report['kernel_link_identities']=ownership
        network_state('authorized')
        # The client is registered but is not authorized for this service.
        denied='prototype-denied'
        exposed=api('b','/api/services/expose',{'serviceId':denied,'protocol':'tcp',
                    'localBind':'127.0.0.1:18080','allowedNodes':[identities['b']]})
        wait(lambda:any(row['serviceId']==denied for row in api('a','/api/services')),'denied service replication')
        rejected=api_result('a','/api/connect/'+denied,{})
        report['unauthorized_api']=rejected
        if (rejected['status']<400 or 'Negotiate HTTP 403' not in rejected['body'].get('error','') or
                any(row['serviceId']==denied for row in api('a','/api/tunnels').values())):
            raise RuntimeError('unauthorized negotiation did not demonstrably reject membership')
        # Allow the real scheduled egress reconciliation to run, then probe the
        # ordinary management underlay. No fallback route or policy is installed.
        time.sleep(6)
        network_state('before-underlay-probe')
        assigned=exposed['assignedPort']
        report['unauthorized_underlay_port']=assigned
        probe='import socket,json,sys\ns=None;ok=False\ntry:\n s=socket.create_connection(("192.0.2.2",int(sys.argv[1])),.5);s.settimeout(.5);p=b"5gnexus-p2-unauthorized";s.sendall(p);ok=s.recv(len(p))==p\nexcept OSError:pass\nfinally:\n if s:s.close()\nprint(json.dumps({"delivered":ok}))'
        report['unauthorized_underlay']=json.loads(ns('a',['python3','-c',probe,str(assigned)]))
        if report['unauthorized_underlay']['delivered']:
            raise RuntimeError('unauthorized protected echo delivered through direct underlay egress')
        report['authorization_denial']='PASS'
        report['residual']={}
        for service,connection in connections.items():
            if not echo('a',int(connection['connectTo'].rsplit(':',1)[1])):raise RuntimeError('first service lost traffic')
            workers=[]
            for mode,fresh in (('established',False),('new',True)):
                directory=root/service/mode;directory.mkdir(mode=0o700)
                worker=TrafficStream(host='127.0.0.1',port=int(connection['connectTo'].rsplit(':',1)[1]),
                                     namespace=names['a'],new_connections=fresh)
                streams.append(worker);worker.start(directory);worker.ready(delivered=True);workers.append((mode,worker))
            request_started=time.monotonic_ns()
            api('a','/api/disconnect/'+service,{})
            api('b','/internal/tunnel/negotiate/'+service+'/'+identities['a'],method='DELETE')
            complete=time.monotonic_ns();time.sleep(.3)
            report['residual'][service]={'request_started_ns':request_started,'both_disconnects_complete_ns':complete}
            for mode,worker in workers:
                rows=worker.stop();streams.remove(worker)
                result=residual_denial(rows,complete)
                result['successful_inflight_attempts_during_disconnect']=sum(r['delivered'] and r['attempt_ns']<complete and r['verdict_ns']>=request_started for r in rows)
                report['residual'][service][mode]=result
        report['residual_forwarding']='DENIED'
        if api('a','/api/tunnels') or api('b','/api/tunnels'):raise RuntimeError('disconnect left tracked tunnels')
        for role in names:
            if json.loads(ns(role,['ip','-j','link','show','type','wireguard'])):raise RuntimeError('disconnect left WireGuard interface')
        network_state('after-disconnect')
        report['disconnect']='PASS'
    except BaseException as exc:
        if isinstance(exc,subprocess.CalledProcessError):
            (root/'failed-command.local.stderr').write_text(exc.stderr or '')
        report['failure']={'type':type(exc).__name__,'message':str(exc)};raise
    finally:
        cleanup=[]
        for worker in streams:
            try:worker.stop()
            except Exception:report['stream_cleanup_error']=True
        capture_errors=[]
        for group in reversed(captures):
            try:group.stop()
            except Exception as exc:capture_errors.append(type(exc).__name__)
        if capture_errors:report['capture_errors']=capture_errors
        elif report.get('disconnect')=='PASS':
            try:
                report['packet_details']=packet_evidence(root,report['connections']);report['packet_evidence']='PASS'
            except Exception as exc:report['packet_evidence_failure']={'type':type(exc).__name__,'message':str(exc)}
        report['owned_processes_stopped']=True
        report['process_cleanup']=[]
        for label,p in reversed(processes):
            alive=p.poll() is None
            if not alive:report['owned_processes_stopped']=False
            if alive:
                p.terminate()
                try:p.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    report['owned_processes_stopped']=False;p.kill();p.wait(timeout=5)
            if p.returncode not in (0,143,-15):report['owned_processes_stopped']=False
            report['process_cleanup'].append({'label':label,'pid':p.pid,'alive_before_stop':alive,'exit_code':p.returncode})
        for name in reversed(created):
            try:cmd(['ip','netns','del',name]);cleanup.append({'namespace':name,'status':'PASS'})
            except Exception:cleanup.append({'namespace':name,'status':'FAIL'})
        report['cleanup']=cleanup
        try:
            remaining={line.split()[0] for line in cmd(['ip','netns','list']).splitlines() if line}
            if remaining.intersection(created):report['namespace_cleanup_error']=True
        except Exception:report['namespace_cleanup_error']=True
        if (qualification_complete(report) and not report.get('stream_cleanup_error') and
                not report.get('namespace_cleanup_error') and not report.get('capture_errors')):report['status']='PASS'
        (root/'standard-result.local.json').write_text(json.dumps(report,indent=2))
        if report['status']!='PASS' and sys.exc_info()[0] is None:raise RuntimeError('STANDARD evidence/cleanup qualification incomplete')


if __name__=='__main__':main()
