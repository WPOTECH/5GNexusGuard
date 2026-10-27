"""Two real product JVMs in isolated namespaces; no synthetic ledger or wg shim."""
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time


def cmd(args):return subprocess.check_output(args,text=True,stderr=subprocess.PIPE,timeout=15)


def main():
    if not Path('/.dockerenv').exists() or os.environ.get('DL_IPSEC_ISOLATED')!='1' or not os.path.ismount('/lab/private'):
        raise RuntimeError('approved isolated Docker environment required')
    os.umask(0o077)
    root=Path('/lab/evidence');root.mkdir(mode=0o700,exist_ok=True)
    if root.is_symlink() or any(root.iterdir()):raise RuntimeError('fresh container evidence directory required')
    root.chmod(0o700)
    names={r:'p2s-'+r+'-'+secrets.token_hex(4) for r in ('a','b')}
    processes=[];created=[];report={'status':'FAIL','scenario':'two-product-jvms-standard'}
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
    def process(role,argv,label):
        with (root/(label+'.local.log')).open('wb') as log:
            p=subprocess.Popen(['ip','netns','exec',names[role],*argv],stdout=log,stderr=log)
        processes.append(p);return p
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
        for role,address in (('a','192.0.2.1'),('b','192.0.2.2')):
            ns(role,['ip','address','add',address+'/30','dev','mgmt']);ns(role,['ip','link','set','mgmt','up'])
            ns(role,['ip','route','add','255.255.255.255/32','dev','mgmt'])
            state=Path('/lab/private')/role;state.mkdir(mode=0o700)
            wg=Path('/etc/wireguard')/names[role];wg.mkdir(parents=True,mode=0o700)
            cfg=dict(runtime.DEFAULT,http_host='0.0.0.0',public_endpoint=address+':51820',heap_mib=256)
            argv=runtime.java_command(cfg,Path('/lab/application.jar'),state,wg)
            process(role,argv[:1]+['-XX:ActiveProcessorCount=2']+argv[1:],'jvm-'+role)
            wait(lambda:api(role,'/api/status'),'JVM readiness '+role)
        identities={r:api(r,'/api/identity')['nodeId'] for r in names}
        report['identities']=identities
        wait(lambda:all(api(r,'/api/status')['knownPeers']>=1 for r in names),'real gossip discovery')
        for r in names:api(r,'/api/node/register',{'endpoints':[('192.0.2.1' if r=='a' else '192.0.2.2')+':8443'],'displayName':'P2-'+r})
        wait(lambda:all(api(r,'/api/status')['registeredNodes']==2 for r in names),'replicated node registration')
        report['discovery_registration']='PASS'
        # A regular protected application, separate from both actual JVMs.
        server='import socketserver\nclass H(socketserver.BaseRequestHandler):\n def handle(self):\n  while True:\n   p=self.request.recv(4096)\n   if not p:break\n   self.request.sendall(p)\nsocketserver.ThreadingTCPServer(("127.0.0.1",18080),H).serve_forever()'
        process('b',['python3','-u','-c',server],'protected-application')
        connections={}
        # These IDs intentionally shared the old sanitizer's first eight chars.
        for service in ('prototype-a','prototype-b'):
            api('b','/api/services/expose',{'serviceId':service,'protocol':'tcp','localBind':'127.0.0.1:18080','allowedNodes':[identities['a']]})
            wait(lambda:any(row['serviceId']==service for row in api('a','/api/services')),'replicated service '+service)
            before=time.monotonic_ns();connection=api('a','/api/connect/'+service,{})
            wait(lambda:echo('a',int(connection['connectTo'].rsplit(':',1)[1])),'protected echo '+service,10)
            connections[service]=connection;report['connections']=connections
            report.setdefault('establishment_ns',{})[service]=time.monotonic_ns()-before
        if len({c['tunnelIf'] for c in connections.values()})!=len(connections):
            raise RuntimeError('STANDARD interface naming collision between distinct service IDs')
        for service,connection in connections.items():
            if not echo('a',int(connection['connectTo'].rsplit(':',1)[1])):raise RuntimeError('first service lost traffic')
            api('a','/api/disconnect/'+service,{})
            api('b','/internal/tunnel/negotiate/'+service+'/'+identities['a'],method='DELETE')
        report['authorized_traffic']='PASS'
        if api('a','/api/tunnels') or api('b','/api/tunnels'):raise RuntimeError('disconnect left tracked tunnels')
        for role in names:
            if json.loads(ns(role,['ip','-j','link','show','type','wireguard'])):raise RuntimeError('disconnect left WireGuard interface')
        report['disconnect']='PASS';report['status']='PASS'
    except BaseException as exc:
        if isinstance(exc,subprocess.CalledProcessError):
            (root/'failed-command.local.stderr').write_text(exc.stderr or '')
        report['failure']={'type':type(exc).__name__,'message':str(exc)};raise
    finally:
        cleanup=[]
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=15)
                except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
        for name in reversed(created):
            try:cmd(['ip','netns','del',name]);cleanup.append({'namespace':name,'status':'PASS'})
            except Exception:cleanup.append({'namespace':name,'status':'FAIL'})
        report['cleanup']=cleanup
        (root/'standard-result.local.json').write_text(json.dumps(report,indent=2))
        if any(r['status']!='PASS' for r in cleanup):raise RuntimeError('isolated STANDARD cleanup failed')


if __name__=='__main__':main()
