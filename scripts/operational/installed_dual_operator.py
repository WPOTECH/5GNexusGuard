"""External test operator and observer; tunnel/control services come from installed packages."""
import base64
import datetime
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import ssl
import struct
import subprocess
import sys
import time

os.umask(0o077)
# Refuse before any package/filesystem mutation outside the owned test VM.
if (os.geteuid()!=0 or not os.path.ismount('/mnt/p2')
        or subprocess.check_output(['systemd-detect-virt','--vm'],text=True).strip() not in ('kvm','qemu')
        or [row.get('ifname') for row in json.loads(subprocess.check_output(['ip','-j','link','show'],text=True))]!=['lo']
        or 'instance-id: nexusguard-installed-dual-' not in Path('/mnt/p2/meta-data').read_text()):
    raise SystemExit('explicit NIC-free disposable VM and reviewed seed required')
out=Path('/var/lib/defenderlink-native/evidence-'+str(time.monotonic_ns()));out.mkdir(mode=0o700,parents=True)
report={'status':'FAIL','checks':{},'scope':'installed services in NIC-free disposable VM'}
captures=[];peer=None;endpoint_fd=None;root_fd=os.open('/proc/self/ns/net',os.O_RDONLY)
def run(args,check=True):
    if args[:3]==['ip','netns','exec'] or args and args[0]=='nsenter':
        pid=subprocess.check_output(['systemctl','show','defenderlink-native-supervisor.service','--property=MainPID','--value'],text=True).strip()
        if pid!='0':args=['nsenter','--mount=/proc/'+pid+'/ns/mnt','--',*args]
    r=subprocess.run(args,capture_output=True,text=True,timeout=90)
    with (out/'commands.local.jsonl').open('a') as f:f.write(json.dumps({'argv':args,'code':r.returncode,'stdout':r.stdout,'stderr':r.stderr})+'\n')
    if check and r.returncode:raise RuntimeError('command failed: '+args[0])
    return r
def require(ok,label):
    if not ok:raise RuntimeError(label)
    report['checks'][label]='PASS'
def wait(fn,label,seconds=20):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            result=fn()
            if result:return result
        except (OSError,ValueError,KeyError):pass
        time.sleep(.05)
    raise RuntimeError(label)
def write(path,value):
    path=Path(path);path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    raw=json.dumps(value).encode() if isinstance(value,dict) else value
    tmp=path.with_name('.'+path.name+'.tmp');tmp.write_bytes(raw);tmp.chmod(0o600);os.replace(tmp,path)
def api():
    import urllib.request
    with urllib.request.urlopen('http://127.0.0.1:8444/api/identity',timeout=1) as r:return json.load(r)
def state():return json.loads((control/'status.json').read_text())
def inside(fd,fn):
    os.setns(fd,0)
    try:return fn()
    finally:os.setns(root_fd,0)
def connect():
    def action():
        s=socket.create_connection(('10.80.0.2',8080),.25);s.settimeout(.25);return s
    return inside(endpoint_fd,action)
def echo(s):
    marker=b'5gnexus-installed-native:authorized'
    try:
        s.sendall(marker);answer=b''
        while len(answer)<len(marker):
            chunk=s.recv(len(marker)-len(answer))
            if not chunk:break
            answer+=chunk
        return answer==marker
    except OSError:return False
def fresh_echo():
    try:
        with connect() as s:return echo(s)
    except OSError:return False
def capture(label,namespace,interface,direction=None):
    log=out/(label+'.capture-status');pcap=out/(label+'.pcap')
    pid=state()['supervisor_pid']
    args=['nsenter','--mount=/proc/'+str(pid)+'/ns/mnt','--','ip','netns','exec',namespace,'tcpdump','-Z','root','-n','-U','--immediate-mode','-i',interface]
    if direction:args+=['-Q',direction]
    args+=['-w',str(pcap)]
    with log.open('wb') as f:child=subprocess.Popen(args,stdout=subprocess.DEVNULL,stderr=f)
    captures.append((child,log,pcap))
    wait(lambda:'listening on' in log.read_text(),label+' capture readiness',3)
def stop_captures():
    while captures:
        child,log,pcap=captures.pop()
        if child.poll() is None:child.send_signal(signal.SIGINT)
        code=child.wait(timeout=5)
        require(code==0 and '0 packets dropped by kernel' in log.read_text() and pcap.stat().st_size>=24,'clean capture '+pcap.stem)
def frames(path):
    data=path.read_bytes();magic=data[:4]
    endian={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>'}.get(magic)
    require(endian is not None,'pcap format '+path.stem)
    link=struct.unpack_from(endian+'I',data,20)[0];offset=24
    while offset<len(data):
        sec,usec,length,wire=struct.unpack_from(endian+'IIII',data,offset);offset+=16
        if length>wire or offset+length>len(data):raise RuntimeError('truncated capture')
        yield link,data[offset:offset+length]
        offset+=length
def packet_audit(prefix):
    marker=b'5gnexus-installed-native:authorized';counts={}
    for label in ('endpoint-public','gateway-public','transit','endpoint-wg','inner-wg','resource','inner-resource'):
        entries=list(frames(out/(prefix+label+'.pcap')));counts[label]=len(entries)
        if label.endswith('public'):
            esp=0
            for link,f in entries:
                require(marker not in f,'no public plaintext '+prefix+label)
                if link!=1 or f[12:14]!=b'\x08\x00':continue
                ip=f[14:];ihl=(ip[0]&15)*4
                if ip[9]==50:esp+=1
                elif ip[9]==17:
                    ports=struct.unpack_from('!HH',ip,ihl)
                    require(all(p in (500,4500) for p in ports),'no public clear WireGuard '+prefix+label)
                else:raise RuntimeError('unexpected public IPv4 protocol')
            require(esp>0,'actual ESP '+prefix+label)
        elif label=='transit':require(all(marker not in f for _,f in entries),'no transit plaintext '+prefix)
        else:require(any(marker in f for _,f in entries),'protected payload '+prefix+label)
    report.setdefault('packet_counts',{})[prefix or 'initial']=counts
def checksum(data):
    data+=bytes(len(data)%2);value=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while value>>16:value=(value&65535)+(value>>16)
    return (~value)&65535
def underlay_probe():
    def dropped():
        data=json.loads(run(['ip','netns','exec','dlip-i','nft','-j','list','chain','inet','ipsec_dual','forward']).stdout)
        return sum(e['counter']['packets'] for item in data['nftables'] for r in [item.get('rule',{})] if any('drop' in e for e in r.get('expr',[])) for e in r['expr'] if 'counter' in e)
    before=dropped()
    def mac(ns):return bytes.fromhex(json.loads(run(['ip','netns','exec',ns,'ip','-j','link','show','dev','transit']).stdout)[0]['address'].replace(':',''))
    dst,src=mac('dlip-i'),mac('dlip-o')
    a,b=socket.inet_aton('10.79.0.1'),socket.inet_aton('10.80.0.2')
    tcp=struct.pack('!HHIIBBHHH',43333,8080,0x50420001,0,0x50,2,8192,0,0)
    tcp=tcp[:16]+struct.pack('!H',checksum(a+b+struct.pack('!BBH',0,6,20)+tcp))+tcp[18:]
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,40,0x5042,0,64,6,0,a,b)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    fd=os.open('/proc/'+str(state()['supervisor_pid'])+'/root/run/netns/dlip-o',os.O_RDONLY)
    def send():
        with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x0800)) as packet:
            packet.bind(('transit',0));packet.send(dst+src+b'\x08\x00'+ip+tcp)
    try:inside(fd,send)
    finally:os.close(fd)
    wait(lambda:dropped()>before,'direct underlay actual nft DROP counter')
    report['underlay_drop_delta']=dropped()-before
def underlay_capture_audit():
    found={}
    for label in ('transit','resource','inner-wg','inner-resource'):
        count=0
        for link,f in frames(out/(label+'.pcap')):
            off=14 if link==1 else 0
            if link==1 and f[12:14]!=b'\x08\x00':continue
            ip=f[off:]
            if len(ip)<40 or ip[9]!=6 or ip[12:20]!=socket.inet_aton('10.79.0.1')+socket.inet_aton('10.80.0.2'):continue
            tcp=ip[(ip[0]&15)*4:]
            if len(tcp)>=20 and struct.unpack_from('!HHI',tcp)==(43333,8080,0x50420001):count+=1
        found[label]=count
    require(found['transit']>0 and all(found[k]==0 for k in ('resource','inner-wg','inner-resource')),'direct underlay physical bypass denial')
    report['underlay_probe_captures']=found
def snapshots(label):
    result={}
    for name in ('auth_map','health_map','verdict_map'):
        result[name]=json.loads(run(['bpftool','-j','map','dump','pinned','/sys/fs/bpf/5gnexusguard-installed/maps/'+name]).stdout)
    result['hooks']=json.loads(run(['ip','netns','exec','dlip-i','nft','-j','list','ruleset']).stdout)
    result['tc']={dev:run(['nsenter','--net=/run/netns/dlip-i','tc','-j','-s','filter','show','dev',dev,'ingress']).stdout for dev in ('wg-inner','resource')}
    write(out/(label+'.json'),result);return result
def map_zero(rows):
    return bool(rows) and all(all((int(v,16) if isinstance(v,str) else v)==0 for v in r['value']) for r in rows)
def operation(action,generation):
    from admission_v2 import operation_bytes,CHALLENGE_FIELDS
    challenge=json.loads((control/'challenge.json').read_text())
    payload={k:challenge[k] for k in CHALLENGE_FIELDS};payload.update(action=action,generation=generation)
    write(control/'inbox.json',dict(operation=payload,signature=base64.b64encode(operator.sign(operation_bytes(payload))).decode()))
    wait(lambda:json.loads((control/'challenge.json').read_text())['nonce']!=challenge['nonce'],'operation consumed')
def aa_transition(action,generation,epoch,expected=200):
    from native_control_v2 import aa_scope_for
    ctx=ssl.create_default_context(cafile=str(pki/'aa-ca.pem'));ctx.load_cert_chain(str(pki/'operator.pem'),str(pki/'operator.key'))
    connection=http.client.HTTPSConnection('127.0.0.1',8445,context=ctx,timeout=3)
    payload=dict(version=2,nodeId=owner,scope=aa_scope_for(dict(serviceId=cfg['service'],clientNodeId=cfg['client'],ownerNodeId=owner,resource='tcp:10.80.0.2:8080')),
        generation=generation,revocation=0,epoch=epoch,action=action)
    try:
        connection.request('POST','/v2/authorization/transition',json.dumps(payload),{'Content-Type':'application/json'});r=connection.getresponse();body=json.loads(r.read());write(out/('aa-'+action+'-'+str(epoch)+'.json'),dict(status=r.status,response=body));require(r.status==expected,'AA '+action+' '+str(epoch))
        if expected!=200:require(body.get('error')=='recovery requires nondecreasing floors and fresh epoch','fresh AA recovery rejection reason')
    finally:connection.close()
def grant(generation):
    from issuance_v2 import canonical
    c=json.loads((control/'challenge.json').read_text());write(out/('grant-challenge-'+str(generation)+'.json'),c);now=time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    payload=dict(version=2,transport='IKEV2_ESP_WIREGUARD',serviceId=cfg['service'],clientNodeId=cfg['client'],ownerNodeId=owner,
        bootId=c['bootId'],nonce=c['nonce'],generation=generation,issuedBoottimeNs=now-1_000_000,
        deadlineBoottimeNs=now+2_500_000_000,resource='tcp:10.80.0.2:8080',issuanceId=secrets.token_hex(16),issuerId=cfg['operator_key'])
    write(control/'approval.json',dict(payload=payload,operatorSignature=base64.b64encode(operator.sign(canonical(payload))).decode()))
    def observed():
        current=state();report.setdefault('grant_status_history',[]).append(current)
        return current.get('kernel_permitted')
    wait(observed,'authenticated installed grant',2.5)
    response=json.loads((control/'inbox.json').read_text())['envelope']
    require(response['payload']==payload,'live Java preserves exact approved payload '+str(generation))
    require(state()['deadline_boottime_ns']==payload['deadlineBoottimeNs'],'immutable signed deadline '+str(generation))
    report.setdefault('grants',[]).append(payload)
    return payload
def start_capture_set(prefix):
    for label,ns,iface,direction in (
        ('endpoint-public','dlip-e','pub','out'),('gateway-public','dlip-o','pub','out'),('transit','dlip-o','transit',None),
        ('endpoint-wg','dlip-e','wg-inner',None),('inner-wg','dlip-i','wg-inner',None),('resource','dlip-r','resource',None),('inner-resource','dlip-i','resource',None)):
        capture(prefix+label,ns,iface,direction)
def resource():
    run(['systemd-run','--unit=guard-protected-resource','--property=NetworkNamespacePath=/proc/'+str(state()['supervisor_pid'])+'/root/run/netns/dlip-r',
        '/usr/bin/python3','/mnt/p2/echo.py'])
    wait(lambda:run(['systemctl','is-active','guard-protected-resource'],False).returncode==0,'protected resource readiness')
try:
    manifest=json.loads(Path('/mnt/p2/package-hashes.json').read_text())
    for name,digest in manifest.items():require(hashlib.sha256((Path('/mnt/p2')/name).read_bytes()).hexdigest()==digest,'archive hash '+name)
    require(json.loads(run(['ip','-j','link']).stdout)[0]['ifname']=='lo','NIC-free VM')
    dependencies=sorted(str(p) for p in Path('/mnt/p2/dependencies').glob('*.deb'))
    run(['dpkg','--install',*dependencies,'/mnt/p2/base.deb','/mnt/p2/native.deb'])
    run(['dpkg','--audit'])
    for role in ('aa','exporter','supervisor'):
        require(run(['systemctl','is-active','defenderlink-native-'+role+'.service'],False).returncode!=0,'no auto start '+role)
    for module in ('wireguard','nf_tables','xfrm_user','esp4'):run(['modprobe',module])
    if run(['mountpoint','-q','/sys/fs/bpf'],False).returncode:run(['mount','-t','bpf','bpf','/sys/fs/bpf'])
    sys.path.insert(0,'/opt/defenderlink/native')
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization,hashes
    from cryptography.hazmat.primitives.asymmetric import ed25519,rsa
    from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID
    state_root=Path('/var/lib/defenderlink-native');control=state_root/'control';control.mkdir(mode=0o700)
    pki=Path('/etc/defenderlink/native/pki');pki.mkdir(mode=0o700)
    operator,supervisor_key,aa_key,server_key,client=(ed25519.Ed25519PrivateKey.generate() for _ in range(5))
    def public(key):return key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
    def keyfile(path,key):write(path,key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    cfg=dict(version=1,profile='DISPOSABLE_VM',production_admission=False,boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        service='installed-prototype',client=public(client),owner='0'*64,operator_key=public(operator),supervisor_key=public(supervisor_key),
        credentials=str(pki/'ipsec'),aa={},control=dict(directory=str(control)))
    write('/etc/defenderlink/native/deployment.json',cfg)
    run(['systemctl','start','defenderlink-native-exporter.service']);owner=wait(lambda:api().get('nodeId'),'actual installed Java identity')
    require(owner==Path(state_root/'node/identity/node.pub').read_bytes().hex(),'persisted live Java identity')
    node=ed25519.Ed25519PrivateKey.from_private_bytes(Path(state_root/'node/identity/node.key').read_bytes())
    require(public(node)==owner,'mTLS node key matches actual Java identity')
    def certificate(key,identity,ca_key=None,ca=None,is_ca=False,ip=False):
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,identity)])
        now=datetime.datetime.now(datetime.timezone.utc)
        b=x509.CertificateBuilder().subject_name(name).issuer_name(ca.subject if ca else name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=is_ca,path_length=None),critical=True)
        if not is_ca:b=b.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(identity)) if ip else x509.DNSName(identity)]),critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH]),critical=False)
        signing=ca_key or key
        b=b.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing.public_key()),critical=False).add_extension(x509.KeyUsage(True,False,isinstance(key,rsa.RSAPrivateKey) and not is_ca,False,False,is_ca,is_ca,False,False),critical=True)
        return b.sign(signing,None if isinstance(signing,ed25519.Ed25519PrivateKey) else hashes.SHA256())
    ca_key=ed25519.Ed25519PrivateKey.generate();ca=certificate(ca_key,'installed-aa-ca',is_ca=True)
    certs={}
    for label,key,identity,ip in (('server',server_key,'127.0.0.1',True),('node',node,'native-node.test',False),('operator',operator,'native-operator.test',False)):
        certs[label]=certificate(key,identity,ca_key,ca,ip=ip);write(pki/(label+'.pem'),certs[label].public_bytes(serialization.Encoding.PEM));keyfile(pki/(label+'.key'),key)
    write(pki/'aa-ca.pem',ca.public_bytes(serialization.Encoding.PEM));keyfile(pki/'supervisor.key',supervisor_key);keyfile(pki/'aa-response.key',aa_key)
    write(pki/'node-pins.json',{owner:certs['node'].fingerprint(hashes.SHA256()).hex()})
    # Outer tunnel credentials are generated by this external test operator,
    # never by an installed daemon or by the old packet fixture.
    outer_ca_key=rsa.generate_private_key(public_exponent=65537,key_size=3072);outer_ca=certificate(outer_ca_key,'installed-ipsec-ca',is_ca=True)
    from config import profile
    for role,name,remote in (('e','endpoint.test','gateway.test'),('o','gateway.test','endpoint.test')):
        directory=pki/'ipsec'/role
        outer_key=rsa.generate_private_key(public_exponent=65537,key_size=3072)
        leaf=certificate(outer_key,name,outer_ca_key,outer_ca)
        keyfile(directory/'private/identity.pem',outer_key);write(directory/'x509/identity.pem',leaf.public_bytes(serialization.Encoding.PEM));write(directory/'x509ca/ca.pem',outer_ca.public_bytes(serialization.Encoding.PEM))
        write(directory/'swanctl.conf',profile('192.0.2.2' if role=='o' else '192.0.2.1','192.0.2.1' if role=='o' else '192.0.2.2',name,remote,role=='o').encode())
    (state_root/'aa').mkdir(mode=0o700)
    cfg.update(owner=owner,aa=dict(db=str(state_root/'aa/authority.sqlite'),signing_key=str(pki/'aa-response.key'),node_pins=str(pki/'node-pins.json'),
        operator_pin=certs['operator'].fingerprint(hashes.SHA256()).hex(),operator_key_pin=public(operator),server_cert=str(pki/'server.pem'),server_key=str(pki/'server.key'),client_ca=str(pki/'aa-ca.pem'),port=8445),
        control=dict(directory=str(control),supervisor_key=str(pki/'supervisor.key'),aa_key=public(aa_key),url='https://127.0.0.1:8445/v2/authorization/attest',ca=str(pki/'aa-ca.pem'),cert=str(pki/'node.pem'),tls_key=str(pki/'node.key')))
    write('/etc/defenderlink/native/deployment.json',cfg)
    write(out/'public-provisioning.json',dict(boot_id=cfg['boot_id'],service=cfg['service'],client=cfg['client'],owner=owner,operator_key=cfg['operator_key'],supervisor_key=cfg['supervisor_key'],aa_key=public(aa_key),node_cert_pin=certs['node'].fingerprint(hashes.SHA256()).hex(),operator_cert_pin=cfg['aa']['operator_pin']))
    for name in ('server.pem','node.pem','operator.pem','aa-ca.pem'):write(out/('public-'+name),(pki/name).read_bytes())
    run(['5gnexus','native-start'])
    wait(lambda:state().get('namespaces'),'installed transport/kernel readiness',25)
    resource()
    shapes={}
    for role in ('e','o'):
        pid=state()['supervisor_pid']
        raw=subprocess.check_output(['nsenter','--mount=/proc/'+str(pid)+'/ns/mnt','--','ip','netns','exec','dlip-'+role,'ip','-s','xfrm','state'],text=True)
        shapes[role]=[line.strip()[:256] for line in raw.splitlines() if 'proto esp spi' in line or '(bytes)' in line]
    write(out/'esp-public-shapes.json',shapes)
    for role in ('e','o'):
        run(['ip','netns','exec','dlip-'+role,'swanctl','--list-sas','--uri','unix://'+state()['transport_state']+'/'+role+'/vici'])
    endpoint_fd=os.open('/proc/'+str(state()['supervisor_pid'])+'/root/run/netns/dlip-e',os.O_RDONLY)
    start_capture_set('')
    require(not fresh_echo(),'pregrant protected TCP denied')
    pre=snapshots('pregrant');require(map_zero(pre['auth_map']) and map_zero(pre['health_map']),'zero pregrant kernel permits')
    aa_transition('recover',1,1,expected=409);aa_transition('authorize',2,2);operation('RECOVER',1)
    payload=grant(2)
    peer=connect();require(echo(peer) and fresh_echo(),'authorized installed nested TCP')
    run(['5gnexus','native-status']);active=snapshots('active')
    require(not map_zero(active['auth_map']) and not map_zero(active['health_map']),'active original kernel deadlines')
    underlay_probe();require(echo(peer),'authorized TCP survives underlay negative probe')
    operation('REVOKE',3);wait(lambda:not state().get('kernel_permitted'),'signed disconnect reaches kernel')
    require(not echo(peer) and not fresh_echo(),'established and new TCP denied after signed disconnect')
    require(time.clock_gettime_ns(time.CLOCK_BOOTTIME)<payload['deadlineBoottimeNs'],'revocation denial before original expiry')
    revoked=snapshots('revoked');require(map_zero(revoked['auth_map']) and map_zero(revoked['health_map']),'revoked kernel permits zero')
    stop_captures();packet_audit('');underlay_capture_audit()
    run(['5gnexus','native-stop'])
    require(not echo(peer),'old TCP denied after installed service stop');peer.close();peer=None
    os.close(endpoint_fd);endpoint_fd=None
    require(not run(['ip','netns','list']).stdout.strip() and not Path('/sys/fs/bpf/5gnexusguard-installed').exists(),'owned namespaces and pins removed')
    run(['systemctl','stop','guard-protected-resource'])
    run(['5gnexus','native-start']);wait(lambda:state().get('namespaces'),'restart transport readiness',25);resource()
    endpoint_fd=os.open('/proc/'+str(state()['supervisor_pid'])+'/root/run/netns/dlip-e',os.O_RDONLY);start_capture_set('recovery-')
    require(not fresh_echo(),'restart stays denied before fresh operator recovery')
    aa_transition('recover',2,3);aa_transition('authorize',3,4);operation('RECOVER',4);grant(5)
    require(fresh_echo(),'fresh authority restores installed protected TCP');run(['5gnexus','native-status'])
    stop_captures();packet_audit('recovery-')
    report['status']='PASS'
except Exception as exc:report['failure']={'type':type(exc).__name__,'message':str(exc)}
finally:
    try:stop_captures()
    except Exception as exc:report['capture_cleanup_error']=str(exc);report['status']='FAIL'
    location=Path('/var/lib/defenderlink-native/control')
    for name in ('approval.json','challenge.json','inbox.json','status.json','aa-highwater.json'):
        source=location/name
        if source.is_file():write(out/('control-'+name),source.read_bytes())
    run(['5gnexus','native-stop'],False);run(['systemctl','stop','guard-protected-resource'],False)
    if peer:peer.close()
    if endpoint_fd is not None:os.close(endpoint_fd)
    os.close(root_fd)
    for unit in ('defenderlink-native-aa','defenderlink-native-exporter','defenderlink-native-supervisor','guard-protected-resource'):
        (out/(unit+'.journal')).write_text(run(['journalctl','-b','-u',unit,'--no-pager'],False).stdout)
    (out/'kernel.journal').write_text(run(['journalctl','-b','-k','--no-pager'],False).stdout)
    for role in ('e','o'):
        for log in Path('/var/lib/defenderlink-native').glob('transport-*/'+role+'/charon.log'):
            (out/('charon-'+role+'.log')).write_text(log.read_text(errors='replace'))
    run(['dpkg','--audit'],False)
    report['namespaces_after']=run(['ip','netns','list'],False).stdout
    report['pins_after']=Path('/sys/fs/bpf/5gnexusguard-installed').exists()
    if report['namespaces_after'].strip() or report['pins_after']:report['status']='FAIL'
    write(out/'result.local.json',report)
    archive=subprocess.check_output(['tar','-czf','-','-C',str(out),'.'])
    with open('/dev/ttyS0','w') as console:console.write('\nP2_VM_EVIDENCE_BEGIN\n'+base64.b64encode(archive).decode()+'\nP2_VM_EVIDENCE_END\n');console.flush()
    run(['sync']);subprocess.run(['systemctl','poweroff'])
