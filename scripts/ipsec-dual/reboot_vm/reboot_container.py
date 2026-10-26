"""Actual reboot qualification, exclusively in the NIC-free guest's Docker lab.

Only test harness factories are replaced; production enforcement is unchanged.
Private fixture keys and persistence stay on the private guest disk.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from native_aa_java_harness import Fixture
from authorization_aa_v2 import Authority, AuthorityServer
from continuous_evidence import CaptureSet, EvidenceError, TrafficStream, namespace_capture
from grant_boundary_diagnostic import BOUNDARIES, assert_packet_boundary, packet_deltas
from independent_kernel_p1 import Supervisor, assert_hooks, kernel_snapshot
from freshness_packet_p14 import fresh_grant, positive_workers, require_invalid_denied

PRIVATE=Path('/lab/reboot-private')
EVIDENCE=Path('/lab/evidence')
PHASE=os.environ.get('MESH_REBOOT_PHASE')


def boot_id(): return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()


def save_fixture(fixture, envelope, recovery, session):
    from isolated_enforcement import pkcs8
    dst=PRIVATE/'checkpoint'; dst.mkdir(mode=0o700)
    with fixture.authority.lock:
        shutil.copytree(fixture.root, dst/'fixture')
    keys={name:pkcs8(getattr(fixture,name)) for name in ('operator','node','supervisor','aa_signer')}
    meta=dict(keys=keys, scope=fixture.scope, node_id=fixture.node_id,
              aa_generation=fixture.aa_generation, aa_revocation=fixture.aa_revocation,
              aa_epoch=fixture.aa_epoch, envelope=envelope, recovery=recovery, session=session, boot_id=boot_id(),
              hashes={name:digest(dst/'fixture'/name) for name in ('admission.journal','aa-highwater.json','state.sqlite')})
    (dst/'private.json').write_text(json.dumps(meta))
    os.sync()
    return {k:meta[k] for k in ('boot_id','hashes','aa_generation','aa_epoch')}


def restored_fixture(_):
    meta=json.loads((PRIVATE/'checkpoint/private.json').read_text())
    if meta['boot_id']==boot_id(): raise EvidenceError('actual guest boot identity did not change')
    for name,expected in meta['hashes'].items():
        if digest(PRIVATE/'checkpoint/fixture'/name)!=expected:
            raise EvidenceError('retained checkpoint integrity mismatch')
    f=Fixture.__new__(Fixture)
    f.temp=tempfile.TemporaryDirectory(); f.root=Path(f.temp.name); f.root.chmod(0o700)
    shutil.copytree(PRIVATE/'checkpoint/fixture',f.root,dirs_exist_ok=True)
    for name,value in meta['keys'].items():
        setattr(f,name,serialization.load_der_private_key(base64.b64decode(value),None))
    f.scope=meta['scope']; f.node_id=meta['node_id']
    f.certs={role:x509.load_pem_x509_certificate((f.root/(role+'.pem')).read_bytes()) for role in ('server','node','operator')}
    f.authority=Authority(f.root/'state.sqlite',f.aa_signer,
        {f.node_id:f.certs['node'].fingerprint(hashes.SHA256()).hex()},
        f.certs['operator'].fingerprint(hashes.SHA256()).hex(),
        operator_key_pin=f.operator.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex())
    if not f.authority.quarantined: raise EvidenceError('retained AA did not quarantine on reboot')
    f.server=AuthorityServer(('127.0.0.1',0),f.authority,str(f.root/'server.pem'),str(f.root/'server.key'),str(f.root/'ca.pem'))
    f.thread=threading.Thread(target=f.server.serve_forever,daemon=True); f.thread.start()
    f.aa_generation=meta['aa_generation']; f.aa_revocation=meta['aa_revocation']; f.aa_epoch=meta['aa_epoch']
    # Constructor loads the actual retained journal and floor, and the new boot ID.
    f.controller=f.new_controller()
    return f


def denied_workers(root):
    from native import NAMES
    result={}
    for name,new in (('established',False),('new',True)):
        path=root/name;path.mkdir(mode=0o700)
        worker=TrafficStream(namespace=NAMES['e'],new_connections=new)
        try:
            worker.start(path);worker.ready(delivered=False);time.sleep(.1)
        finally:rows=worker.stop()
        if not rows or any(row['delivered'] for row in rows): raise EvidenceError('stale authority delivered protected TCP')
        result[name]=rows
    return result


def run(root, scenario, fixture, old_issuer, ticker, publisher, inner, *, topology):
    from isolated_enforcement import JavaIssuer, stop_ticker_for_failure
    from functional_p0 import PROBES, inject, mac, frames, packet_id
    from native import NAMES
    root=Path(root)/('reboot-'+PHASE);root.mkdir(mode=0o700)
    report=dict(phase=PHASE,boot_id=boot_id(),status='FAIL')
    captures=CaptureSet(namespace_capture,boundaries=BOUNDARIES)
    controller=fixture.controller; supervisor=issuer=None;workers=[]
    stop_ticker_for_failure(ticker);publisher.revoke();old_issuer.close()
    try:
        captures.start(root)
        initial=kernel_snapshot(publisher,inner);assert_hooks(initial)
        if any(row['value']['epoch'] or row['value']['deadline_ns'] for row in initial['maps'].values()):
            raise EvidenceError('new BPF maps initialized with a permit')
        report['initialized_kernel']=initial
        (root/'pregrant').mkdir(mode=0o700)
        report['pregrant']=denied_workers(root/'pregrant')
        session=root/'supervisor';session.mkdir(mode=0o700)
        supervisor=Supervisor(fixture,publisher,session)
        fixture.controller=SimpleNamespace(session=supervisor.initial['session'])
        issuer=JavaIssuer(fixture,fixture.operator,fixture.node,old_issuer.child.args[2])
        if PHASE=='after':
            meta=json.loads((PRIVATE/'checkpoint/private.json').read_text())
            report['retained']={k:meta[k] for k in ('boot_id','hashes','aa_generation','aa_epoch')}
            report['old_authority']={k:meta['envelope']['payload'][k] for k in ('bootId','generation','deadlineBoottimeNs')}
            report['old_authority']['session']=meta['session']
            report['stale_envelope']=require_invalid_denied(supervisor,{'envelope':meta['envelope']})
            report['replayed_recovery']=require_invalid_denied(supervisor,meta['recovery'])
            stale=root/'stale';stale.mkdir(mode=0o700)
            report['stale_tcp']=denied_workers(stale)
            denied=kernel_snapshot(publisher,inner);assert_hooks(denied)
            report['denied_kernel']=denied
            if denied['verdicts']['wg_ingress']['auth_missing'] <= initial['verdicts']['wg_ingress']['auth_missing']:
                raise EvidenceError('physical stale-authority BPF rejection absent')
            # AA starts quarantined from the same store; authenticated operator
            # recovery alone does not grant. Fresh authorization follows it.
            fixture.aa_epoch+=1;fixture.transition('recover')
            fixture.aa_generation+=1;fixture.aa_epoch+=1;fixture.transition('authorize')
            report['fresh_aa']={'generation':fixture.aa_generation,'epoch':fixture.aa_epoch}
        report['grant'],envelope,recovery=fresh_grant(supervisor,fixture,issuer)
        traffic=root/'authorized';traffic.mkdir(mode=0o700)
        workers=positive_workers(traffic);time.sleep(.08)
        live=kernel_snapshot(publisher,inner);assert_hooks(live);report['authorized_kernel']=live
        if not live['maps']['authorization']['value']['epoch'] or not live['maps']['health']['value']['epoch']:
            raise EvidenceError('fresh authorization did not populate BPF maps')
        inject('o','transit',PROBES['underlay'],mac('i','transit'))
        report['authorized_tcp']={}
        for name,worker in workers:
            rows=worker.stop()
            if not rows or not all(r['delivered'] for r in rows): raise EvidenceError('authorized TCP failed')
            report['authorized_tcp'][name]=rows
        workers=[]
        final=kernel_snapshot(publisher,inner);assert_hooks(final)
        report['packet_deltas']=packet_deltas(initial,final)
        captures.stop();captures.children=[]
        report['packet_boundary']=assert_packet_boundary(root)
        for label in ('outer-transit','inner-transit'):
            if PROBES['underlay'] not in {packet_id(link,frame) for link,frame in frames(root/(label+'.pcap'))}:
                raise EvidenceError('underlay probe not captured at ingress')
        for label in ('inner-resource','resource'):
            if PROBES['underlay'] in {packet_id(link,frame) for link,frame in frames(root/(label+'.pcap'))}:
                raise EvidenceError('direct underlay bypass')
        report['underlay_bypass']='DENIED'
        report['status']='PASS'
        (root/'summary.local.json').write_text(json.dumps(report,indent=2))
        if PHASE=='before':
            report['retained']=save_fixture(fixture,envelope,recovery,report['grant']['session'])
            report['checkpoint_boottime_ns']=time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            report['checkpoint_remaining_ns']=envelope['payload']['deadlineBoottimeNs']-report['checkpoint_boottime_ns']
            if report['checkpoint_remaining_ns']<=0:raise EvidenceError('authorization expired before reboot checkpoint')
            # Supervisor remains running; no revoke, EOF, or topology cleanup.
            os.sync()
            (EVIDENCE/'before-ready.json').write_text(json.dumps(report,indent=2));os.sync()
            while True: time.sleep(1)
        if report['grant']['session']==meta['session']:
            raise EvidenceError('reboot recovery reused prior supervisor session')
        if report['grant']['generation']<=meta['envelope']['payload']['generation']:
            raise EvidenceError('reboot recovery failed native high-water advancement')
        (EVIDENCE/'after-result.json').write_text(json.dumps(report,indent=2));os.sync()
    except BaseException as exc:
        report['failure']={'type':type(exc).__name__,'message':str(exc)}
        (EVIDENCE/(PHASE+'-failure.json')).write_text(json.dumps(report,indent=2))
        raise
    finally:
        for _,worker in workers:worker.stop()
        if captures.children:captures.stop()
        if supervisor is not None:supervisor.close()
        if issuer is not None:issuer.close()
        fixture.controller=controller


def main():
    if PHASE not in ('before','after'):raise ValueError('fixed reboot phase required')
    os.umask(0o077)
    from native import require_container
    require_container()
    prior={}
    for kind in ('map','prog'):
        rows=json.loads(subprocess.check_output(['bpftool','-j',kind,'show'],text=True))
        prior[kind]=[r for r in rows if r.get('name') in
                     ('auth_map','health_map','verdict_map','wg_ingress','resource_ingress')]
        if prior[kind]:raise EvidenceError('kernel gate survived before fresh post-boot installation')
    (EVIDENCE/(PHASE+'-fresh-kernel.local.json')).write_text(json.dumps(prior))
    import isolated_enforcement as runner
    import freshness_packet_p14
    import p0_container
    if PHASE=='after':runner.Fixture=restored_fixture
    freshness_packet_p14.run=run
    os.environ['DL_P1_SCENARIO']='p14_envelope_replay'
    # Each boot has a distinct directory; p0_container owns compile/load/cleanup.
    packet=EVIDENCE/'packet'
    if packet.exists():
        if PHASE!='after':raise EvidenceError('unexpected existing packet evidence')
        packet.rename(EVIDENCE/'packet-before')
    p0_container.main()
    cleanup=json.loads((EVIDENCE/'cleanup.json').read_text())
    post=json.loads((EVIDENCE/'post-cleanup.json').read_text())
    if ([r['stage'] for r in cleanup]!=['ticker','issuer','fixture','server','topology','pins'] or
            any(r['status']!='PASS' for r in cleanup) or
            any(r['exit_code'] or r['stdout'].strip() or r['stderr'].strip() for r in post.values())):
        raise EvidenceError('guest namespace/pin cleanup verification failed')
    result=json.loads((EVIDENCE/'after-result.json').read_text())
    result['cleanup']='PASS'
    (EVIDENCE/'after-result.json').write_text(json.dumps(result,indent=2));os.sync()


if __name__=='__main__': main()
