#!/usr/bin/env python3
"""Explicitly provisioned installed prototype services; production admission stays denied.

Only a NIC-free disposable KVM guest with an operator-pinned current boot is
eligible. This is a deployment safety guard, not protection from its root user.
No test fixture, credential issuer or synthetic authorization path is imported.
"""
import argparse
import fcntl
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

MODULES = Path('/opt/defenderlink/native')
CONFIG = Path('/etc/defenderlink/native/deployment.json')
STATE = Path('/var/lib/defenderlink-native')
PINS = Path('/sys/fs/bpf/5gnexusguard-installed')
sys.path.insert(0, str(MODULES))


def configuration():
    from native_control_v2 import private_read, private_directory, boot_id
    private_directory(CONFIG.parent)
    cfg = json.loads(private_read(CONFIG))
    external = cfg.get('profile') == 'DISPOSABLE_PFSENSE'
    if (set(cfg) - ({'external_gateway'} if external else set()) != {'version', 'profile', 'production_admission', 'boot_id', 'service',
                    'client', 'owner', 'operator_key', 'supervisor_key', 'credentials', 'aa', 'control'}
            or type(cfg['version']) is not int or cfg['version'] != 1 or cfg['profile'] not in ('DISPOSABLE_VM','DISPOSABLE_PFSENSE')
            or cfg['production_admission'] is not False or cfg['boot_id'] != boot_id()):
        raise ValueError('explicit current-boot isolated profile required')
    if os.geteuid() != 0:
        raise ValueError('dedicated isolated root service required')
    guest = subprocess.check_output(['systemd-detect-virt', '--vm'], text=True).strip()
    if guest not in ('kvm', 'qemu'):
        raise ValueError('disposable KVM guest required')
    links = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show'], text=True))
    if external:
        from external_gateway import interfaces
        interfaces(cfg.get('external_gateway'), links)
    elif len(links) != 1 or links[0].get('ifname') != 'lo':
        raise ValueError('guest must have no network adapter')
    for name in ('client', 'owner', 'operator_key', 'supervisor_key'):
        if not isinstance(cfg[name], str) or not re.fullmatch('[0-9a-f]{64}', cfg[name]):
            raise ValueError('explicit identity pins required')
    if not re.fullmatch('[A-Za-z0-9._-]{1,128}', cfg['service']):
        raise ValueError('invalid service scope')
    return cfg


def stop(*_):
    raise KeyboardInterrupt


def exporter(cfg):
    # This launches the installed Quarkus application, not a test classpath/CLI.
    node = STATE/'node'; node.mkdir(mode=0o700, exist_ok=True)
    control = Path(cfg['control']['directory'])
    command = ['java', '-Xms64m', '-Xmx256m', '-XX:ActiveProcessorCount=2',
        '-Dmesh.access.mode=NATIVE_DUAL', '-Dmesh.native.gateway-mode=NATIVE',
        '-Dmesh.data-dir='+str(node), '-Dmesh.native.service-id='+cfg['service'],
        '-Dmesh.native.client-node-id='+cfg['client'],
        '-Dmesh.native.lease-file='+str(STATE/'deny-lease.json'),
        '-Dmesh.native.v2.directory='+str(control),
        '-Dmesh.native.v2.operator-key='+cfg['operator_key'],
        '-Dmesh.native.v2.supervisor-key='+cfg['supervisor_key'],
        '-Dquarkus.http.host=127.0.0.1', '-Dquarkus.http.port=8444',
        '-Dmesh.gossip.port=9451', '-jar', '/opt/defenderlink/lib/defenderlink-mesh.jar']
    env = {k:v for k,v in os.environ.items() if k not in
           ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH')}
    os.execvpe(command[0], command, env)


def authority(cfg):
    from authorization_aa_v2 import Authority, AuthorityServer
    from native_control_v2 import private_read, private_directory
    from cryptography.hazmat.primitives import serialization
    aa = cfg['aa']
    if set(aa) != {'db','signing_key','node_pins','operator_pin','operator_key_pin',
                   'server_cert','server_key','client_ca','port'}:
        raise ValueError('invalid explicit AA configuration')
    private_directory(Path(aa['db']).parent)
    signer = serialization.load_pem_private_key(private_read(Path(aa['signing_key'])), password=None)
    pins = json.loads(private_read(Path(aa['node_pins'])))
    instance = Authority(aa['db'], signer, pins, aa['operator_pin'], operator_key_pin=aa['operator_key_pin'])
    server = None
    try:
        server = AuthorityServer(('127.0.0.1', aa['port']), instance, aa['server_cert'], aa['server_key'], aa['client_ca'])
        server.serve_forever()
    finally:
        if server: server.server_close()
        instance.close()


def supervisor(cfg):
    from native import Topology, NAMES
    from native_control_v2 import Controller, private_read, private_directory, atomic_private_write
    from kernel_gate_publisher_v2 import Publisher, FreshHealth, command
    from cryptography.hazmat.primitives import serialization
    control = cfg['control']
    if set(control) != {'directory','supervisor_key','aa_key','url','ca','cert','tls_key'}:
        raise ValueError('invalid supervisor configuration')
    private_directory(Path(control['directory']))
    signer = serialization.load_pem_private_key(private_read(Path(control['supervisor_key'])), password=None)
    instance = Controller(control['directory'], dict(serviceId=cfg['service'],clientNodeId=cfg['client'],
        ownerNodeId=cfg['owner'],resource='tcp:10.80.0.2:8080'), bytes.fromhex(cfg['operator_key']),
        bytes.fromhex(cfg['owner']), signer, control['url'], control['ca'], control['cert'],
        control['tls_key'], bytes.fromhex(control['aa_key']))
    for module in ('wireguard','nf_tables'):
        if not Path('/sys/module', module).is_dir():
            raise ValueError('kernel prerequisites must be preloaded by the operator')
    topology = None; publisher = None; owned_pins = False
    transport = Path(tempfile.mkdtemp(prefix='transport-', dir=STATE))
    status = Path(control['directory'])/'status.json'
    try:
        # Default Topology callers retain their existing Docker guard. This new
        # installed adapter proves an explicit NIC-free VM instead.
        if cfg['profile'] == 'DISPOSABLE_PFSENSE':
            from external_gateway import ExternalTopology
            topology = ExternalTopology(transport, Path(cfg['credentials']), isolation_guard=configuration,
                                        external=cfg['external_gateway'])
        else:
            topology = Topology(transport, Path(cfg['credentials']), isolation_guard=configuration)
        topology.create()
        if PINS.exists(): raise ValueError('refusing to adopt existing kernel pins')
        PINS.mkdir(mode=0o700); owned_pins=True
        (PINS/'maps').mkdir(); (PINS/'progs').mkdir()
        def inner(args, *, input=None):
            if args[0] == 'bpftool': return command(args, input=input)
            if args[0] == 'tc':
                return command(['nsenter','--net=/run/netns/'+NAMES['i'],'--',*args],input=input)
            return command(['ip','netns','exec',NAMES['i'],*args],input=input)
        if cfg['profile'] == 'DISPOSABLE_PFSENSE':
            from external_gateway import ExternalHealth
            health = ExternalHealth(topology.daemon_roles['e'].pid,NAMES['e'],NAMES['i'],vici_dir=transport)
        else:
            health = FreshHealth([topology.daemon_roles[r].pid for r in ('e','o')],
                'wg-inner','resource',NAMES['e'],NAMES['o'],NAMES['i'],vici_dir=transport)
        # The existing scoped gate has two independent nft forward hooks. No
        # wall-clock lease or unsigned Java export is used by this adapter.
        publisher = Publisher(instance,inner,PINS,'wg-inner','resource',health=health,
                              object_path=MODULES/'kernel_gate_v2.bpf.o', table='nexusguard_kernel_gate')
        publisher.install()
        health.provision_owned_probe()
        while True:
            permitted = publisher.tick()
            atomic_private_write(status,json.dumps(dict(profile=cfg['profile'],production_admission=False,
                supervisor_pid=os.getpid(),observed_boottime_ns=time.clock_gettime_ns(time.CLOCK_BOOTTIME),
                session=instance.session,authorization=instance.admission.status,
                kernel_permitted=bool(permitted),deadline_boottime_ns=instance.admission.deadline,
                transport_state=str(transport),namespaces=NAMES)).encode())
            time.sleep(.08)
    finally:
        errors=[]
        if publisher:
            try: publisher.revoke()
            except Exception as error:
                # Publisher's bounded map diagnostic contains only allowlisted
                # types/reasons and numeric exit codes, never raw command output.
                text=str(error)
                errors.append('revoke: ' + text if type(error) is RuntimeError and
                    text.startswith('map zero/readback failed; revocation uncertain until kernel deadline: ') and
                    len(text)<=1600 else 'revoke_unknown')
        if topology:
            topology.close()
            names={r.split()[0] for r in command(['ip','netns','list']).splitlines() if r}
            if names.intersection(NAMES.values()): errors.append('namespace_cleanup')
        if owned_pins:
            # All pins are inside the freshly owned private directory; never
            # adopt pre-existing maps, programs or namespace objects.
            for directory in (PINS/'progs', PINS/'maps'):
                for entry in directory.iterdir(): entry.unlink()
                directory.rmdir()
            PINS.rmdir()
        atomic_private_write(status,json.dumps(dict(profile=cfg['profile'],production_admission=False,
            kernel_permitted=False,stopped=True,cleanup_errors=errors)).encode())
        if errors: raise RuntimeError('installed cleanup failed')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('role',choices=('exporter','aa','supervisor'))
    args=p.parse_args();os.umask(0o077)
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    cfg=configuration()
    STATE.mkdir(mode=0o700,exist_ok=True)
    from native_control_v2 import private_directory
    private_directory(STATE)
    with (STATE/(args.role+'.lock')).open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        try: {'exporter':exporter,'aa':authority,'supervisor':supervisor}[args.role](cfg)
        except KeyboardInterrupt: return


if __name__=='__main__': main()
