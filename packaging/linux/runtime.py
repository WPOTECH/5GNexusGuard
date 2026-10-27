#!/usr/bin/env python3
"""Linux operator entry point. No test fixtures, credential generation, or shell eval."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import urllib.request

CONFIG=Path('/etc/defenderlink/node.json')
STATE=Path('/var/lib/defenderlink')
WG_CONFIG=Path('/etc/wireguard/defenderlink')
DEFAULT=dict(version=1, mode='STANDARD', http_host='127.0.0.1', http_port=8443,
             gossip_port=9450, public_endpoint='127.0.0.1:51820', heap_mib=512,
             production_admission=False)
REQUIRED=('java','ip','/usr/bin/wg','python3','systemctl')


def read_config(path):
    path=Path(path)
    info=path.lstat()
    if (path.resolve()!=path or not stat.S_ISREG(info.st_mode) or
            info.st_uid not in (0,os.getuid()) or info.st_mode&0o022 or info.st_nlink!=1 or info.st_size>16384):
        raise ValueError('configuration must be a real, owned, non-writable regular file')
    def unique(pairs):
        result={}
        for k,v in pairs:
            if k in result:raise ValueError('duplicate configuration field')
            result[k]=v
        return result
    cfg=json.loads(path.read_text(),object_pairs_hook=unique)
    if set(cfg)!=set(DEFAULT) or type(cfg['version']) is not int or cfg['version']!=1:
        raise ValueError('unsupported configuration schema')
    if cfg['mode'] not in ('STANDARD','DUAL_TUNNEL'):raise ValueError('invalid access mode')
    if cfg['production_admission'] is not False:raise ValueError('production admission remains disabled')
    ipaddress.ip_address(cfg['http_host'])
    for field in ('http_port','gossip_port'):
        if type(cfg[field]) is not int or not 1024<=cfg[field]<=65535:raise ValueError('invalid service port')
    if type(cfg['heap_mib']) is not int or not 128<=cfg['heap_mib']<=4096:raise ValueError('invalid JVM heap size')
    host,port=cfg['public_endpoint'].rsplit(':',1)
    ipaddress.IPv4Address(host)
    if not re.fullmatch(r'[0-9]{1,5}',port) or not 1024<=int(port)<=65535:raise ValueError('invalid WG endpoint')
    return cfg


def java_major():
    result=subprocess.run(['java','-version'],capture_output=True,text=True,timeout=10)
    match=re.search(r'version "(\d+)',result.stderr+result.stdout)
    if result.returncode or not match or int(match[1])<24:raise ValueError('Java 24 or newer is required')
    return int(match[1])


def check_directory(path):
    path=Path(path);info=path.lstat()
    if (path.resolve()!=path or not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or
            stat.S_IMODE(info.st_mode)!=0o700):raise ValueError('runtime directory must be real, owner-owned, mode 0700')
    for parent in path.parents:
        mode=parent.lstat()
        if (not stat.S_ISDIR(mode.st_mode) or parent.resolve()!=parent or
                mode.st_uid not in (0,os.getuid()) or
                mode.st_mode&0o022 and not (mode.st_uid==0 and mode.st_mode&stat.S_ISVTX)):
            raise ValueError('replaceable runtime directory ancestor')


def dependencies(cfg):
    names=list(REQUIRED)
    if cfg['mode']=='DUAL_TUNNEL':names+=['nft','bpftool','swanctl','clang']
    missing=[name for name in names if shutil.which(name) is None]
    if missing:raise ValueError('missing dependencies: '+', '.join(missing))
    return java_major()


def java_command(cfg, jar, state=STATE, wg_config=WG_CONFIG):
    # DUAL_TUNNEL needs a service-wired authenticated supervisor. The old test
    # fixture is intentionally never invoked or passed off as that deployment.
    if cfg['mode']=='DUAL_TUNNEL':
        raise ValueError('DUAL_TUNNEL service integration is not yet qualified; access remains denied')
    return ['java','-Xms64m','-Xmx'+str(cfg['heap_mib'])+'m',
            '-Dmesh.data-dir='+str(state),'-Dmesh.tunnel.config-dir='+str(wg_config),
            '-Dmesh.access.mode=STANDARD','-Dmesh.node.public-endpoint='+cfg['public_endpoint'],
            '-Dquarkus.http.host='+cfg['http_host'],'-Dquarkus.http.port='+str(cfg['http_port']),
            '-Dmesh.gossip.port='+str(cfg['gossip_port']),'-jar',str(jar)]


def api_url(cfg, path):
    host=ipaddress.ip_address(cfg['http_host'])
    if host.is_unspecified:host=ipaddress.ip_address('127.0.0.1' if host.version==4 else '::1')
    return 'http://'+('['+str(host)+']' if host.version==6 else str(host))+':'+str(cfg['http_port'])+'/api/'+path


def request(cfg,path):
    req=urllib.request.Request(api_url(cfg,path),method='POST',data=b'{}',headers={'Content-Type':'application/json'})
    # Never forward operator requests through ambient HTTP proxy settings.
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=10) as response:
        return json.load(response)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,default=CONFIG)
    parser.add_argument('--jar',type=Path,default=Path('/opt/defenderlink/lib/defenderlink-mesh.jar'))
    sub=parser.add_subparsers(dest='action',required=True)
    for command in ('validate','diagnostics','run','start','status','stop','restart'):sub.add_parser(command)
    for command in ('connect','disconnect'):
        p=sub.add_parser(command);p.add_argument('service_id')
    args=parser.parse_args()
    try:
        os.umask(0o077)
        cfg=read_config(args.config)
        if args.action=='validate':
            print(json.dumps({'configuration':'VALID','mode':cfg['mode'],'production_admission':False}));return
        if args.action=='diagnostics':
            print(json.dumps({'configuration':'VALID','java_major':dependencies(cfg),'mode':cfg['mode'],
                              'production_admission':False}));return
        if args.action in ('start','stop','restart','status'):
            if args.action in ('start','restart'):
                dependencies(cfg);java_command(cfg,args.jar)
            raise SystemExit(subprocess.run(['systemctl',args.action,'defenderlink-mesh.service']).returncode)
        if args.action in ('connect','disconnect'):
            if cfg['mode']!='STANDARD':raise ValueError('use authenticated native V2 recovery; STANDARD fallback is forbidden')
            if not re.fullmatch(r'[A-Za-z0-9._-]{1,128}',args.service_id):raise ValueError('invalid service ID')
            print(json.dumps(request(cfg,args.action+'/'+args.service_id)));return
        dependencies(cfg);check_directory(STATE);check_directory(WG_CONFIG)
        if args.jar.resolve()!=args.jar or not args.jar.is_file():raise ValueError('installed application JAR missing or linked')
        argv=java_command(cfg,args.jar)
        # No inherited JAVA_TOOL_OPTIONS/JDK_JAVA_OPTIONS arbitrary startup code.
        env={k:v for k,v in os.environ.items() if k not in ('JAVA_TOOL_OPTIONS','JDK_JAVA_OPTIONS','_JAVA_OPTIONS','CLASSPATH')}
        os.execvpe(argv[0],argv,env)
    except (OSError,ValueError,KeyError,TypeError,subprocess.SubprocessError):
        # Credentials/configuration contents and raw application diagnostics stay local.
        print('5GNexusGuard command failed; check configuration, permissions and local service journal',file=sys.stderr)
        return 1


if __name__=='__main__':sys.exit(main())
