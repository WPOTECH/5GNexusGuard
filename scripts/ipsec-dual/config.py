#!/usr/bin/env python3
"""Render a bounded native/external IKEv2 profile; never configure a remote appliance."""
import argparse
import ipaddress
from pathlib import Path
import re
import shutil
import stat
import subprocess

TRANSPORT = 'IKEV2_ESP_WIREGUARD'


def profile(local='192.0.2.1', remote='192.0.2.2', local_id='endpoint.test',
            remote_id='gateway.test', gateway=False):
    for address in (local, remote):
        ipaddress.IPv4Address(address)
    for identity in (local_id, remote_id):
        if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}', identity):
            raise ValueError('identity must be an exact DNS SAN, no wildcards')
    left, right = ('10.78.0.2', '10.77.0.1') if gateway else ('10.77.0.1', '10.78.0.2')
    return f'''connections {{
 hybrid {{
  version = 2
  local_addrs = {local}
  remote_addrs = {remote}
  proposals = aes256gcm16-prfsha384-ecp384
  mobike = no
  local {{
   auth = pubkey
   id = {local_id}
   certs = identity.pem
  }}
  remote {{
   auth = pubkey
   id = {remote_id}
  }}
  children {{
   inner-transport {{
    local_ts = {left}/32[17/51821]
    remote_ts = {right}/32[17/51821]
    mode = tunnel
    reqid = 42
    esp_proposals = aes256gcm16-ecp384
    start_action = none
    dpd_action = clear
   }}
  }}
 }}
}}
'''


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def provision_lab(state):
    """Ephemeral test CA and RSA credentials, unrelated to WG or ledger identity."""
    state = state.resolve()
    script = Path(__file__).resolve()
    repo = next((parent for parent in script.parents if (parent / '.git').exists()), script.parent)
    if state == repo or repo in state.parents:
        raise ValueError('test credentials must be outside the repository')
    ca = state / 'ca'
    ca.mkdir(mode=0o700)
    run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256',
        '-days', '2', '-subj', '/CN=DefenderLink TEST ONLY CA',
        '-addext', 'basicConstraints=critical,CA:TRUE',
        '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
        '-keyout', str(ca / 'ca.key'), '-out', str(ca / 'ca.pem'))
    for role, identity, peer, local, remote in (
            ('e', 'endpoint.test', 'gateway.test', '192.0.2.1', '192.0.2.2'),
            ('o', 'gateway.test', 'endpoint.test', '192.0.2.2', '192.0.2.1')):
        directory = state / role
        directory.mkdir(mode=0o700)
        for name in ('private', 'x509', 'x509ca'):
            (directory / name).mkdir(mode=0o700)
        run('openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes',
            '-subj', '/CN=' + identity, '-keyout', str(directory / 'private/identity.pem'),
            '-out', str(directory / 'request.pem'))
        extension = directory / 'extensions'
        extension.write_text('basicConstraints=critical,CA:FALSE\n'
                             'keyUsage=critical,digitalSignature\nsubjectAltName=DNS:' + identity + '\n')
        run('openssl', 'x509', '-req', '-in', str(directory / 'request.pem'),
            '-CA', str(ca / 'ca.pem'), '-CAkey', str(ca / 'ca.key'), '-CAcreateserial',
            '-days', '2', '-sha256', '-extfile', str(extension),
            '-out', str(directory / 'x509/identity.pem'))
        (directory / 'x509ca/ca.pem').write_bytes((ca / 'ca.pem').read_bytes())
        (directory / 'swanctl.conf').write_text(profile(local, remote, identity, peer, role == 'o'))
        daemon_config(directory)
    # Signing key is never needed by either daemon, and is removed after issuance.
    (ca / 'ca.key').unlink()


def daemon_config(directory):
    (directory / 'strongswan.conf').write_text(f'''charon {{
 install_routes = no
 load = random nonce x509 constraints pubkey pkcs1 pkcs8 pem openssl sha2 hmac kdf kernel-netlink socket-default vici
 plugins {{
  vici {{
   socket = unix://{directory}/vici
  }}
 }}
}}
''')


def provision_operator(state, source):
    """Copy explicit protected operator credentials; never issue a CA in native mode."""
    if source.resolve() != source or source.stat().st_uid != 0 or stat.S_IMODE(source.stat().st_mode) != 0o700:
        raise ValueError('credentials require a real root-owned mode-0700 directory')
    for role in ('e', 'o'):
        origin = source / role
        # A trusted operator supplies reciprocal, pinned swanctl profiles and PKI.
        required = ('swanctl.conf', 'private/identity.pem', 'x509/identity.pem', 'x509ca/ca.pem')
        for name in required:
            path = origin / name
            if path.resolve() != path or not path.is_file() or path.stat().st_uid != 0:
                raise ValueError('untrusted operator credential path')
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise ValueError('operator credential files must be mode 0600')
        directory = state / role
        directory.mkdir(mode=0o700)
        for name in ('private', 'x509', 'x509ca'):
            (directory / name).mkdir(mode=0o700)
        for name in required:
            shutil.copyfile(origin / name, directory / name)
            (directory / name).chmod(0o600)
        daemon_config(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['NATIVE', 'EXTERNAL_CONFIG'], required=True)
    parser.add_argument('--local', default='192.0.2.1')
    parser.add_argument('--remote', default='192.0.2.2')
    parser.add_argument('--local-id', default='endpoint.test')
    parser.add_argument('--remote-id', default='gateway.test')
    args = parser.parse_args()
    print(profile(args.local, args.remote, args.local_id, args.remote_id))
    if args.mode == 'EXTERNAL_CONFIG':
        print('# Configuration only: require peer certificate SAN, dedicated trusted CA,')
        print('# reciprocal UDP/51821 /32 selectors, tunnel ESP, routing and fail-closed ACLs.')
        print('# No remote deployment, appliance test, or interoperability assertion.')


if __name__ == '__main__':
    main()
