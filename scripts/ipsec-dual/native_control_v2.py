"""Opt-in, deny-only native supervisor V2 control plane. No packet gate calls.

Input is a 0600 owner-owned atomic-rename spool in a 0700 private directory.
The challenge output is informational (signed); only pinned signatures authorize
operations and Java V2 approvals. Local journals are NOT rollback resistant.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from admission_v2 import Admission
from authorization_aa_v2 import AttestationVerifier, request_attestation as aa_request


def aa_scope_for(scope):
    """Bind AA policy to the complete native enforcement scope, not service alone."""
    fields = ('serviceId', 'clientNodeId', 'ownerNodeId', 'resource')
    if type(scope) is not dict or set(scope) != set(fields):
        raise ValueError('invalid AA enforcement scope')
    patterns = (r'[A-Za-z0-9._-]{1,128}', r'[0-9a-f]{64}', r'[0-9a-f]{64}',
                r'tcp:[0-9.]{7,15}:[0-9]{1,5}')
    for field, pattern in zip(fields, patterns):
        if type(scope[field]) is not str or not re.fullmatch(pattern, scope[field]):
            raise ValueError('invalid AA scope field')
    text = 'DEFENDERLINK-NATIVE-AA-SCOPE-V2\n' + ''.join(f'{key}={scope[key]}\n' for key in fields)
    return hashlib.sha256(text.encode('ascii')).hexdigest()


def boot_id():
    value = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value):
        raise ValueError('invalid kernel boot ID')
    return value


def private_directory(path):
    path = Path(path)
    st = path.lstat()
    if (not path.is_absolute() or path.resolve() != path or not stat.S_ISDIR(st.st_mode)
            or st.st_uid != os.getuid() or st.st_mode & 0o077):
        raise ValueError('private, real owner-owned directory required')
    return path


def private_read(path, limit=65536):
    """Read only a single regular private inode, never following links."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077
                or st.st_nlink != 1 or st.st_size > limit or st.st_ino != os.lstat(path).st_ino):
            raise ValueError('unsafe spool entry')
        data = os.read(fd, limit + 1)
        if len(data) != st.st_size:
            raise ValueError('spool changed while reading')
        return data
    finally:
        os.close(fd)


def atomic_private_write(path, data):
    temporary = path.with_name('.' + path.name + '-' + secrets.token_hex(16))
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class Controller:
    def __init__(self, directory, scope, operator_key, node_key, supervisor_signer,
                 aa_url, ca_file, node_cert, node_tls_key, aa_key, request_attestation=None):
        self.directory = private_directory(directory)
        if not aa_url or not all((ca_file, node_cert, node_tls_key)):
            raise ValueError('AA endpoint and mTLS paths required')
        if (type(node_key) is not bytes or len(node_key) != 32
                or scope.get('ownerNodeId') != node_key.hex()):
            raise ValueError('native owner node and AA mTLS node pin must match')
        self.url, self.ca, self.cert, self.key = aa_url, ca_file, node_cert, node_tls_key
        self.request_attestation = request_attestation or aa_request
        self.signer = supervisor_signer
        self.session = secrets.token_hex(16)
        self.scope = dict(scope)
        self.scope['bootId'] = boot_id()
        supervisor_key = supervisor_signer.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.admission = Admission(self.directory/'admission.journal', operator_key, node_key,
                                   supervisor_key, self.scope, self.session)
        self.node_id = node_key.hex()
        self.aa_scope = aa_scope_for(scope)
        self.aa_key = aa_key
        self.highwater = self.directory/'aa-highwater.json'
        self.floors = self._load_floors()
        if not self.highwater.exists():
            atomic_private_write(self.highwater, json.dumps(dict(nodeId=self.node_id,
                scope=self.aa_scope, generation=0, revocation=0, epoch=0)).encode())
        self.until_ms = 0
        self.until_ns = 0
        self.approval_nonce = None
        self._publish_challenge()

    def _load_floors(self):
        try:
            data = json.loads(private_read(self.highwater))
            if (set(data) != {'nodeId', 'scope', 'generation', 'revocation', 'epoch'}
                    or data['nodeId'] != self.node_id or data['scope'] != self.aa_scope
                    or any(type(data[k]) is not int or data[k] < 0 for k in ('generation', 'revocation', 'epoch'))):
                raise ValueError('invalid AA highwater')
            return tuple(data[k] for k in ('generation', 'revocation', 'epoch'))
        except FileNotFoundError:
            # Existing admission history without an AA floor must not be promoted.
            if self.admission.generation:
                raise ValueError('missing AA highwater for existing journal')
            return (0, 0, 0)

    def _publish_challenge(self):
        challenge = self.admission.challenge(self.signer.sign, time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        atomic_private_write(self.directory/'challenge.json', json.dumps(challenge, sort_keys=True).encode())

    def _input(self):
        try:
            raw = private_read(self.directory/'inbox.json')
        except FileNotFoundError:
            return None
        return json.loads(raw, object_pairs_hook=_unique_pairs)

    def step(self):
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        status = self.admission.state(now)
        if status != 'AUTHORIZED':
            self.until_ms = self.until_ns = 0
        try:
            if self._load_floors() != self.floors:
                raise ValueError('AA highwater changed outside supervisor')
            item = self._input()
            if item is not None and type(item) is dict and set(item) == {'operation', 'signature'}:
                signature = base64.b64decode(item['signature'], validate=True)
                if self.admission.apply_operation(item['operation'], signature, now):
                    self.approval_nonce = None
                    self._publish_challenge()
            elif item is not None and type(item) is dict and set(item) == {'envelope'}:
                pending = self.admission.pending
                if pending and self.admission.accept(item['envelope'], now) is not None:
                    self.approval_nonce = pending['nonce']
                    self.until_ms = self.until_ns = 0
                    self._attest(now)
                    self._publish_challenge()
            now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            if self.admission.state(now) != 'AUTHORIZED':
                return 'DENIED'
            if self.approval_nonce and not self.until_ns:
                self._attest(now)
            if now >= self.until_ns or int(time.time()*1000) >= self.until_ms:
                return 'DENIED'
            return 'ATTESTED'  # informational only; never opens packet ACLs
        except (OSError, ValueError, TypeError, KeyError):
            self.until_ms = self.until_ns = 0
            return 'DENIED'

    def _attest(self, now):
        verifier = AttestationVerifier(self.aa_key, self.node_id, self.aa_scope, *self.floors)
        request = dict(version=2, nodeId=self.node_id, scope=self.aa_scope,
                       challenge=secrets.token_hex(16), bootId=self.scope['bootId'].replace('-', ''),
                       sessionId=self.session, lastObservedGeneration=self.floors[0])
        if not self.request_attestation(self.url, self.ca, self.cert, self.key, request, verifier):
            return
        floors = (verifier.generation_floor, verifier.revocation_floor, verifier.epoch_floor)
        # The AA signature has been checked by verifier before durable floor update.
        data = dict(nodeId=self.node_id, scope=self.aa_scope, generation=floors[0],
                    revocation=floors[1], epoch=floors[2])
        atomic_private_write(self.highwater, json.dumps(data, sort_keys=True).encode())
        self.floors = floors
        # AA verifier bounds its wall-clock validity to 30 s. Use a shorter
        # monotonic interval; wall-clock step still checks this deadline too.
        remaining_ms = max(0, min(29000, verifier.accepted_expires_at_ms - int(time.time()*1000)))
        self.until_ms = verifier.accepted_expires_at_ms
        self.until_ns = min(self.admission.deadline, time.clock_gettime_ns(time.CLOCK_BOOTTIME) + remaining_ms * 1_000_000)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON field')
        result[key] = value
    return result
