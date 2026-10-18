"""Disconnected admission control; no traffic integration or packet gate.

A restarted process always quarantines grants. Journal rollback cannot be detected
without an external monotonic anchor; recovery requires a NEW operator signature.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from issuance_v2 import verify

CHALLENGE_FIELDS = ('bootId', 'sessionId', 'nonce', 'serviceId', 'clientNodeId', 'ownerNodeId', 'resource')
OP_FIELDS = ('action', 'bootId', 'sessionId', 'nonce', 'generation', 'serviceId', 'clientNodeId', 'ownerNodeId', 'resource')


def challenge_bytes(challenge):
    if type(challenge) is not dict or set(challenge) != set(CHALLENGE_FIELDS):
        raise ValueError('invalid challenge')
    for field in CHALLENGE_FIELDS:
        value = challenge[field]
        if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9.:_-]{1,128}', value):
            raise ValueError('invalid challenge field')
    if not re.fullmatch(r'[0-9a-f]{32}', challenge['nonce']):
        raise ValueError('invalid nonce')
    return ('DEFENDERLINK-NATIVE-CHALLENGE-V2\n' + ''.join(f'{k}={challenge[k]}\n' for k in CHALLENGE_FIELDS)).encode('ascii')


def operation_bytes(op):
    if type(op) is not dict or set(op) != set(OP_FIELDS) or op['action'] not in ('REVOKE', 'RECOVER'):
        raise ValueError('invalid operation')
    if type(op['generation']) is not int or not 0 < op['generation'] < 2**63:
        raise ValueError('invalid generation')
    challenge_bytes({k: op[k] for k in CHALLENGE_FIELDS})
    return ('DEFENDERLINK-NATIVE-OPERATION-V2\n' + ''.join(f'{k}={op[k]}\n' for k in OP_FIELDS)).encode('ascii')


def _verify(key, signature, data):
    try:
        if len(key) != 32 or len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(key).verify(signature, data)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


class Admission:
    """One process-local session. No persisted grant is ever reactivated."""
    def __init__(self, path, operator_key, node_key, supervisor_key, scope, session_id):
        self.path = Path(path)
        self.operator_key, self.node_key, self.supervisor_key = operator_key, node_key, supervisor_key
        self.scope, self.session_id = dict(scope), session_id
        if len({operator_key, node_key, supervisor_key}) != 3 or any(len(k) != 32 for k in (operator_key, node_key, supervisor_key)):
            raise ValueError('distinct pins required')
        self.generation = 0
        self.seen = set()
        self.pending = None
        self.deadline = None
        self.status = 'DENIED'
        self.last_now = None
        self.digest = '0' * 64
        self.healthy = self._load()
        # Deliberately DENIED regardless of the last persisted status.

    def _parent_is_private(self):
        try:
            parent = self.path.parent
            info = parent.lstat()
            return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                    and not (info.st_mode & 0o077) and parent.resolve() == parent)
        except OSError:
            return False

    def _load(self):
        try:
            if not self._parent_is_private():
                return False
            st = self.path.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_nlink != 1:
                return False
            digest = '0' * 64
            entries = self.path.read_bytes().splitlines(keepends=True)
            if not entries or any(not x.endswith(b'\n') for x in entries):
                return False
            generation, seen = 0, set()
            for line in entries:
                record = json.loads(line)
                if type(record) is not dict or set(record) != {'previous', 'event', 'digest'} or record['previous'] != digest:
                    return False
                event = record['event']
                body = json.dumps(event, sort_keys=True, separators=(',', ':')).encode()
                digest = hashlib.sha256(digest.encode() + body).hexdigest()
                if record['digest'] != digest or type(event) is not dict or set(event) != {'type', 'generation', 'issuanceId'}:
                    return False
                if event['type'] not in ('RECOVER', 'ALLOW', 'REVOKE') or type(event['generation']) is not int or event['generation'] <= generation:
                    return False
                if event['issuanceId'] in seen:
                    return False
                seen.add(event['issuanceId'])
                generation = event['generation']
            self.digest, self.generation, self.seen = digest, generation, seen
            return True
        except (OSError, ValueError, TypeError, KeyError, UnicodeError):
            return False

    def state(self, now_ns):
        if self.healthy:
            digest, generation, seen = self.digest, self.generation, self.seen.copy()
            if (not self._load() or self.digest != digest or self.generation != generation
                    or self.seen != seen):
                self.healthy = False
                self.status, self.deadline, self.pending = 'DENIED', None, None
        if type(now_ns) is not int or now_ns < 0 or (self.last_now is not None and now_ns < self.last_now):
            self.status, self.deadline, self.pending = 'DENIED', None, None
            self.healthy = False
        else:
            self.last_now = now_ns
            if self.status == 'AUTHORIZED' and now_ns >= self.deadline:
                self.status, self.deadline = 'EXPIRED', None
        return self.status

    def challenge(self, supervisor_signer, now_ns):
        self.state(now_ns)
        challenge = dict(self.scope, sessionId=self.session_id, nonce=secrets.token_hex(16))
        message = challenge_bytes(challenge)
        signature = supervisor_signer(message)
        if not _verify(self.supervisor_key, signature, message):
            raise SecurityError('invalid supervisor challenge')
        self.pending = challenge
        return dict(challenge, supervisorSignature=base64.b64encode(signature).decode('ascii'))

    def _append(self, kind, generation, issuance_id, reset=False):
        event = dict(type=kind, generation=generation, issuanceId=issuance_id)
        previous = '0' * 64 if reset else self.digest
        body = json.dumps(event, sort_keys=True, separators=(',', ':')).encode()
        digest = hashlib.sha256(previous.encode() + body).hexdigest()
        record = (json.dumps(dict(previous=previous, event=event, digest=digest), sort_keys=True, separators=(',', ':')) + '\n').encode()
        try:
            if not self._parent_is_private():
                self.status, self.deadline, self.healthy = 'DENIED', None, False
                return False
            if reset:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            else:
                if not self.healthy or not self._load() or self.digest != previous:
                    self.status, self.deadline, self.healthy = 'DENIED', None, False
                    return False
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077 or st.st_nlink != 1:
                    return False
                pending = memoryview(record)
                while pending:
                    written = os.write(fd, pending)
                    if written <= 0:
                        raise OSError('short journal write')
                    pending = pending[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            if reset:
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            self.digest, self.generation = digest, generation
            self.seen.add(issuance_id)
            self.healthy = True
            return True
        except OSError:
            self.status, self.deadline, self.healthy = 'DENIED', None, False
            return False

    def accept(self, envelope, now_ns):
        if self.state(now_ns) not in ('PENDING_FRESH_APPROVAL', 'EXPIRED') or not self.healthy or not self.pending:
            return None
        p = envelope.get('payload') if type(envelope) is dict else None
        if (type(p) is not dict or type(p.get('issuanceId')) is not str
                or p['issuanceId'] in self.seen):
            return None
        deadline = verify(envelope, self.operator_key, self.node_key, self.scope,
                          self.pending['nonce'], self.generation, now_ns)
        if deadline is None or not self._append('ALLOW', p['generation'], p['issuanceId']):
            return None
        self.pending, self.deadline, self.status = None, deadline, 'AUTHORIZED'
        return deadline

    def apply_operation(self, op, signature, now_ns):
        self.state(now_ns)
        try:
            message = operation_bytes(op)
            if (not self.pending or any(op[k] != self.pending[k] for k in CHALLENGE_FIELDS)
                    or not _verify(self.operator_key, signature, message)
                    or op['generation'] <= self.generation):
                return False
            kind = op['action']
            if kind == 'REVOKE' and not self.healthy:
                return False
            if kind == 'RECOVER' and self.healthy and self.status not in ('DENIED', 'REVOKED'):
                return False
            if not self.healthy and self.path.exists():
                # Preserve corrupt evidence before signed recovery; never trust its floor.
                try:
                    st = self.path.lstat()
                    parent = self.path.parent.stat()
                    if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1
                            or st.st_mode & 0o077 or not stat.S_ISDIR(parent.st_mode)
                            or parent.st_mode & 0o077 or parent.st_uid != os.getuid()):
                        return False
                    archive = self.path.with_name(self.path.name + '.corrupt-' + secrets.token_hex(16))
                    os.rename(self.path, archive)
                    directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                except OSError:
                    return False
            if not self._append(kind, op['generation'], self.pending['nonce'], reset=not self.healthy):
                return False
            self.pending, self.deadline = None, None
            self.status = 'REVOKED' if kind == 'REVOKE' else 'PENDING_FRESH_APPROVAL'
            return True
        except (ValueError, KeyError, TypeError):
            return False


class SecurityError(Exception):
    pass
