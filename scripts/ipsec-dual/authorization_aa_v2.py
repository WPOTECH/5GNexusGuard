"""Isolated, opt-in native authorization authority. No traffic enforcement hooks."""
import argparse
import base64
import binascii
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import stat
import ssl
import threading
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DOMAIN = b'DEFENDERLINK-NATIVE-AA-ATTEST-V2\n'
FIELDS = ('version', 'nodeId', 'scope', 'challenge', 'bootId', 'sessionId',
          'epoch', 'generation', 'revocation', 'issuanceId', 'issuedAtMs', 'expiresAtMs')
REQUEST = {'version', 'nodeId', 'scope', 'challenge', 'bootId', 'sessionId', 'lastObservedGeneration'}
TRANSITION = {'version', 'nodeId', 'scope', 'generation', 'revocation', 'epoch', 'action'}
MAX_VALIDITY_MS = 30000


def _token(value, pattern):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def _number(value, positive=False):
    return type(value) is int and (0 < value if positive else 0 <= value) and value < 2**63


def _identity(node, scope):
    return _token(node, r'[0-9a-f]{64}') and _token(scope, r'[A-Za-z0-9._-]{1,128}')


def canonical(payload):
    if type(payload) is not dict or set(payload) != set(FIELDS) or payload['version'] != 2 or type(payload['version']) is not int:
        raise ValueError('invalid attestation schema')
    if not _identity(payload['nodeId'], payload['scope']) or not all(
            _token(payload[key], r'[0-9a-f]{32}') for key in ('challenge', 'bootId', 'sessionId', 'issuanceId')):
        raise ValueError('invalid attestation identity')
    if not all(_number(payload[key], key != 'revocation') for key in
               ('epoch', 'generation', 'revocation', 'issuedAtMs', 'expiresAtMs')):
        raise ValueError('invalid attestation number')
    if not 0 < payload['expiresAtMs'] - payload['issuedAtMs'] <= MAX_VALIDITY_MS:
        raise ValueError('invalid attestation lifetime')
    return DOMAIN + ''.join(f'{key}={payload[key]}\n' for key in FIELDS).encode('ascii')


def _fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _fsync_file(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Denied(ValueError):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


class Authority:
    """SQLite FULL+DELETE journal; always quarantine pre-existing state on process start."""
    def __init__(self, path, signing_key, node_fingerprints, operator_fingerprint, operator_key_pin=None, max_issuances=100000):
        self.path = Path(path)
        parent = self.path.parent
        if not self.path.is_absolute() or parent.resolve() != parent:
            raise ValueError('AA state requires an absolute, non-symlinked parent path')
        parent_stat = parent.lstat()
        if (not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_uid != os.getuid()
                or parent_stat.st_mode & 0o077):
            raise ValueError('state parent must be owner-owned, real, and private (0700)')
        if self.path.is_symlink():
            raise ValueError('symlink database refused')
        if self.path.exists() and self.path.stat().st_mode & 0o077:
            raise ValueError('existing database must be private (0600)')
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise ValueError('AA signing key must be Ed25519')
        signing_id = signing_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        if signing_id in node_fingerprints:
            raise ValueError('AA signing identity must differ from node client identity')
        self.signing_key = signing_key
        self.nodes = dict(node_fingerprints)
        self.operator = operator_fingerprint
        if not all(_token(k, r'[0-9a-f]{64}') and _token(v, r'[0-9a-f]{64}') for k, v in self.nodes.items()) or not _token(self.operator, r'[0-9a-f]{64}'):
            raise ValueError('explicit node and operator certificate SHA256 pins required')
        if self.operator in self.nodes.values():
            raise ValueError('operator certificate pin must differ from every node certificate pin')
        if operator_key_pin is not None and (not _token(operator_key_pin, r'[0-9a-f]{64}') or operator_key_pin in self.nodes):
            raise ValueError('operator public key pin must be distinct from node public keys')
        self.operator_key_pin = operator_key_pin
        if type(max_issuances) is not int or not 1 <= max_issuances <= 1000000:
            raise ValueError('max_issuances must be in 1..1000000')
        self.max_issuances = max_issuances
        existed = self.path.exists()
        self.bootstrap_marker = Path(str(self.path) + '.pristine')
        self.used_marker = Path(str(self.path) + '.used')
        if not existed:
            if self.bootstrap_marker.exists() or self.bootstrap_marker.is_symlink() or self.used_marker.exists() or self.used_marker.is_symlink():
                raise ValueError('new database cannot reuse historical markers')
            # SQLite otherwise creates the file with the process umask (often 0644).
            # Reserve it exclusively at 0600 before handing the path to SQLite.
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            _fsync_directory(self.path.parent)
        self.lock = threading.RLock()
        self.quarantined = existed
        self.pending_recovery = set()
        self.db = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        try:
            if not existed:
                os.chmod(self.path, 0o600)
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA busy_timeout=5000')
            self.db.executescript('''
                CREATE TABLE IF NOT EXISTS scopes(node TEXT NOT NULL, scope TEXT NOT NULL,
                    generation INTEGER NOT NULL, revocation INTEGER NOT NULL, epoch INTEGER NOT NULL,
                    authorized INTEGER NOT NULL, PRIMARY KEY(node,scope));
                CREATE TABLE IF NOT EXISTS challenges(node TEXT NOT NULL, scope TEXT NOT NULL,
                    challenge TEXT NOT NULL, PRIMARY KEY(node,scope,challenge));
                CREATE TABLE IF NOT EXISTS issuances(id TEXT PRIMARY KEY, node TEXT NOT NULL, scope TEXT NOT NULL,
                    generation INTEGER NOT NULL, epoch INTEGER NOT NULL, expires_ms INTEGER NOT NULL,
                    valid INTEGER NOT NULL);
            ''')
            self._sync()
            if not existed:
                self._create_marker(self.bootstrap_marker)
            else:
                self.pending_recovery = set(self.db.execute('SELECT node,scope FROM scopes'))
            def private_marker(path):
                try:
                    info = path.lstat()
                    return stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077
                except FileNotFoundError:
                    return False
            self.bootstrap_eligible = (existed and private_marker(self.bootstrap_marker)
                and self.bootstrap_marker.read_bytes() == b'fresh'
                and not self.used_marker.exists() and not self.used_marker.is_symlink()
                and not self.pending_recovery and all(self.db.execute(
                    f'SELECT COUNT(*) FROM {table}').fetchone()[0] == 0
                    for table in ('scopes', 'challenges', 'issuances')))
            if self.used_marker.is_symlink() or (self.used_marker.exists() and not private_marker(self.used_marker)):
                raise ValueError('unsafe history marker')
        except Exception:
            self.db.close()
            raise

    def _create_marker(self, path):
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, b'fresh' if path == self.bootstrap_marker else b'used!')
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_directory(path.parent)

    def _mark_history(self):
        if self.bootstrap_marker.exists():
            fd = os.open(self.bootstrap_marker, os.O_WRONLY | os.O_NOFOLLOW)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise ValueError('unsafe bootstrap marker')
                os.write(fd, b'used!')
                os.fsync(fd)
            finally:
                os.close(fd)
        if not self.used_marker.exists():
            self._create_marker(self.used_marker)

    def _sync(self):
        # SQLite FULL syncs rollback journal before database writes and syncs database
        # before commit returns. Also explicitly sync final DB inode and directory entry.
        _fsync_file(self.path)
        _fsync_directory(self.path.parent)

    def close(self):
        with self.lock:
            self.db.close()

    def _commit(self, callback):
        with self.lock:
            try:
                self.db.execute('BEGIN IMMEDIATE')
                result = callback()
                self.db.execute('COMMIT')
                self._sync()  # NO acknowledgment/signature before both fsyncs succeed.
                return result
            except Denied:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
                raise
            except Exception:
                if self.db.in_transaction:
                    self.db.execute('ROLLBACK')
                self.quarantined = True  # ambiguous commit/sync => quarantine, not retry.
                raise

    def transition(self, payload):
        if type(payload) is not dict or set(payload) != TRANSITION or type(payload['version']) is not int or payload['version'] != 2:
            raise Denied(400, 'invalid transition')
        node, scope = payload['nodeId'], payload['scope']
        if not _identity(node, scope) or node not in self.nodes or not all(
                _number(payload[k], k != 'revocation') for k in ('generation', 'revocation', 'epoch')) or payload['action'] not in ('authorize', 'revoke', 'recover'):
            raise Denied(400, 'invalid transition fields')
        def change():
            row = self.db.execute('SELECT generation,revocation,epoch,authorized FROM scopes WHERE node=? AND scope=?', (node, scope)).fetchone()
            old_g, old_r, old_e, _ = row or (0, 0, 0, 0)
            g, r, e = (payload[k] for k in ('generation', 'revocation', 'epoch'))
            action = payload['action']
            if action == 'recover':
                if self.quarantined and not self.pending_recovery:
                    self.pending_recovery = set(self.db.execute('SELECT node,scope FROM scopes'))
                if (not self.quarantined or
                        not ((row is not None and (node, scope) in self.pending_recovery)
                             or (row is None and self.bootstrap_eligible))
                        or g < old_g or r < old_r or e <= old_e):
                    raise Denied(409, 'recovery requires nondecreasing floors and fresh epoch')
                allowed = 0
            elif self.quarantined:
                raise Denied(503, 'authority quarantined')
            elif action == 'authorize':
                if g <= old_g or r < old_r or e <= old_e:
                    raise Denied(409, 'nonmonotonic authorization')
                allowed = 1
            else:
                if row is None or g < old_g or r <= old_r or e <= old_e:
                    raise Denied(409, 'nonmonotonic revocation')
                allowed = 0
            if not self.used_marker.exists():
                self._mark_history()  # Durable history before any scope commit.
            self.db.execute('INSERT INTO scopes VALUES (?,?,?,?,?,?) ON CONFLICT(node,scope) DO UPDATE SET generation=excluded.generation,revocation=excluded.revocation,epoch=excluded.epoch,authorized=excluded.authorized',
                            (node, scope, g, r, e, allowed))
            self.db.execute('UPDATE issuances SET valid=0 WHERE node=? AND scope=?', (node, scope))
            return action
        with self.lock:
            try:
                action = self._commit(change)
            except Denied:
                raise
            except (sqlite3.Error, OSError) as exc:
                raise Denied(503, 'durability unavailable') from exc
            if action == 'recover':
                self.bootstrap_eligible = False
                self.pending_recovery.discard((node, scope))
                if not self.pending_recovery:
                    self.quarantined = False  # atomic with commit; no later failure can be overwritten
            return {'status': 'committed', 'authorized': action == 'authorize'}

    def attest(self, request):
        if type(request) is not dict or set(request) != REQUEST or type(request['version']) is not int or request['version'] != 2:
            raise Denied(400, 'invalid request')
        node, scope = request['nodeId'], request['scope']
        if not _identity(node, scope) or node not in self.nodes or not all(
                _token(request[k], r'[0-9a-f]{32}') for k in ('challenge', 'bootId', 'sessionId')) or not _number(request['lastObservedGeneration']):
            raise Denied(400, 'invalid request fields')
        if self.quarantined:
            raise Denied(503, 'authority quarantined')
        def issue():
            if self.quarantined:
                raise Denied(503, 'authority quarantined')
            row = self.db.execute('SELECT generation,revocation,epoch,authorized FROM scopes WHERE node=? AND scope=?', (node, scope)).fetchone()
            if row is None or not row[3]:
                raise Denied(403, 'not authorized')
            g, r, e, _ = row
            if request['lastObservedGeneration'] > g:
                self.quarantined = True
                raise Denied(409, 'local generation ahead of authority; quarantine required')
            if self.db.execute('SELECT 1 FROM challenges WHERE node=? AND scope=? AND challenge=?',
                               (node, scope, request['challenge'])).fetchone():
                raise Denied(409, 'duplicate challenge')
            if any(self.db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0] >= self.max_issuances
                   for table in ('challenges', 'issuances')):
                raise Denied(503, 'persistent issuance quota exhausted')
            try:
                self.db.execute('INSERT INTO challenges VALUES (?,?,?)', (node, scope, request['challenge']))
            except sqlite3.IntegrityError as exc:
                raise Denied(409, 'duplicate challenge') from exc
            issued = int(time.time() * 1000)
            payload = dict(version=2, nodeId=node, scope=scope, challenge=request['challenge'],
                           bootId=request['bootId'], sessionId=request['sessionId'], epoch=e,
                           generation=g, revocation=r, issuanceId=secrets.token_hex(16),
                           issuedAtMs=issued, expiresAtMs=issued + MAX_VALIDITY_MS)
            canonical(payload)
            self.db.execute('INSERT INTO issuances VALUES (?,?,?,?,?,?,1)',
                            (payload['issuanceId'], node, scope, g, e, payload['expiresAtMs']))
            return payload
        try:
            payload = self._commit(issue)
            signature = self.signing_key.sign(canonical(payload))
            return {'payload': payload, 'signature': base64.b64encode(signature).decode('ascii')}
        except Denied:
            raise
        except (sqlite3.Error, OSError, ValueError) as exc:
            self.quarantined = True
            raise Denied(503, 'issuance unavailable') from exc


class AttestationVerifier:
    """In-memory supervisor helper, fail closed on restart until fresh recovery/challenge."""
    def __init__(self, aa_key, node_id, scope, generation_floor=0, revocation_floor=0, epoch_floor=0):
        if type(aa_key) is not bytes or len(aa_key) != 32 or not _identity(node_id, scope) or not all(
                _number(x) for x in (generation_floor, revocation_floor, epoch_floor)):
            raise ValueError('explicit AA response key pin and identity/floors required')
        self.key = Ed25519PublicKey.from_public_bytes(aa_key)
        self.node_id, self.scope = node_id, scope
        self.generation_floor, self.revocation_floor, self.epoch_floor = generation_floor, revocation_floor, epoch_floor
        self.pending = None
        self.seen = set()
        self.lock = threading.RLock()
        self.accepted_expires_at_ms = None

    def challenge(self, request):
        with self.lock:
            if type(request) is not dict or set(request) != REQUEST or request.get('nodeId') != self.node_id or request.get('scope') != self.scope or not all(
                    _token(request.get(k), r'[0-9a-f]{32}') for k in ('challenge', 'bootId', 'sessionId')) or type(request.get('lastObservedGeneration')) is not int or request['lastObservedGeneration'] != self.generation_floor:
                raise ValueError('invalid challenge context')
            self.pending = dict(request)

    def accept(self, envelope, now_ms=None):
        with self.lock:
            return self._accept_locked(envelope, now_ms)

    def _accept_locked(self, envelope, now_ms):
        try:
            if self.pending is None or type(envelope) is not dict or set(envelope) != {'payload', 'signature'}:
                return False
            p = envelope['payload']
            message = canonical(p)
            if any(p[k] != self.pending[k] for k in ('nodeId', 'scope', 'challenge', 'bootId', 'sessionId')):
                return False
            if p['generation'] < self.generation_floor or p['revocation'] < self.revocation_floor or p['epoch'] < self.epoch_floor or p['issuanceId'] in self.seen:
                return False
            now = int(time.time() * 1000) if now_ms is None else now_ms
            if type(now) is not int or not p['issuedAtMs'] - 5000 <= now < p['expiresAtMs']:
                return False
            text = envelope['signature']
            if type(text) is not str:
                return False
            signature = base64.b64decode(text, validate=True)
            if len(signature) != 64 or base64.b64encode(signature).decode('ascii') != text:
                return False
            self.key.verify(signature, message)
            self.seen.add(p['issuanceId'])
            self.pending = None
            self.accepted_expires_at_ms = p['expiresAtMs']
            self.generation_floor = p['generation']
            self.revocation_floor = p['revocation']
            self.epoch_floor = p['epoch']
            return True
        except (ValueError, TypeError, KeyError, InvalidSignature, binascii.Error):
            return False


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('duplicate JSON field')
        obj[key] = value
    return obj


class AuthorityServer(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, authority, server_cert, server_key, client_ca, max_workers=32):
        if type(max_workers) is not int or not 1 <= max_workers <= 256:
            raise ValueError('max_workers must be in 1..256')
        self.authority = authority
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        self._worker_lock = threading.Lock()
        self.active_workers = 0
        super().__init__(address, _Handler)
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(server_cert, server_key)
            context.load_verify_locations(cafile=client_ca)
            context.verify_mode = ssl.CERT_REQUIRED
            self.tls_context = context
        except Exception:
            self.server_close()
            raise

    def process_request(self, request, client_address):
        if not self._worker_slots.acquire(blocking=False):
            self.shutdown_request(request)  # Refuse before TLS, without allocating a worker.
            return
        with self._worker_lock:
            self.active_workers += 1
        try:
            super().process_request(request, client_address)
        except Exception:
            with self._worker_lock:
                self.active_workers -= 1
            self._worker_slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._worker_lock:
                self.active_workers -= 1
            self._worker_slots.release()

    def finish_request(self, request, client_address):
        # Accept stays plaintext; the bounded TLS handshake runs in a worker.
        request.settimeout(2)
        try:
            with self.tls_context.wrap_socket(request, server_side=True) as secure:
                super().finish_request(secure, client_address)
        except (ssl.SSLError, OSError):
            pass  # Failed/idle peer cannot block the accept loop or quarantine AA.


class _Handler(BaseHTTPRequestHandler):
    def handle_one_request(self):
        # socket timeouts are per read; a peer could trickle header lines forever.
        expired = threading.Event()
        def expire_headers():
            expired.set()
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(2, expire_headers)
        timer.daemon = True
        self._header_timer = timer
        self._header_expired = expired
        timer.start()
        try:
            return super().handle_one_request()
        except OSError:
            if not expired.is_set():
                raise
        finally:
            timer.cancel()

    def do_POST(self):
        self._header_timer.cancel()
        if self._header_expired.is_set():
            return  # A timed-out header is not an AA state or durability failure.
        role = {'/v2/authorization/attest': 'node',
                '/v2/authorization/transition': 'operator'}.get(self.path)
        if role is None:
            self.send_error(404)
            return
        try:
            der = self.connection.getpeercert(binary_form=True)
            if not der:
                raise Denied(403, 'client certificate required')
            fingerprint = hashlib.sha256(der).hexdigest()
            length = self.headers.get('Content-Length', '')
            if self.headers.get('Content-Type') != 'application/json' or not length.isdecimal() or not 0 < int(length) <= 4096:
                raise Denied(400, 'invalid content framing')
            deadline = time.monotonic() + 2
            remaining = int(length)
            chunks = []
            while remaining:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise Denied(408, 'request body timeout')
                self.connection.settimeout(left)
                try:
                    chunk = self.rfile.read(min(remaining, 1024))
                except TimeoutError as exc:
                    raise Denied(408, 'request body timeout') from exc
                if not chunk:
                    raise Denied(400, 'incomplete request body')
                chunks.append(chunk)
                remaining -= len(chunk)
            body = b''.join(chunks)
            payload = json.loads(body, object_pairs_hook=_unique_pairs)
            if role == 'node':
                if type(payload) is not dict or not _token(payload.get('nodeId'), r'[0-9a-f]{64}') or self.server.authority.nodes.get(payload['nodeId']) != fingerprint:
                    raise Denied(403, 'node certificate pin mismatch')
                cert = x509.load_der_x509_certificate(der)
                public = cert.public_key()
                if not isinstance(public, Ed25519PublicKey) or public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex() != payload['nodeId']:
                    raise Denied(403, 'node key identity mismatch')
                result = self.server.authority.attest(payload)
            else:
                if fingerprint != self.server.authority.operator:
                    raise Denied(403, 'operator pin mismatch')
                operator_key = x509.load_der_x509_certificate(der).public_key()
                if not isinstance(operator_key, Ed25519PublicKey):
                    raise Denied(403, 'operator Ed25519 key required')
                operator_id = operator_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
                if operator_id in self.server.authority.nodes or (self.server.authority.operator_key_pin is not None
                        and operator_id != self.server.authority.operator_key_pin):
                    raise Denied(403, 'operator public key pin mismatch or node key reuse')
                result = self.server.authority.transition(payload)
            status = 200
        except Denied as exc:
            status, result = exc.status, {'error': str(exc)}
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            status, result = 400, {'error': 'malformed JSON'}
        except Exception:
            status, result = 503, {'error': 'authority unavailable'}
            self.server.authority.quarantined = True
        data = json.dumps(result, separators=(',', ':'), sort_keys=True).encode('utf-8')
        self.connection.settimeout(2)
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        pass  # no identity/challenge logging


def request_attestation(url, ca_file, node_cert, node_key, request, verifier):
    """Explicit HTTPS endpoint and trust paths; True only for authenticated, fresh response."""
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.path != '/v2/authorization/attest' or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise ValueError('explicit HTTPS attest endpoint required')
    context = ssl.create_default_context(cafile=ca_file)
    context.load_cert_chain(node_cert, node_key)
    verifier.challenge(request)
    try:
        body = json.dumps(request, separators=(',', ':')).encode('utf-8')
        http_request = Request(url, body, {'Content-Type': 'application/json'}, method='POST')
        with urlopen(http_request, context=context, timeout=5) as response:
            if response.status != 200:
                return False
            data = response.read(8193)
            if len(data) > 8192:
                return False
            envelope = json.loads(data, object_pairs_hook=_unique_pairs)
            return verifier.accept(envelope)
    except HTTPError as exc:
        exc.close()
        return False
    except (URLError, OSError, ssl.SSLError, ValueError, TypeError):
        return False
    finally:
        verifier.pending = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ('db', 'signing-key', 'server-cert', 'server-key', 'client-ca', 'node-pins', 'operator-pin', 'operator-key-pin'):
        parser.add_argument('--' + option, required=True)
    parser.add_argument('--max-workers', type=int, default=32, help='concurrent TLS workers (1..256; default 32)')
    parser.add_argument('--max-issuances', type=int, default=100000, help='lifetime persistent issuance/challenge rows (1..1000000; default 100000)')
    parser.add_argument('--bind', required=True, help='explicit listen host (no default)')
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()
    key = serialization.load_pem_private_key(Path(args.signing_key).read_bytes(), password=None)
    pins = json.loads(Path(args.node_pins).read_text())
    authority = Authority(args.db, key, pins, args.operator_pin,
                          operator_key_pin=args.operator_key_pin, max_issuances=args.max_issuances)
    server = AuthorityServer((args.bind, args.port), authority, args.server_cert, args.server_key,
                             args.client_ca, max_workers=args.max_workers)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        authority.close()


if __name__ == '__main__':
    main()
