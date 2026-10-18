"""Private JSON-lines fixture for NativeControlAaIntegrationTest; not a production entrypoint.

Private keys arrive only via stdin, remain in a 0700 temporary directory, and are
never included in responses. stdout is exclusively protocol JSON; no packet gate.
"""
import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from admission_v2 import operation_bytes
from authorization_aa_v2 import Authority, AuthorityServer
from native_control_v2 import Controller, atomic_private_write
from test_authorization_aa_v2 import certificate, pem_key


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)


class Fixture:
    def __init__(self, request):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.operator = serialization.load_der_private_key(base64.b64decode(request['operatorPkcs8']), None)
        self.node = serialization.load_der_private_key(base64.b64decode(request['nodePkcs8']), None)
        self.supervisor = serialization.load_der_private_key(base64.b64decode(request['supervisorPkcs8']), None)
        if not all(isinstance(key, Ed25519PrivateKey) for key in (self.operator, self.node, self.supervisor)):
            raise ValueError('Ed25519 keys required')
        self.node_id = self.node.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.scope = dict(serviceId='svc', clientNodeId='a' * 64, ownerNodeId=self.node_id,
                          resource='tcp:10.80.0.2:8080')
        self.ca_key = Ed25519PrivateKey.generate()
        ca = certificate(self.ca_key, 'test-ca', ca=True)
        private_write(self.root/'ca.pem', ca.public_bytes(serialization.Encoding.PEM))
        self.certs = {}
        for role, key in (('server', Ed25519PrivateKey.generate()), ('operator', self.operator), ('node', self.node)):
            cert = certificate(key, role, self.ca_key, ca)
            self.certs[role] = cert
            private_write(self.root/f'{role}.pem', cert.public_bytes(serialization.Encoding.PEM))
            private_write(self.root/f'{role}.key', pem_key(key))
        self.aa_signer = Ed25519PrivateKey.generate()
        self.authority = Authority(self.root/'state.sqlite', self.aa_signer,
            {self.node_id: self.certs['node'].fingerprint(hashes.SHA256()).hex()},
            self.certs['operator'].fingerprint(hashes.SHA256()).hex(),
            operator_key_pin=self.operator.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
        self.server = AuthorityServer(('127.0.0.1', 0), self.authority,
            str(self.root/'server.pem'), str(self.root/'server.key'), str(self.root/'ca.pem'))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.aa_generation = 1
        self.aa_revocation = 0
        self.aa_epoch = 1
        self.transition('authorize')
        self.controller = self.new_controller()

    def new_controller(self):
        from native_control_v2 import aa_scope_for
        return Controller(self.root, self.scope,
            self.operator.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw),
            bytes.fromhex(self.node_id), self.supervisor,
            f'https://127.0.0.1:{self.server.server_port}/v2/authorization/attest',
            str(self.root/'ca.pem'), str(self.root/'node.pem'), str(self.root/'node.key'),
            self.aa_signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def transition(self, action):
        import http.client
        import ssl
        from native_control_v2 import aa_scope_for
        ctx = ssl.create_default_context(cafile=str(self.root/'ca.pem'))
        ctx.load_cert_chain(str(self.root/'operator.pem'), str(self.root/'operator.key'))
        connection = http.client.HTTPSConnection('127.0.0.1', self.server.server_port, context=ctx, timeout=3)
        try:
            body = dict(version=2, nodeId=self.node_id, scope=aa_scope_for(self.scope),
                generation=self.aa_generation, revocation=self.aa_revocation,
                epoch=self.aa_epoch, action=action)
            connection.request('POST', '/v2/authorization/transition', json.dumps(body).encode(),
                               {'Content-Type': 'application/json'})
            response = connection.getresponse()
            response.read()
            if response.status != 200:
                raise ValueError('AA transition denied')
        finally:
            connection.close()

    def state(self, status=None):
        import native
        class OperatorTopology:
            credentials = object()
            def __init__(self):
                self.calls = []
            def authorize(self, value):
                self.calls.append(value)
        topology = OperatorTopology()
        native._control = self.controller
        try:
            native.renew_authorization(topology, None, True)
        finally:
            native._control = None
        return dict(status=status if status is not None else self.controller.step(),
                    challenge=json.loads((self.root/'challenge.json').read_text()),
                    generation=self.controller.admission.generation,
                    packetGateEnabled=topology.calls != [0])

    def dispatch(self, request):
        action = request['action']
        if action == 'clock':
            return dict(nowNs=time.clock_gettime_ns(time.CLOCK_BOOTTIME))
        if action == 'operation':
            op = request['operation']
            operation_bytes(op)
            atomic_private_write(self.root/'inbox.json', json.dumps(dict(operation=op,
                signature=request['signature'])).encode())
            status = self.controller.step()
            if op['action'] == 'REVOKE' and self.aa_revocation == 0:
                self.aa_revocation += 1
                self.aa_epoch += 1
                self.transition('revoke')
            return self.state(status)
        if action == 'aa_revoke':
            (self.root/'inbox.json').unlink(missing_ok=True)
            self.aa_revocation += 1
            self.aa_epoch += 1
            self.transition('revoke')
            # AA denial is visible at re-attestation, not instantaneously.
            self.controller.until_ns = 0
            return self.state()
        if action == 'grant':
            atomic_private_write(self.root/'inbox.json', json.dumps(dict(envelope=request['envelope'])).encode())
            return self.state(self.controller.step())
        if action == 'step':
            (self.root/'inbox.json').unlink(missing_ok=True)
            return self.state()
        if action == 'restart':
            (self.root/'inbox.json').unlink(missing_ok=True)
            self.controller = self.new_controller()
            self.aa_generation += 1
            self.aa_epoch += 1
            self.transition('authorize')
            return self.state()
        if action == 'aa_down':
            (self.root/'inbox.json').unlink(missing_ok=True)
            self.server.shutdown()
            self.server.server_close()
            self.authority.close()
            self.controller.until_ns = 0
            return self.state()
        raise ValueError('unknown action')

    def close(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
                self.authority.close()
            except Exception:
                pass
        self.temp.cleanup()


def main():
    fixture = None
    try:
        for line in sys.stdin:
            try:
                request = json.loads(line)
                if fixture is None:
                    if request.get('action') != 'init':
                        raise ValueError('initialization required')
                    fixture = Fixture(request)
                    response = fixture.state()
                else:
                    response = fixture.dispatch(request)
            except Exception as exc:
                response = {'error': type(exc).__name__}
            sys.stdout.write(json.dumps(response, separators=(',', ':')) + '\n')
            sys.stdout.flush()
    finally:
        if fixture is not None:
            fixture.close()


if __name__ == '__main__':
    main()
