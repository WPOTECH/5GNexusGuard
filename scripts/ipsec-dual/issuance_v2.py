"""Standalone V2 signature verifier. This does NOT install a kernel packet gate."""
import base64
import re
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIELDS = ('version', 'transport', 'serviceId', 'clientNodeId', 'ownerNodeId',
          'bootId', 'nonce', 'generation', 'issuedBoottimeNs', 'deadlineBoottimeNs',
          'resource', 'issuanceId', 'issuerId')
DOMAIN = b'DEFENDERLINK-NATIVE-ISSUANCE-V2\n'
NODE_DOMAIN = b'DEFENDERLINK-NATIVE-NODE-V2\n'


def canonical(payload):
    if type(payload) is not dict or set(payload) != set(FIELDS):
        raise ValueError('invalid issuance schema')
    if type(payload['version']) is not int or payload['version'] != 2 or payload['transport'] != 'IKEV2_ESP_WIREGUARD':
        raise ValueError('invalid protocol')
    for key, pattern in (('serviceId', r'[A-Za-z0-9._-]{1,128}'),
                         ('clientNodeId', r'[0-9a-f]{64}'), ('ownerNodeId', r'[0-9a-f]{64}'),
                         ('bootId', r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
                         ('nonce', r'[0-9a-f]{32}'), ('issuanceId', r'[0-9a-f]{32}'),
                         ('issuerId', r'[0-9a-f]{64}'),
                         ('resource', r'tcp:[0-9.]{7,15}:[0-9]{1,5}')):
        if type(payload[key]) is not str or not re.fullmatch(pattern, payload[key]):
            raise ValueError('invalid identifier')
    for key in ('generation', 'issuedBoottimeNs', 'deadlineBoottimeNs'):
        if type(payload[key]) is not int or not 0 < payload[key] < 2**63:
            raise ValueError('invalid numeric field')
    if payload['issuedBoottimeNs'] >= payload['deadlineBoottimeNs'] or payload['deadlineBoottimeNs'] - payload['issuedBoottimeNs'] > 3_000_000_000:
        raise ValueError('invalid lifetime')
    return DOMAIN + ''.join(f'{key}={payload[key]}\n' for key in FIELDS).encode('ascii')


def node_message(payload_bytes, operator_signature):
    if len(operator_signature) != 64:
        raise ValueError('invalid operator signature length')
    return NODE_DOMAIN + payload_bytes + operator_signature


def verify(envelope, operator_key, node_key, scope, nonce, generation_floor, now_ns):
    """Return immutable original BOOTTIME deadline or None; no duration resampling."""
    try:
        if len(operator_key) != 32 or len(node_key) != 32 or operator_key == node_key:
            return None
        if type(envelope) is not dict or set(envelope) != {'payload', 'operatorSignature', 'nodeSignature'}:
            return None
        payload = envelope['payload']
        message = canonical(payload)
        if payload['ownerNodeId'] != node_key.hex() or payload['issuerId'] != operator_key.hex():
            return None
        if any(payload[key] != scope[key] for key in ('serviceId', 'clientNodeId', 'ownerNodeId', 'bootId', 'resource')):
            return None
        if payload['nonce'] != nonce or payload['generation'] <= generation_floor:
            return None
        if not payload['issuedBoottimeNs'] <= now_ns < payload['deadlineBoottimeNs']:
            return None
        signatures = []
        for key in ('operatorSignature', 'nodeSignature'):
            text = envelope[key]
            if type(text) is not str:
                return None
            sig = base64.b64decode(text, validate=True)
            if len(sig) != 64 or base64.b64encode(sig).decode('ascii') != text:
                return None
            signatures.append(sig)
        Ed25519PublicKey.from_public_bytes(operator_key).verify(signatures[0], message)
        Ed25519PublicKey.from_public_bytes(node_key).verify(signatures[1], node_message(message, signatures[0]))
        return payload['deadlineBoottimeNs']
    except (ValueError, KeyError, TypeError, InvalidSignature):
        return None


class ChallengeVerifier:
    def __init__(self, operator_key, node_key, scope, generation_floor):
        if len(operator_key) != 32 or len(node_key) != 32 or operator_key == node_key:
            raise ValueError('operator and node pins must be separate')
        self.operator_key, self.node_key = operator_key, node_key
        self.scope, self.generation_floor = dict(scope), generation_floor
        self.pending = None
        self.seen_issuance_ids = set()

    def challenge(self, nonce):
        if type(nonce) is not str or not re.fullmatch(r'[0-9a-f]{32}', nonce):
            raise ValueError('invalid challenge')
        self.pending = nonce

    def accept(self, envelope, now_ns):
        if self.pending is None:
            return None
        if (type(envelope) is dict and type(envelope.get('payload')) is dict
                and type(envelope['payload'].get('issuanceId')) is str
                and envelope['payload']['issuanceId'] in self.seen_issuance_ids):
            return None
        deadline = verify(envelope, self.operator_key, self.node_key, self.scope,
                          self.pending, self.generation_floor, now_ns)
        if deadline is not None:
            self.pending = None
            self.generation_floor = envelope['payload']['generation']
            self.seen_issuance_ids.add(envelope['payload']['issuanceId'])
        return deadline
