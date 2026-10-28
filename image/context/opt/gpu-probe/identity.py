"""Offline enrollment boundary; NOT a provider transport or ownership verifier.

Only a reviewed controller may construct Binding after durable create receipt,
account and placement verification. A nonce is binding data, not authentication.
No full-history, attestation, credential eligibility or compute admission claim.
"""
import base64
import dataclasses
import hashlib
import ipaddress
import json
import re

class Refused(ValueError):
    pass


def object_json(raw):
    def pairs(items):
        out = {}
        for k, v in items:
            if k in out:
                raise Refused('duplicate JSON key')
            out[k] = v
        return out
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(Refused('nonfinite JSON')))
        if type(value) is not dict:
            raise Refused('object required')
        return value
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise Refused('invalid JSON object') from None


def public_key(text):
    try:
        kind, encoded = text.split(' ')
        raw = base64.b64decode(encoded, validate=True)
        if (kind != 'ssh-ed25519' or len(raw) != 51 or
            raw[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20' or
            base64.b64encode(raw).decode() != encoded):
            raise ValueError()
        return text
    except (ValueError, TypeError, AttributeError):
        raise Refused('invalid canonical Ed25519 public key') from None


@dataclasses.dataclass(frozen=True)
class Binding:
    account: str
    pod: str
    request_sha256: str
    image_sha256: str
    nonce: str
    host: str
    port: int

    def __post_init__(self):
        for value in (self.account, self.pod):
            if type(value) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value):
                raise Refused('invalid account/Pod identifier')
        for value in (self.request_sha256, self.image_sha256, self.nonce):
            if type(value) is not str or not re.fullmatch('[0-9a-f]{64}', value):
                raise Refused('invalid digest or nonce')
        try:
            if str(ipaddress.ip_address(self.host)) != self.host:
                raise ValueError()
        except (ValueError, TypeError):
            raise Refused('literal canonical IP required') from None
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise Refused('invalid port')


def enrollment(chunks, *, binding, response_pod, end_reason, status=200,
               content_type='text/event-stream'):
    """Parse bounded captured bytes from a trusted exact-Pod authenticated route.

    Caller must enforce 20s wall time, TLS, no proxies/redirects/reconnects and
    distinguish its deliberate stop from EOF/transport errors. No network here.
    A deliberate stop is accepted only at a complete SSE frame boundary.
    """
    if (response_pod != binding.pod or status != 200 or
        content_type.split(';')[0].strip().lower() != 'text/event-stream'):
        raise Refused('response binding or headers invalid')
    buf = bytearray()
    for chunk in chunks:
        if type(chunk) is not bytes or len(buf) + len(chunk) > 262144:
            raise Refused('capture exceeds byte bound')
        buf.extend(chunk)
    if end_reason != 'controller_snapshot_end':
        raise Refused('unexpected stream end')
    raw = bytes(buf).replace(b'\r\n', b'\n')
    if not raw.endswith(b'\n\n') or b'\r' in raw:
        raise Refused('incomplete or invalid frame')
    frames = raw[:-2].split(b'\n\n')
    if len(frames) > 128:
        raise Refused('too many frames')
    records = []
    for frame in frames:
        if len(frame) > 8192:
            raise Refused('oversized frame')
        data = []
        for line in frame.split(b'\n'):
            if line.startswith(b'data:'):
                value = line[5:]
                data.append(value[1:] if value.startswith(b' ') else value)
            elif line.startswith((b':', b'id:', b'event:')) or not line:
                continue
            else:
                raise Refused('unexpected SSE field')
        if not data:
            continue
        entry = object_json(b'\n'.join(data))
        if (set(entry) != {'source', 'line', 'ts'} or entry['source'] != 'container' or
            type(entry['line']) is not str or type(entry['ts']) is not str):
            raise Refused('unexpected log envelope')
        # Exclusive pre-enrollment output: no arbitrary workload log accepted.
        record = object_json(entry['line'])
        expected = {'version', 'request_sha256', 'nonce', 'host_key'}
        if (set(record) != expected or type(record['version']) is not int or
            record['version'] != 1 or record['request_sha256'] != binding.request_sha256 or
            record['nonce'] != binding.nonce):
            raise Refused('identity record binding mismatch')
        records.append(public_key(record['host_key']))
    if len(records) != 1:
        raise Refused('exactly one identity record required')
    return dict(dataclasses.asdict(binding), host_key=records[0],
                capture_sha256=hashlib.sha256(bytes(buf)).hexdigest(),
                scope='host_key_enrollment_only')


def qualify(binding, capture, save_once, cleanup_owned):
    """Simulation-ready coordinator, never creates resources or admits compute.

    All callbacks are trusted controller dependencies. save_once must atomically
    persist without overwriting an existing Pod binding. cleanup_owned must use
    the existing exact-owned-resource termination fence, not a name lookup.
    """
    try:
        result = enrollment(binding=binding, **capture())
        save_once(result)
        return result
    except Exception as primary:
        try:
            cleanup_owned(binding.pod)
        except Exception:
            raise Refused('enrollment failed; cleanup unresolved') from primary
        raise Refused('enrollment failed; cleanup requested, not billing finality') from primary
