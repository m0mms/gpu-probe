"""Fail-closed single-Pod host authentication candidate; not a released API.

The isolated estate controller supplies a private local context after reconciling
an exact Pod ID. No cloud credential or SSH client private key belongs in receipts.
Only provider-authenticated public-key evidence may create a trust binding.
"""
from contextlib import contextmanager
from contextvars import ContextVar
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import shlex
import struct
import time
import threading


# Versioned management bootstrap. No credential download or scientific execution.
# A pre-existing dedicated key refuses boot rather than sharing a baked-in key.
SSHD_CONFIG = """Port 22
HostKey /etc/ssh/sky_host_ed25519
AuthorizedKeysFile /etc/ssh/sky_authorized_keys
PermitRootLogin prohibit-password
PubkeyAuthentication yes
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM no
DisableForwarding yes
AllowAgentForwarding no
AllowTcpForwarding no
AllowStreamLocalForwarding no
X11Forwarding no
PermitTunnel no
PermitTTY no
PermitUserEnvironment no
PermitUserRC no
AllowUsers root
SetEnv OMP_NUM_THREADS=3 OPENBLAS_NUM_THREADS=3
Subsystem sftp internal-sftp
"""
# Fail closed if the reviewed image lacks tools; never install at runtime.
BOOTSTRAP = (
    'set -eu; test "$(id -u)" -eq 0; '
    'test -x /usr/sbin/sshd; test -x /usr/bin/ssh-keygen; '
    'test -x /usr/bin/rsync; '
    'test ! -L /etc/ssh; test -d /etc/ssh; '
    'test ! -e /etc/ssh/sky_host_ed25519; test ! -L /etc/ssh/sky_host_ed25519; '
    'test ! -e /etc/ssh/sky_host_ed25519.pub; test ! -L /etc/ssh/sky_host_ed25519.pub; '
    'test ! -e /etc/ssh/sky_authorized_keys; test ! -L /etc/ssh/sky_authorized_keys; '
    'test ! -e /etc/ssh/sky_sshd_config; test ! -L /etc/ssh/sky_sshd_config; '
    'umask 077; '
    '/usr/bin/ssh-keygen -q -t ed25519 -N "" -f /etc/ssh/sky_host_ed25519; '
    'printf "%s" '+ shlex.quote(SSHD_CONFIG) +
    ' > /etc/ssh/sky_sshd_config; '
)

BOOTSTRAP_SHA256 = hashlib.sha256(BOOTSTRAP.encode()).hexdigest()


_controller_context = ContextVar('skypilot_host_auth_context', default=None)


@contextmanager
def use_context(path, guard):
    """Explicit isolated controller scope; never mutates process environment."""
    if not callable(guard):
        raise HostAuthError('Controller eligibility guard required')
    active = threading.Event()
    active.set()
    owner_pid = os.getpid()
    def checked_guard():
        if not active.is_set() or os.getpid() != owner_pid:
            raise HostAuthError('Controller scope closed or foreign process')
        guard()
        if not active.is_set() or os.getpid() != owner_pid:
            raise HostAuthError('Controller scope closed during authorization')
    token = _controller_context.set((path, checked_guard))
    try:
        yield
    finally:
        active.clear()
        _controller_context.reset(token)


class HostAuthError(RuntimeError):
    """Authentication is unavailable; do not fall back to unchecked SSH."""


def _reject(message):
    raise HostAuthError(message)


def _read(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            s = os.fstat(stream.fileno())
            if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid()
                    or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1):
                _reject('Unsafe authentication file')
            data = stream.read(16385)
            if len(data) > 16384:
                _reject('Oversized authentication file')
            return data
    except (OSError, ValueError):
        raise HostAuthError('Authentication file unavailable') from None


def context():
    """Read one controller-owned session; absent configuration denies access."""
    scope = _controller_context.get()
    if scope is not None:
        path, guard = scope
        guard()
    else:
        _reject('Explicit controller guard scope required')
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+', path) or '..' in path.split('/'):
        _reject('Missing or unsafe authentication context path')
    # Reject writable/symlink parent components, except sticky system /tmp.
    for parent in reversed(Path(path).parents):
        s = parent.lstat()
        if not stat.S_ISDIR(s.st_mode):
            _reject('Authentication parent is not a directory')
        if s.st_uid not in (0, os.getuid()):
            _reject('Foreign-owned authentication parent')
        if s.st_mode & 0o022 and not (s.st_uid == 0 and s.st_mode & stat.S_ISVTX):
            _reject('Writable authentication parent')
    parent = Path(path).parent
    s = parent.stat()
    if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
        _reject('Session directory must be private')
    try:
        c = json.loads(_read(path))
        required = {'account', 'tenant', 'session', 'pod_id', 'cluster',
                    'ip', 'port', 'expires_at', 'bootstrap_sha256', 'client_key'}
        if not isinstance(c, dict) or set(c) != required:
            _reject('Invalid authentication context schema')
        for name in ('account', 'tenant', 'session', 'pod_id', 'cluster'):
            if not isinstance(c[name], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', c[name]):
                _reject('Invalid identity')
        ipaddress.ip_address(c['ip'])
        if type(c['port']) is not int or not 1 <= c['port'] <= 65535:
            _reject('Invalid port')
        if type(c['expires_at']) not in (int, float) or not time.time() < c['expires_at'] < float('inf'):
            _reject('Expired authentication context')
        if c['bootstrap_sha256'] != BOOTSTRAP_SHA256:
            _reject('Missing bootstrap binding')
        if c['client_key'] != str(parent / 'client_key'):
            _reject('Unsafe client key path')
    except (ValueError, TypeError, KeyError):
        raise HostAuthError('Malformed authentication context') from None
    _read(parent / 'client_key')  # Private session key, never an ambient identity.
    return c, parent


def _identity(c):
    return hashlib.sha256(json.dumps(c, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def parse_key(response):
    """Accept exactly one complete Ed25519 public key; never log raw output."""
    if (not isinstance(response, dict) or type(response.get('exitCode')) is not int
            or response['exitCode'] != 0 or response.get('timedOut') is not False
            or response.get('truncated') is not False or response.get('stderr') != ''):
        _reject('Provider key command did not complete cleanly')
    value = response.get('stdout')
    if not isinstance(value, str) or len(value) > 256:
        _reject('Invalid host key output')
    value = value.removesuffix('\n')
    if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/]+={0,2}', value):
        _reject('Invalid host key syntax')
    encoded = value.split(' ')[1]
    try:
        blob = base64.b64decode(encoded, validate=True)
    except ValueError:
        raise HostAuthError('Invalid host key encoding') from None
    if (len(blob) != 51 or blob[:19] != struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32)
            or base64.b64encode(blob).decode() != encoded):
        _reject('Invalid Ed25519 wire key')
    return value


def _create_or_check(path, data):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if _read(path) != data:
            _reject('Authentication binding changed')
        return
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def enroll(cluster, instances, fetch):
    """Gate get_cluster_info before any management connection.

    fetch is the existing provider transport, supplied by the Runpod module.
    The externally reconciled context must already name exactly one owned Pod.
    """
    c, root = context()
    if cluster != c['cluster'] or set(instances) != {c['pod_id']}:
        _reject('Unexpected cluster or Pod set')
    inst = instances[c['pod_id']]
    if inst.get('external_ip') != c['ip'] or inst.get('ssh_port') != c['port']:
        _reject('Provider endpoint differs from owned session')
    try:
        response = fetch('POST', '/pods/' + c['pod_id'] + '/exec', json={
            'command': ['/usr/bin/ssh-keygen', '-y', '-f', '/etc/ssh/sky_host_ed25519'],
            'timeoutSeconds': 5})
    except Exception:
        raise HostAuthError('Provider host-key acquisition failed') from None
    key = parse_key(response)
    alias = 'sky-pod-' + _identity(c)
    record = {'context_sha256': _identity(c), 'alias': alias, 'public_key': key}
    # Receipt first: an interruption cannot authorize a changed key on retry.
    _create_or_check(root / 'host-key.json', json.dumps(record, sort_keys=True).encode())
    _create_or_check(root / 'known_hosts', f'{alias} {key}\n'.encode())


def options(ip, port, client_key, user):
    """OpenSSH options shared by readiness, commands, rsync and forwarding."""
    c, root = context()
    if (ip, port, client_key, user) != (c['ip'], c['port'], c['client_key'], 'root'):
        _reject('SSH destination or client identity mismatch')
    try:
        r = json.loads(_read(root / 'host-key.json'))
        if set(r) != {'context_sha256', 'alias', 'public_key'}:
            _reject('Invalid host-key receipt')
        if r['context_sha256'] != _identity(c) or r['alias'] != 'sky-pod-' + _identity(c):
            _reject('Stale host-key receipt')
        key = parse_key({'stdout': r['public_key'], 'stderr': '', 'exitCode': 0,
                         'timedOut': False, 'truncated': False})
        if _read(root / 'known_hosts') != f"{r['alias']} {key}\n".encode():
            _reject('Known-hosts binding mismatch')
    except (ValueError, TypeError, KeyError):
        raise HostAuthError('Malformed host-key receipt') from None
    return {
        'StrictHostKeyChecking': 'yes', 'UserKnownHostsFile': str(root / 'known_hosts'),
        'GlobalKnownHostsFile': '/dev/null', 'HostKeyAlias': r['alias'],
        'HostKeyAlgorithms': 'ssh-ed25519', 'UpdateHostKeys': 'no',
        'VerifyHostKeyDNS': 'no', 'ForwardAgent': 'no', 'IdentityAgent': 'none',
        'IdentitiesOnly': 'yes', 'BatchMode': 'yes', 'PasswordAuthentication': 'no',
        'KbdInteractiveAuthentication': 'no', 'AddKeysToAgent': 'no',
        'ControlMaster': 'no', 'ControlPath': 'none', 'ControlPersist': 'no',
        'ProxyCommand': 'none', 'ProxyJump': 'none'}


def management_bootstrap(public_key):
    """Render a single bound public key; never interpolate arbitrary shell input."""
    if type(public_key) is not str:
        raise HostAuthError('Client public key required')
    key = parse_key(dict(stdout=public_key + '\n', stderr='', exitCode=0,
                         timedOut=False, truncated=False))
    return (BOOTSTRAP + 'printf "%s\\n" ' + shlex.quote(key) +
            ' > /etc/ssh/sky_authorized_keys; '
            'mkdir -p /run/sshd; '
            '/usr/sbin/sshd -t -f /etc/ssh/sky_sshd_config; '
            'exec /usr/sbin/sshd -D -e -f /etc/ssh/sky_sshd_config')
