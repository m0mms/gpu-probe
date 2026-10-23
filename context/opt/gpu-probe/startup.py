"""Unactivated image startup candidate. Fixed creation-bound public input required.
No provider API, payload execution, key lookup, or environment-derived authority.
Controller verification of the claimed runtime Pod ID remains mandatory.
"""
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from paid_probe.protocol import parsed_object, identifier
from identity import public_key

STATE = Path('/run/gpu-bootstrap-identity')
REGISTRATION = Path('/etc/gpu-paid-worker/registration.json')
SSHD = '/etc/ssh/sshd_config_probe'
CLEAN_ENV = {'PATH':'/usr/bin:/bin', 'LANG':'C'}


def validate(value):
    if type(value) is not dict or set(value) != {'registration','nonce','authorized_public_key'}:
        raise ValueError('shape')
    reg = value['registration']
    keys = {'request_id','tenant','account_ref','request_hash','resource_id'}
    if type(reg) is not dict or set(reg) != keys:
        raise ValueError('registration')
    for key in keys - {'request_hash'}:
        identifier(reg[key])
    for value_hash in (reg['request_hash'], value['nonce']):
        if type(value_hash) is not str or not re.fullmatch('[0-9a-f]{64}',value_hash):
            raise ValueError('digest')
    public_key(value['authorized_public_key'])
    return value


def read_config():
    # Exactly two selected values; never enumerate or log the environment.
    # Provider runtime ID is a claim, not independent ownership evidence.
    from registration_input import materialize
    return validate(materialize(os.environ.get('GPU_PROBE_LAUNCH_JSON'),
                                os.environ.get('RUNPOD_POD_ID')))


def write_new(path, raw, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd,'wb') as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def start():
    if os.geteuid() != 0:
        raise ValueError('root startup required')
    cfg = read_config()
    os.umask(0o077)
    STATE.mkdir(mode=0o755, exist_ok=False)
    os.chmod(STATE,0o755) # public authorized_keys must be traversable by gpu-probe
    key = STATE/'ssh_host_ed25519_key'
    subprocess.run(['/usr/bin/ssh-keygen','-q','-t','ed25519','-N','','-C','','-f',str(key)],
                   check=True, timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=CLEAN_ENV)
    os.chmod(key,0o600)
    host_key = public_key(key.with_suffix('.pub').read_text().strip())
    # Parent directories must already be immutable root-owned image paths.
    # Public registration is readable by unprivileged forced-command worker.
    write_new(REGISTRATION, json.dumps(cfg['registration'],sort_keys=True).encode()+b'\n',0o644)
    os.chmod(REGISTRATION,0o644)
    write_new(STATE/'authorized_keys', ('restrict '+cfg['authorized_public_key']+'\n').encode(),0o644)
    os.chmod(STATE/'authorized_keys',0o644)
    subprocess.run(['/usr/sbin/sshd','-t','-f',SSHD], check=True,timeout=10,
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=CLEAN_ENV)
    print(json.dumps(dict(version=1,request_sha256=cfg['registration']['request_hash'],
                          nonce=cfg['nonce'],host_key=host_key),sort_keys=True),flush=True)
    # No inherited provider environment reaches sshd or the forced probe command.
    # This is environment minimization, NOT proof of credential absence elsewhere.
    os.execve('/usr/sbin/sshd',['/usr/sbin/sshd','-D','-f',SSHD],CLEAN_ENV)

if __name__ == '__main__':
    try:
        start()
    except Exception:
        # No exception strings, input, environment or private keys in provider logs.
        raise SystemExit(2)
