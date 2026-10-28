"""Fixed capability-only stdio worker. No workload execution or file transfer.

The operator installs a reviewed immutable release and registration; none is
selected by the wire frame. Measurements are NOT attestation or admission to
compute. Missing controls remain unknown. Linux/GPU qualification is separate.
"""
import json
import os
from pathlib import Path
import stat
import sys
from .protocol import Refused, identifier, sha
from .protocol import parsed_object
from .worker_probe import probe_current

REGISTRATION = '/etc/gpu-paid-worker/registration.json'
MAX_FRAME = 64 * 1024
MAX_RESPONSE = 256 * 1024


def load_registration(path=REGISTRATION):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or
                info.st_mode & 0o022 or info.st_size>MAX_FRAME):
            raise Refused('Operator-owned registration required')
        with os.fdopen(fd,'rb',closefd=False) as stream:raw=stream.read(MAX_FRAME+1)
        if len(raw)>MAX_FRAME:raise Refused('Registration exceeds bound')
        return parsed_object(raw)
    finally:os.close(fd)


def handle(frame, registration, measure=probe_current):
    import re
    keys={'request_id','tenant','account_ref','request_hash','resource_id'}
    if type(registration) is not dict or set(registration)!=keys:
        raise Refused('Fixed registration shape required')
    for key in keys-{'request_hash'}:identifier(registration[key])
    if not re.fullmatch('[0-9a-f]{64}',str(registration['request_hash'])):
        raise Refused('Request digest required')
    if (type(frame) is not dict or set(frame)!={'protocol_version','operation','binding','payload'} or
            type(frame['protocol_version']) is not int or frame['protocol_version']!=1 or
            frame['operation']!='probe' or frame['binding']!=registration or frame['payload']!={}):
        raise Refused('Only the registered capability probe is supported')
    measured=measure()
    # Source-defined fields only; do not forward arbitrary provider/environment
    # responses or turn missing isolation observations into positive assertions.
    required={'hard_limits','cgroup_paths','cpu_bandwidth','process_tree_contained',
              'setup_complete','provider_credentials_present','qualification'}
    if type(measured) is not dict or set(measured)!=required:
        raise Refused('Unexpected capability measurement')
    if (measured['qualification']!='measurements_only_not_attestation' or
            any(measured[k] is not None for k in ('process_tree_contained','setup_complete','provider_credentials_present'))):
        raise Refused('Probe cannot assert containment or credential isolation')
    result={'binding':dict(registration),'operation':'probe','request_sha256':sha(frame),
            'result':measured,'compute_admitted':False}
    encoded=json.dumps(result,sort_keys=True,allow_nan=False).encode()+b'\n'
    if len(encoded)>MAX_RESPONSE:raise Refused('Measurement response exceeds bound')
    return encoded


def serve(input_stream, output_stream, registration, measure=probe_current):
    raw=input_stream.readline(MAX_FRAME+1)
    if len(raw)>MAX_FRAME or not raw.endswith(b'\n'):
        raise Refused('Bounded newline frame required')
    # Exactly one request per invocation. Transport EOF is required; the existing
    # client supplies a finite input file and owns the connection timeout.
    if input_stream.read(1):raise Refused('Multiple/trailing requests refused')
    output_stream.write(handle(parsed_object(raw),registration,measure))
    output_stream.flush()


def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    try:
        if args!=['--stdio-v1']:raise Refused('Fixed worker mode required')
        serve(sys.stdin.buffer,sys.stdout.buffer,load_registration())
        return 0
    except Exception:
        # Never expose registration contents, environment, paths or exceptions.
        sys.stdout.write('{"status":"refused","compute_admitted":false}\n')
        return 2


if __name__=='__main__':raise SystemExit(main())
