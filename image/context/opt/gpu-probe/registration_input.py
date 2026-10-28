"""Pure candidate decoder; not wired to startup or a provider transport.

Receives only explicit public launch text and provider Pod ID. Reading the whole
process environment, credentials, API calls and file writes are out of scope.
Output is a claimed binding: controller must independently verify ownership.
"""
import json
from paid_probe.protocol import parsed_object, identifier
from identity import public_key
import re


def materialize(launch_text, provider_pod_id):
    if type(launch_text) is not str or len(launch_text.encode('utf-8')) > 8192:
        raise ValueError('bounded launch text required')
    launch = parsed_object(launch_text)
    if set(launch) != {'version','registration','nonce','authorized_public_key'} or type(launch['version']) is not int or launch['version'] != 1:
        raise ValueError('launch schema mismatch')
    reg = launch['registration']
    if type(reg) is not dict or set(reg) != {'request_id','tenant','account_ref','request_hash'}:
        raise ValueError('pre-create registration schema mismatch')
    for key in ('request_id','tenant','account_ref'):
        identifier(reg[key])
    for value in (reg['request_hash'],launch['nonce']):
        if type(value) is not str or not re.fullmatch('[0-9a-f]{64}',value):
            raise ValueError('digest or nonce invalid')
    public_key(launch['authorized_public_key'])
    identifier(provider_pod_id)
    return dict(registration=dict(reg,resource_id=provider_pod_id),
                nonce=launch['nonce'],authorized_public_key=launch['authorized_public_key'])
