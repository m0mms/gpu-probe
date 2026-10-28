"""Bind registry descriptors and release job outputs; image IDs are not manifests."""
import hashlib
import json
import re

REPOSITORY = 'm0mms/gpu-probe'
IMAGE = 'ghcr.io/' + REPOSITORY


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', value):
        raise ValueError('invalid digest')
    return value


def verify_bytes(raw, expected):
    if 'sha256:' + hashlib.sha256(raw).hexdigest() != digest(expected):
        raise ValueError('manifest digest mismatch')
    return json.loads(raw)


def platform_descriptor(index):
    entries = index.get('manifests')
    if not isinstance(entries, list):
        raise ValueError('expected attested image index')
    matches = [d for d in entries if d.get('platform') == {'architecture': 'amd64', 'os': 'linux'}]
    if len(matches) != 1:
        raise ValueError('ambiguous linux/amd64 descriptor')
    item = matches[0]
    digest(item['digest'])
    if type(item.get('size')) is not int or not 0 < item['size'] <= 1024 * 1024:
        raise ValueError('invalid descriptor size')
    return item


def release_context(env):
    sha = env.get('EXPECTED_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', sha) or env.get('GITHUB_SHA') != sha:
        raise ValueError('source commit mismatch')
    for key, value in {'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REPOSITORY_ID': '1430654983',
                       'GITHUB_REPOSITORY_OWNER_ID': '474625', 'GITHUB_REF': 'refs/heads/main',
                       'GITHUB_EVENT_NAME': 'workflow_dispatch', 'RUNNER_ENVIRONMENT': 'github-hosted'}.items():
        if env.get(key) != value:
            raise ValueError('release context mismatch: ' + key)
    for key in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'):
        if not re.fullmatch('[1-9][0-9]*', env.get(key, '')):
            raise ValueError('invalid run identity')
    if env['GITHUB_RUN_ATTEMPT'] != '1':
        raise ValueError('rerun requires reconciled new dispatch')
    return IMAGE + ':candidate-' + sha + '-' + env['GITHUB_RUN_ID'] + '-1'


def qualification_reference(value, mode='registry'):
    if mode == 'local-build':
        return digest(value)  # Docker config/image ID, never a registry manifest claim.
    if mode != 'registry' or not value.startswith(IMAGE+'@'):
        raise ValueError('unexpected qualification image or mode')
    digest(value.split('@',1)[1])
    return value
