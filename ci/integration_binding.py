"""Observe actual BuildKit constraints and bind the loaded local image ID."""
import json
import os
from pathlib import Path
import re
import sys
from bounded import run
from identity import digest


def builder_limits(obj):
    host = obj['HostConfig']
    if host.get('Memory') != 4*1024**3 or host.get('MemorySwap') != 4*1024**3:
        raise ValueError('BuildKit memory limits differ')
    if host.get('CpuPeriod') != 100000 or host.get('CpuQuota') != 200000:
        raise ValueError('BuildKit CPU limits differ')
    if obj.get('State', {}).get('Running') is not True:
        raise ValueError('BuildKit not running')
    return {k: host.get(k) for k in ('Memory','MemorySwap','CpuPeriod','CpuQuota','Privileged')}


def inspect(kind, target):
    code, out, err = run(['docker', kind, 'inspect', target], timeout=15)
    if code:
        raise ValueError('Docker inspection failed')
    values = json.loads(out)
    if len(values) != 1:
        raise ValueError('ambiguous Docker inspection')
    return values[0]


if __name__ == '__main__':
    root = Path(os.environ['EVIDENCE_DIR'])
    root.mkdir(parents=True, exist_ok=True)
    if sys.argv[1] == 'builder':
        nodes = json.loads(os.environ['BUILDER_NODES'])
        if len(nodes) != 1 or not re.fullmatch('[a-zA-Z0-9_-]{1,100}', nodes[0]['name']):
            raise ValueError('unexpected builder nodes')
        # Buildx docker-container naming convention is checked, never guessed around on failure.
        name = 'buildx_buildkit_'+nodes[0]['name']
        obj = inspect('container', name)
        record = {'name': name, 'id': obj['Id'], 'image_id': obj['Image'],
                  'observed_limits': builder_limits(obj),
                  'scope': 'BuildKit container only; Docker daemon not bounded by these limits'}
        (root/'builder.json').write_text(json.dumps(record, indent=2)+'\n')
    elif sys.argv[1] == 'image':
        image_id = digest(os.environ['BUILT_IMAGE_ID'])
        obj = inspect('image', image_id)
        if obj['Id'] != image_id or obj['Os'] != 'linux' or obj['Architecture'] != 'amd64':
            raise ValueError('local build identity/platform differs')
        (root/'local-build.json').write_text(json.dumps({'source_sha': os.environ['GITHUB_SHA'],
            'image_id': image_id, 'kind': 'local Docker config identity, not registry digest',
            'registry_qualified': False}, indent=2)+'\n')
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('image='+image_id+'\n')
    else:
        raise ValueError('unknown binding operation')
