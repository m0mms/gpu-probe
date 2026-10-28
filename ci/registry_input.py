"""Anonymous image retrieval; credentials are kept out of this subprocess tree."""
import json
import os
from pathlib import Path
import shutil
import tempfile
from bounded import run
from identity import IMAGE, digest, verify_bytes, platform_descriptor


def main():
    top = digest(os.environ['CANDIDATE_DIGEST'])
    evidence = Path(os.environ['EVIDENCE_DIR'])
    evidence.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(evidence).free < 4 * 1024**3:
        raise ValueError('insufficient retrieval disk')
    with tempfile.TemporaryDirectory(prefix='anonymous-docker-') as config:
        env = {'PATH': os.environ['PATH'], 'HOME': config, 'DOCKER_CONFIG': config, 'LANG': 'C'}
        def command(args):
            code, out, err = run(args, env=env, timeout=180)
            if code:
                (evidence/'anonymous-failure.json').write_text(json.dumps({'code': code, 'stderr': err.decode(errors='replace')}))
                raise ValueError('anonymous registry retrieval failed')
            return out
        # Docker's default daemon driver provides buildx; fail if unavailable, never install ad hoc.
        raw = command(['docker', 'buildx', 'imagetools', 'inspect', '--raw', IMAGE+'@'+top])
        index = verify_bytes(raw, top)
        descriptor = platform_descriptor(index)
        platform = descriptor['digest']
        raw_platform = command(['docker', 'buildx', 'imagetools', 'inspect', '--raw', IMAGE+'@'+platform])
        if len(raw_platform) != descriptor['size']:
            raise ValueError('platform descriptor size mismatch')
        manifest = verify_bytes(raw_platform, platform)
        blobs = [manifest['config'], *manifest['layers']]
        for blob in blobs:
            digest(blob['digest'])
            if type(blob['size']) is not int or not 0 < blob['size'] <= 512 * 1024**2:
                raise ValueError('blob size invalid')
            if blob.get('urls'):
                raise ValueError('external layer URL not permitted')
        if sum(b['size'] for b in blobs) > 512 * 1024**2:
            raise ValueError('image transfer budget')
        # The container client verifies the complete runtime config/layer digest closure.
        command(['docker', 'pull', '--platform', 'linux/amd64', IMAGE+'@'+platform])
        (evidence/'registry.json').write_text(json.dumps({'anonymous': True, 'index_digest': top,
            'platform_digest': platform, 'manifest': manifest,
            'scope': 'runtime config and layers retrieved by Docker; attestations verified separately'}, indent=2)+'\n')
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.write('image='+IMAGE+'@'+platform+'\n')


if __name__ == '__main__':
    main()
