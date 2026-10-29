"""Validate the reviewed handoff; never accept caller-provided image references."""
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from bounded import run
from identity import REPOSITORY, IMAGE, digest


def verify_run(record, run_id, sha, workflow):
    expected = {'id': int(run_id), 'head_sha': sha, 'event': 'workflow_dispatch',
                'status': 'completed', 'conclusion': 'success', 'run_attempt': 1,
                'path': '.github/workflows/' + workflow}
    if any(record.get(k) != v for k, v in expected.items()):
        raise ValueError('source run mismatch')
    if record.get('repository', {}).get('id') != 1430654983:
        raise ValueError('repository mismatch')
    if workflow == 'worker-security.yml':
        end = datetime.fromisoformat(record['updated_at'].replace('Z', '+00:00'))
        if not 0 <= (datetime.now(timezone.utc)-end).total_seconds() <= 86400:
            raise ValueError('security run expired')


def api_run(run_id):
    if not re.fullmatch('[1-9][0-9]*', run_id):
        raise ValueError('invalid source run')
    code, out, err = run(['gh', 'api', 'repos/'+REPOSITORY+'/actions/runs/'+run_id], cap=1024**2)
    if code:
        raise ValueError('cannot verify source run')
    return json.loads(out)


def validate_receipt(raw, expected_hash, run_id, sha):
    if len(raw) > 65536 or not re.fullmatch('[0-9a-f]{64}', expected_hash):
        raise ValueError('receipt bounds')
    if hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError('receipt hash mismatch')
    x = json.loads(raw)
    if x.get('repository') != REPOSITORY or x.get('source_sha') != sha or x.get('run_id') != run_id or x.get('attempt') != 1:
        raise ValueError('receipt identity mismatch')
    if x.get('tag') != IMAGE+':candidate-'+sha+'-'+run_id+'-1':
        raise ValueError('candidate tag mismatch')
    return digest(x['digest'])


if __name__ == '__main__':
    mode = os.environ['RECEIPT_MODE']
    if mode == 'write':
        x = {'repository': REPOSITORY, 'source_sha': os.environ['GITHUB_SHA'],
             'run_id': os.environ['GITHUB_RUN_ID'], 'attempt': 1,
             'tag': os.environ['CANDIDATE_TAG'], 'digest': digest(os.environ['CANDIDATE_DIGEST'])}
        folder = Path('release-evidence'); folder.mkdir(exist_ok=True)
        (folder/'receipt.json').write_text(json.dumps(x, sort_keys=True, indent=2)+'\n')
    else:
        run_id = os.environ['SOURCE_RUN_ID']; sha = os.environ['EXPECTED_SHA']
        if not re.fullmatch('[0-9a-f]{40}', sha):
            raise ValueError('invalid commit')
        workflow = 'worker-security.yml' if mode == 'security' else 'worker-release.yml'
        verify_run(api_run(run_id), run_id, sha, workflow)
        if mode == 'metadata':
            code, out, err = run(['gh', 'api', 'repos/'+REPOSITORY+'/actions/runs/'+run_id+'/artifacts'], cap=1024**2)
            if code:
                raise ValueError('cannot read receipt inventory')
            records = json.loads(out)
            if records.get('total_count') != 1:
                raise ValueError('unexpected publication artifact inventory')
            a = records['artifacts'][0]
            if a.get('name') != 'release-receipt-'+run_id+'-1' or a.get('expired') or not 0 < a.get('size_in_bytes',0) <= 65536:
                raise ValueError('receipt artifact bounds or identity')
        elif mode == 'qualify':
            value = validate_receipt(Path('release-receipt/receipt.json').read_bytes(),
                                     os.environ['RECEIPT_SHA256'], run_id, sha)
            with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
                f.write('digest='+value+'\n')
        elif mode != 'security':
            raise ValueError('unknown receipt mode')
