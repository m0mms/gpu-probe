"""Authenticate signed provenance with bounded output; do not print credentials."""
import os
import re
from pathlib import Path
from bounded import run
from identity import digest, IMAGE, REPOSITORY


if __name__ == '__main__':
    sha = os.environ['EXPECTED_SHA']
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('invalid expected commit')
    subject = IMAGE+'@'+digest(os.environ['CANDIDATE_DIGEST'])
    args = ['gh', 'attestation', 'verify', 'oci://'+subject, '--repo', REPOSITORY,
            '--signer-workflow', REPOSITORY+'/.github/workflows/worker-release.yml',
            '--source-digest', sha, '--signer-digest', sha, '--source-ref', 'refs/heads/main',
            '--deny-self-hosted-runners', '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
            '--format', 'json']
    code, out, err = run(args, timeout=120, cap=4*1024**2)
    if code:
        raise ValueError('attestation verification failed; no qualification')
    (Path(os.environ['EVIDENCE_DIR'])/'attestation.json').write_bytes(out)
