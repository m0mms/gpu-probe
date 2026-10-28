"""One intentional failure after owned resources exist; unexpected failures do not pass."""
import json
import os
from pathlib import Path
import sys
from bounded import run


def accepted(code, result):
    return (code == 1 and result.get('passed') is False and
            result.get('cleanup_passed') is True and result.get('forced_failure_reached') is True)


if __name__ == '__main__':
    root = Path(os.environ['EVIDENCE_DIR'])/'failure-control'
    env = dict(os.environ, EVIDENCE_DIR=str(root), QUALIFICATION_FORCE_FAILURE='1')
    code, out, err = run([sys.executable, str(Path(__file__).with_name('qualify.py'))],
                         env=env, timeout=560, cap=1024*1024)
    result = json.loads((root/'result.json').read_text())
    if not accepted(code, result):
        raise ValueError('cleanup control did not reach expected failure and confirmed cleanup')
    (root/'control.json').write_text(json.dumps({'expected_failure_observed': True,
        'cleanup_verified': True, 'returncode': code})+'\n')
