"""Check actual Docker-save client handling of RLIMIT_FSIZE after a successful baseline."""
import json
import os
from pathlib import Path
import tempfile
from bounded import run
from identity import qualification_reference


def accepted(code, error, sizes):
    # Expected Linux client EFBIG error, not an arbitrary failed save.
    return code != 0 and b'file too large' in error.lower() and all(s <= 65536 for s in sizes)


if __name__ == '__main__':
    root = Path(os.environ['EVIDENCE_DIR'])
    baseline = json.loads((root/'suite/result.json').read_text())
    image = qualification_reference(os.environ['QUALIFY_IMAGE'], 'local-build')
    if baseline.get('passed') is not True or baseline.get('cleanup_passed') is not True or baseline.get('image_reference') != image:
        raise ValueError('no successful normal-save baseline for this image')
    with tempfile.TemporaryDirectory(prefix='save-limit-control-') as directory:
        env = {k:v for k,v in os.environ.items() if k in ('PATH','HOME','DOCKER_CONFIG')}
        env['LANG']='C'
        code, out, err = run(['docker','image','save','--output',str(Path(directory)/'image.tar'),image],
                             env=env, timeout=60, cap=65536, file_cap=65536)
        sizes = [p.stat().st_size for p in Path(directory).iterdir() if p.is_file()]
        result = {'passed': accepted(code,err,sizes), 'returncode':code,'residual_file_sizes':sizes,
                  'scope':'Linux Docker-save client; not daemon layer expansion',
                  'expected_efbig':b'file too large' in err.lower(),
                  'stderr':err.decode(errors='replace').replace(directory,'<control>')}
        (root/'save-limit-control.json').write_text(json.dumps(result,indent=2)+'\n')
        if not result['passed']:
            raise ValueError('Docker-save limit control inconclusive; no changed-message retry')
