import hashlib,json,os,re,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent

def verify_image(root=ROOT):
    m=json.loads((root/'ci/image-freeze.json').read_text())
    actual={str(f.relative_to(root/'image')) for f in (root/'image').rglob('*') if f.is_file() or f.is_symlink()}
    if actual!=set(m):raise ValueError('image source membership')
    for n,h in m.items():
        f=root/'image'/n
        if f.is_symlink() or not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest()!=h:raise ValueError('image source binding')
    return True

def admission(env):
    sha=env.get('GITHUB_SHA','')
    if not re.fullmatch('[0-9a-f]{40}',sha) or sha!=env.get('EXPECTED_SHA') or sha!=env.get('REVIEWED_SHA'):
        raise ValueError('source SHA admission')
    if env.get('GITHUB_REPOSITORY')!='m0mms/gpu-probe' or env.get('GITHUB_EVENT_NAME')!='workflow_dispatch':raise ValueError('destination/event admission')
    return sha
if __name__=='__main__':
    sha=admission(os.environ);verify_image()
    if shutil.disk_usage(os.environ['RUNNER_TEMP']).free<12*2**30:raise ValueError('disk admission')
    mem=next(int(x.split()[1])*1024 for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:'))
    if mem<4*2**30:raise ValueError('memory admission')
    print(json.dumps({'sha':sha,'memory_available':mem,'capacity_snapshot_only':True}))
