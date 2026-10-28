"""Finite disk sampling for a disposable Linux job; not a Docker disk quota."""
import json
import os
from pathlib import Path
import shutil
import sys
import time
from bounded import run


def write(root, value):
    target = root/'resources.json'
    temporary = root/'resources.tmp'
    temporary.write_text(json.dumps(value, indent=2)+'\n')
    temporary.replace(target)


def sample(paths):
    return {p: shutil.disk_usage(p).free for p in paths}


def monitor(root):
    root.mkdir(parents=True, exist_ok=True)
    if (root/'resources.json').exists() or (root/'stop-resources').exists():
        raise ValueError('prior sampler state; no retry')
    code, out, err = run(['docker', 'info', '--format', '{{.DockerRootDir}}'], timeout=10)
    docker_root = out.decode().strip()
    if code or not Path(docker_root).is_absolute() or not Path(docker_root).is_dir():
        raise ValueError('Docker data directory unavailable')
    paths = [str(root.resolve()), docker_root]
    if Path('/var/lib/containerd').is_dir():
        paths.append('/var/lib/containerd')
    initial = sample(paths)
    if min(initial.values()) < 12 * 1024**3:
        raise ValueError('less than 12 GiB initial free disk')
    state = {'initial_free': initial, 'minimum_sampled_free': dict(initial), 'samples': 0,
             'healthy': True, 'complete': False, 'hard_disk_quota': False}
    begin = time.monotonic()
    try:
        while True:
            current = sample(paths)
            state['samples'] += 1
            for path, free in current.items():
                state['minimum_sampled_free'][path] = min(state['minimum_sampled_free'][path], free)
                if free < 4*1024**3 or initial[path]-free > 8*1024**3:
                    state['healthy'] = False
            state['elapsed_seconds'] = round(time.monotonic()-begin, 2)
            state['sampled_at'] = time.time()
            state['maximum_sampled_consumption'] = {
                path: initial[path]-state['minimum_sampled_free'][path] for path in paths}
            if (root/'stop-resources').exists():
                state['complete'] = True
            if time.monotonic()-begin > 1500:
                state['healthy'] = False
                state['complete'] = True
                state['reason'] = 'sampler finite deadline reached'
            write(root, state)
            if state['complete']:
                return
            time.sleep(1)
    except BaseException:
        state['healthy'] = False
        state['complete'] = True
        state['reason'] = 'sampler failed'
        write(root, state)
        raise


def validate(state, *, complete=False):
    if state.get('healthy') is not True or state.get('samples', 0) < 1:
        raise ValueError('resource observation unhealthy')
    age = time.time()-state.get('sampled_at', 0)
    if not 0 <= age <= 10:
        raise ValueError('stale resource observation')
    if complete and state.get('complete') is not True:
        raise ValueError('sampler did not stop')


if __name__ == '__main__':
    root = Path(os.environ['EVIDENCE_DIR'])
    if sys.argv[1] == 'monitor':
        monitor(root)
    elif sys.argv[1] == 'check':
        validate(json.loads((root/'resources.json').read_text()))
    elif sys.argv[1] == 'stop':
        (root/'stop-resources').touch()
        try:
            for _ in range(30):
                path = root/'resources.json'
                state = json.loads(path.read_text()) if path.exists() else {}
                if state.get('complete'):
                    validate(state, complete=True)
                    break
                time.sleep(.2)
            else:
                raise ValueError('sampler completion unconfirmed')
        finally:
            (root/'stop-resources').unlink(missing_ok=True)
    else:
        raise ValueError('unknown sampler operation')
