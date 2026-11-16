"""One-attempt trusted-code guard; no provider admission or containment proof."""
import os
import resource
import sys
from pathlib import Path, PurePosixPath

GIB = 2**30
ENV_KEYS = ('OPENBLAS_NUM_THREADS', 'OMP_NUM_THREADS', 'MKL_NUM_THREADS',
            'VECLIB_MAXIMUM_THREADS')


def establish():
    if sys.platform != 'linux':
        raise RuntimeError('Linux required')
    # Before importing NumPy/CUDA. Never raise an existing lower hard limit.
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)
    ceiling = 48 * GIB if hard == resource.RLIM_INFINITY else min(hard, 48 * GIB)
    resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))
    for key in ENV_KEYS:
        os.environ[key] = '3'


def memory_observation(cgroup_text, mount_text, read):
    """Resolve one visible cgroup2 mount; refuse ambiguity, escapes and bad reads."""
    paths = [line[3:] for line in cgroup_text.splitlines() if line.startswith('0::')]
    if len(paths) != 1:
        raise RuntimeError('one unified cgroup required')
    cg = PurePosixPath(paths[0])
    if not cg.is_absolute() or '..' in cg.parts or '\\' in str(cg):
        raise RuntimeError('invalid cgroup path')
    matches = []
    for line in mount_text.splitlines():
        left, sep, right = line.partition(' - ')
        fields = left.split()
        if not sep or not right.startswith('cgroup2 ') or len(fields) < 6:
            continue
        root, mount = map(PurePosixPath, fields[3:5])
        # Escaped mount paths are deliberately unsupported, not guessed.
        if any('\\' in str(p) or '..' in p.parts or not p.is_absolute()
               for p in (root, mount)):
            raise RuntimeError('unsupported cgroup mount')
        if cg.is_relative_to(root):
            matches.append((mount / cg.relative_to(root), mount))
    if len(matches) != 1:
        raise RuntimeError('ambiguous or hidden cgroup mapping')
    leaf, mount = matches[0]
    observations = []
    node = leaf
    while True:
        raw = read(str(node / 'memory.max')).strip()
        maximum = None if raw == 'max' else int(raw)
        current = int(read(str(node / 'memory.current')).strip())
        if current < 0 or (maximum is not None and
                           (maximum <= 0 or current > maximum)):
            raise MemoryError('invalid cgroup memory observation')
        observations.append({'path': str(node), 'limit': maximum, 'current': current})
        if node == mount:
            break
        node = node.parent
    finite = [o['limit'] for o in observations if o['limit'] is not None]
    if not finite or min(finite) > 64 * GIB:
        raise MemoryError('finite visible effective ceiling <=64GiB required')
    return {'effective_limit': min(finite), 'visible_ancestors': observations,
            'hidden_ancestors_verified': False}


def validate_process(rss, threads, limits, environment):
    soft, hard = limits
    if not 0 <= rss <= 6 * GIB:
        raise MemoryError('sampled RSS')
    if not 0 < soft <= hard <= 48 * GIB:
        raise MemoryError('address space')
    if not 1 <= threads <= 3:
        raise RuntimeError('thread count')
    if any(environment.get(k) != '3' for k in ENV_KEYS):
        raise RuntimeError('thread configuration')


class AttendedGuard:
    def __init__(self):
        self.peak_rss = 0
        self.last = None

    def __call__(self):
        if sys.platform != 'linux':
            raise RuntimeError('Linux required')
        read = lambda name: Path(name).read_text()
        memory = memory_observation(read('/proc/self/cgroup'),
                                    read('/proc/self/mountinfo'), read)
        status = dict(line.split(':', 1) for line in
                      read('/proc/self/status').splitlines() if ':' in line)
        rss = int(status['VmRSS'].split()[0]) * 1024
        threads = int(status['Threads'])
        limits = resource.getrlimit(resource.RLIMIT_AS)
        validate_process(rss, threads, limits, os.environ)
        self.peak_rss = max(self.peak_rss, rss)
        # Never return environment values or unfiltered proc data.
        self.last = dict(memory, rss=rss, threads=threads, as_limits=list(limits))
        return self.last
