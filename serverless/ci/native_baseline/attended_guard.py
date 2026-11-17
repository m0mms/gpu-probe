"""One-attempt trusted-code guard; no provider admission or containment proof."""
import os
import resource
import re
import sys
from pathlib import Path, PurePosixPath
from admission_diagnostics import mark
from cgroup_alias import AliasView

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


def layout_counts(cgroup_text, mount_text):
    """Bounded structural observations only; never infer enforcement or admit v1."""
    facts = dict(cgroup_layout_oversize=0, cgroup_v1_memory_memberships=0,
                 cgroup_unified_memberships=0, cgroup_membership_malformed=0,
                 mount_records=0, mount_malformed=0, mount_v1_memory_records=0,
                 mount_v2_records=0, mount_cgroup2_tokens=0)
    if len(cgroup_text) > 1024*1024 or len(mount_text) > 1024*1024:
        facts['cgroup_layout_oversize'] = 1
        return facts
    for line in cgroup_text.splitlines():
        fields = line.split(':', 2)
        if (len(fields) != 3 or not re.fullmatch(r'[0-9]+', fields[0])
                or not fields[2].startswith('/')
                or (fields[0] == '0' and fields[1] != '')
                or (fields[0] != '0' and fields[1] == '')):
            facts['cgroup_membership_malformed'] += 1
            continue
        if fields[0] == '0':
            facts['cgroup_unified_memberships'] += 1
        elif 'memory' in fields[1].split(','):
            facts['cgroup_v1_memory_memberships'] += 1
    for line in mount_text.splitlines():
        facts['mount_records'] += 1
        # A token in malformed or unrelated text is not a verified mount type.
        if 'cgroup2' in line.split():
            facts['mount_cgroup2_tokens'] += 1
        left, sep, right = line.partition(' - ')
        fields, tail = left.split(), right.split()
        if (not sep or len(fields) < 6 or len(tail) != 3
                or not all(re.fullmatch(r'[0-9]+', x) for x in fields[:2])
                or not re.fullmatch(r'[0-9]+:[0-9]+', fields[2])
                or not all(x.startswith('/') for x in fields[3:5])):
            facts['mount_malformed'] += 1
            continue
        if tail[0] == 'cgroup2':
            facts['mount_v2_records'] += 1
        elif tail[0] == 'cgroup' and 'memory' in tail[2].split(','):
            facts['mount_v1_memory_records'] += 1
    return facts


def memory_observation(cgroup_text, mount_text, read, alias_factory=AliasView):
    """Resolve one visible cgroup2 mount; refuse ambiguity, escapes and bad reads."""
    mark('cgroup_unified', cgroup2_mount_count=0, cgroup_match_count=0, cgroup_identity_count=0)
    mark('cgroup_unified', **layout_counts(cgroup_text, mount_text))
    paths = [line[3:] for line in cgroup_text.splitlines() if line.startswith('0::')]
    if len(paths) != 1:
        raise RuntimeError('one unified cgroup required')
    mark('cgroup_path')
    cg = PurePosixPath(paths[0])
    if not cg.is_absolute() or '..' in cg.parts or '\\' in str(cg):
        raise RuntimeError('invalid cgroup path')
    matches = []
    records = []
    mount_count = 0
    if len(mount_text) > 1024*1024 or len(cgroup_text) > 1024*1024:
        raise RuntimeError("cgroup input bound")
    for line in mount_text.splitlines():
        left, sep, right = line.partition(' - ')
        fields = left.split()
        if not sep or not right.startswith('cgroup2 ') or len(fields) < 6:
            continue
        mount_count += 1
        mark('cgroup_mount', cgroup2_mount_count=mount_count)
        root, mount = map(PurePosixPath, fields[3:5])
        # Escaped mount paths are deliberately unsupported, not guessed.
        if any('\\' in str(p) or '..' in p.parts or not p.is_absolute()
               for p in (root, mount)):
            raise RuntimeError('unsupported cgroup mount')
        if cg.is_relative_to(root):
            matches.append((mount / cg.relative_to(root), mount))
            records.append((fields[0], tuple(int(x) for x in fields[2].split(':'))))
    mark('cgroup_mapping', cgroup_match_count=len(matches))
    if not matches or len(matches)>16:
        raise RuntimeError('missing or excessive cgroup mappings')
    if len(matches) == 1:
        observations = read_views(matches, read)
    else:
        with alias_factory(matches, records, cgroup_text, mount_text) as view:
            observations = read_views(matches, view.file)
            mark('cgroup_mapping')
            view.verify()
    finite = [o['limit'] for o in observations if o['limit'] is not None]
    mark('memory_ceiling', **({'effective_limit': min(finite)} if finite else {}))
    if not finite or min(finite) > 64 * GIB:
        raise MemoryError('finite visible effective ceiling <=64GiB required')
    return {'effective_limit': min(finite), 'visible_ancestors': observations,
            'hidden_ancestors_verified': False}


def read_views(matches, reader):
    observations = []
    for leaf, mount in matches:
        node = leaf
        while True:
            mark('memory_max_read')
            raw = reader(str(node / 'memory.max')).strip()
            mark('memory_max_parse')
            maximum = None if raw == 'max' else int(raw)
            mark('memory_current_read')
            current_raw = reader(str(node / 'memory.current')).strip()
            mark('memory_current_parse')
            current = int(current_raw)
            mark('memory_observation')
            if current < 0 or (maximum is not None and
                               (maximum <= 0 or current > maximum)):
                raise MemoryError('invalid cgroup memory observation')
            observations.append({'path': str(node), 'limit': maximum, 'current': current})
            if node == mount:
                break
            node = node.parent
    return observations


def validate_process(rss, threads, limits, environment):
    soft, hard = limits
    mark('process_rss', rss=rss, threads=threads, as_soft=soft, as_hard=hard)
    if not 0 <= rss <= 6 * GIB:
        raise MemoryError('sampled RSS')
    mark('process_as')
    if not 0 < soft <= hard <= 48 * GIB:
        raise MemoryError('address space')
    mark('process_threads')
    if not 1 <= threads <= 3:
        raise RuntimeError('thread count')
    mark('process_environment')
    if any(environment.get(k) != '3' for k in ENV_KEYS):
        raise RuntimeError('thread configuration')


class AttendedGuard:
    def __init__(self):
        self.peak_rss = 0
        self.last = None

    def __call__(self):
        mark('platform')
        if sys.platform != 'linux':
            raise RuntimeError('Linux required')
        read = lambda name: Path(name).read_text()
        mark('cgroup_read')
        cgroup = read('/proc/self/cgroup')
        mark('mount_read')
        mounts = read('/proc/self/mountinfo')
        memory = memory_observation(cgroup, mounts, read)
        mark('status_read')
        raw_status = read('/proc/self/status')
        mark('status_parse')
        status = dict(line.split(':', 1) for line in raw_status.splitlines() if ':' in line)
        mark('rss_parse')
        rss = int(status['VmRSS'].split()[0]) * 1024
        mark('threads_parse')
        threads = int(status['Threads'])
        mark('limits_read')
        limits = resource.getrlimit(resource.RLIMIT_AS)
        validate_process(rss, threads, limits, os.environ)
        self.peak_rss = max(self.peak_rss, rss)
        # Never return environment values or unfiltered proc data.
        self.last = dict(memory, rss=rss, threads=threads, as_limits=list(limits))
        return self.last
