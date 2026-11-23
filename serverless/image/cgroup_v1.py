"""Conservative read-only v1 memory observation, never containment attestation.

A finite leaf hard limit is mandatory. No path guessing, writes or v2 fallback
following v1 refusal. Real Linux v1 qualification is a separate deployment gate.
"""
import os
import re
from pathlib import PurePosixPath
from cgroup_alias import AliasView, read_fd
from admission_diagnostics import mark

BOUND = 1024 * 1024
CEILING = 64 * 2**30
FILES = frozenset(('memory.limit_in_bytes', 'memory.usage_in_bytes',
                  'memory.use_hierarchy', 'memory.stat', 'cgroup.procs'))


def path(value):
    p = PurePosixPath(value)
    if (not p.is_absolute() or '..' in p.parts or '\\' in value
            or str(p) != value or '\x00' in value):
        raise RuntimeError('unsupported v1 path')
    return p


def membership(text):
    if type(text) is not str or len(text) > BOUND:
        raise RuntimeError('v1 membership bound')
    found = []
    ids = set()
    for line in text.splitlines():
        fields = line.split(':', 2)
        if len(fields) != 3 or not re.fullmatch('[0-9]+', fields[0]):
            raise RuntimeError('malformed cgroup membership')
        number = int(fields[0])
        if number in ids:
            raise RuntimeError('duplicate cgroup hierarchy')
        ids.add(number)
        controllers = fields[1].split(',') if fields[1] else []
        if (number == 0 and controllers or number != 0 and not controllers
                or len(set(controllers)) != len(controllers)
                or any(not re.fullmatch('[A-Za-z0-9_=.-]+', c) for c in controllers)):
            raise RuntimeError('malformed controllers')
        if 'memory' in controllers:
            found.append(path(fields[2]))
    if len(found) > 1:
        raise RuntimeError('ambiguous memory membership')
    return found[0] if found else None


class V1View(AliasView):
    def file(self, value):
        p = PurePosixPath(value)
        if p.name not in FILES:
            raise RuntimeError('v1 file allowlist')
        fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self.fds[str(p.parent)])
        try:
            self.verify_fd(fd, self.path_records[str(p.parent)])
            return read_fd(fd)
        finally:
            os.close(fd)


def unsigned(raw):
    if type(raw) is not str or len(raw) > 32:
        raise RuntimeError('v1 numeric bound')
    value = raw.strip()
    if not re.fullmatch('[0-9]{1,19}', value):
        raise RuntimeError('v1 numeric syntax')
    number = int(value)
    if number >= 2**63:
        raise RuntimeError('v1 numeric range')
    return number


def hierarchical(raw):
    if type(raw) is not str or len(raw) > BOUND:
        raise RuntimeError('v1 stat bound')
    seen = {}
    for line in raw.splitlines():
        f = line.split()
        if (len(f) != 2 or not re.fullmatch('[a-zA-Z0-9_]+', f[0])
                or f[0] in seen or len(seen) >= 4096):
            raise RuntimeError('v1 stat schema')
        seen[f[0]] = unsigned(f[1])
    if 'hierarchical_memory_limit' not in seen:
        raise RuntimeError('v1 hierarchy limit absent')
    return seen['hierarchical_memory_limit']


def mapping(cg, text):
    if type(text) is not str or len(text) > BOUND:
        raise RuntimeError('v1 mount bound')
    found = []
    for line in text.splitlines():
        left, sep, right = line.partition(' - ')
        fields, tail = left.split(), right.split()
        if not sep or len(tail) != 3:
            raise RuntimeError('malformed mount record')
        if tail[0] != 'cgroup' or 'memory' not in tail[2].split(','):
            continue
        if (len(fields) < 6 or not all(re.fullmatch('[0-9]+', v) for v in fields[:2])
                or not re.fullmatch('[0-9]+:[0-9]+', fields[2])):
            raise RuntimeError('malformed memory mount')
        root, mount = path(fields[3]), path(fields[4])
        if not cg.is_relative_to(root):
            raise RuntimeError('v1 membership outside mount root')
        found.append(((mount / cg.relative_to(root), mount),
                      (fields[0], tuple(int(v) for v in fields[2].split(':')))))
    # Aliases are deliberately unsupported in this first conservative lane.
    if len(found) != 1:
        raise RuntimeError('one v1 memory mount required')
    return found[0]


def observe(cgroup_text, mount_text, view_factory=V1View):
    mark('v1_mapping')
    cg = membership(cgroup_text)
    if cg is None:
        raise RuntimeError('v1 memory membership absent')
    match, record = mapping(cg, mount_text)
    observations = []
    with view_factory([match], [record], cgroup_text, mount_text) as view:
        leaf, mount = match
        node = leaf
        while True:
            mark('v1_values')
            limit = unsigned(view.file(str(node / 'memory.limit_in_bytes')))
            current = unsigned(view.file(str(node / 'memory.usage_in_bytes')))
            hierarchy = unsigned(view.file(str(node / 'memory.use_hierarchy')))
            effective = hierarchical(view.file(str(node / 'memory.stat')))
            if hierarchy != 1 or not 0 < effective <= limit or current > effective:
                raise MemoryError('v1 hierarchy or usage refusal')
            if node == leaf and not 0 < limit <= CEILING:
                raise MemoryError('finite v1 leaf ceiling <=64GiB required')
            observations.append(dict(path=str(node), limit=limit, current=current,
                                     hierarchical_limit=effective))
            if len(observations) > 256:
                raise RuntimeError('v1 ancestor bound')
            if node == mount:
                break
            node = node.parent
        for child, parent in zip(observations, observations[1:]):
            if child['hierarchical_limit'] > parent['hierarchical_limit']:
                raise MemoryError('inconsistent v1 hierarchy')
        mark('v1_stability')
        view.verify()
        for item in observations:
            node = PurePosixPath(item['path'])
            if (unsigned(view.file(str(node / 'memory.limit_in_bytes'))) != item['limit']
                    or unsigned(view.file(str(node / 'memory.use_hierarchy'))) != 1
                    or hierarchical(view.file(str(node / 'memory.stat'))) != item['hierarchical_limit']):
                raise RuntimeError('v1 limits changed')
        view.verify()
    effective = observations[0]['hierarchical_limit']
    mark('memory_ceiling', effective_limit=effective)
    return dict(effective_limit=effective, visible_ancestors=observations,
                hidden_ancestors_verified=False)
