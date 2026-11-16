"""CPU-only installed Linux descriptor check; no mounts or namespaces created."""
from pathlib import Path, PurePosixPath
import os
import attended_guard as guard
import admission_diagnostics as diagnostics
from cgroup_alias import AliasView

def check():
    cg=Path('/proc/self/cgroup').read_text()
    mi=Path('/proc/self/mountinfo').read_text()
    counts=guard.layout_counts(cg,mi)
    if counts['cgroup_layout_oversize'] or counts['mount_malformed'] or counts['mount_v2_records']<1:
        raise ValueError('CI structural cgroup view')
    # Exercise synthetic hybrid rejection in the installed image, without mounts.
    diagnostics.reset()
    try:
        guard.memory_observation('7:memory:/job\n0::/job',
            '31 22 0:27 / /memory ro - cgroup cgroup rw,memory',
            lambda path: (_ for _ in ()).throw(AssertionError('unexpected read')))
    except RuntimeError:
        facts=diagnostics.snapshot()
        if facts['code']!='cgroup_mapping' or facts['facts']['mount_v1_memory_records']!=1 or facts['facts']['mount_v2_records']!=0:
            raise ValueError('CI hybrid diagnostics')
    else:
        raise ValueError('CI hybrid admitted')
    diagnostics.reset()
    # Exercise installed mapper against the actual bounded CI container.
    observation=guard.memory_observation(cg,mi,lambda name:Path(name).read_text())
    if not 0<observation['effective_limit']<=2*guard.GIB:
        raise ValueError('CI container memory ceiling')
    path=PurePosixPath([line[3:] for line in cg.splitlines() if line.startswith('0::')][0])
    candidates=[]
    for line in mi.splitlines():
        left,sep,right=line.partition(' - ');fields=left.split()
        if sep and right.startswith('cgroup2 ') and len(fields)>=6:
            root,mount=map(PurePosixPath,fields[3:5])
            if path.is_relative_to(root):
                candidates.append(((mount/path.relative_to(root),mount),(fields[0],tuple(map(int,fields[2].split(':'))))))
    if not candidates:raise ValueError('CI cgroup unavailable')
    match,record=candidates[0]
    # Duplicate view exercises real Linux fds and membership, not a second mount.
    with AliasView([match,match],[record,record],cg,mi) as view:
        view.file(str(match[0]/'memory.max'))
        view.file(str(match[0]/'memory.current'))
        view.verify()
    # Real fdinfo must refuse a fabricated mount ID before control-file access.
    try:
        with AliasView([match,match],[('0',record[1])]*2,cg,mi):
            raise AssertionError('incorrect mount accepted')
    except RuntimeError:
        pass
    return True
