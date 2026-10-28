"""Read-only Linux cgroup-v2 measurements, not remote attestation/enforcement.

Does not infer disk/GPU limits from requested capacity or available bytes. A
trusted launcher must add identity, setup, credential and containment evidence.
The current output intentionally cannot pass verify_worker by itself.
"""
from pathlib import Path, PurePosixPath
import platform
from .protocol import Refused


def finite_limit(text):
    value=text.strip()
    if value=='max': return None
    if not value.isdecimal() or int(value)<=0: raise Refused('Invalid cgroup limit')
    return int(value)


def cpu_quota(text):
    """Cgroup bandwidth quota, not instantaneous parallelism or CPU affinity.

    Round up to millicores so reporting cannot understate the allowed rate.
    Period/burst behavior still needs profile-specific evaluation.
    """
    parts=text.split()
    if len(parts)!=2 or not parts[1].isascii() or not parts[1].isdecimal() or int(parts[1])<=0:
        raise Refused('Invalid CPU bandwidth period')
    quota=finite_limit(parts[0]);period=int(parts[1])
    return {'quota_us':quota,'period_us':period,
            'cpu_millicores':None if quota is None else (quota*1000+period-1)//period}


def measure_cgroup(cgroup_file, mountinfo_file):
    membership=[line[3:] for line in Path(cgroup_file).read_text().splitlines() if line.startswith('0::')]
    if len(membership)!=1: raise Refused('One unified cgroup membership required')
    group=PurePosixPath(membership[0])
    if not group.is_absolute() or '..' in group.parts: raise Refused('Unsafe cgroup membership')
    candidates=[]
    for line in Path(mountinfo_file).read_text().splitlines():
        fields=line.split(); separator=fields.index('-') if '-' in fields else -1
        if separator<6 or fields[separator+1]!='cgroup2': continue
        root=PurePosixPath(fields[3]); mount=Path(fields[4])
        # Escaped/multiply mounted paths require explicit support, never guessing.
        if '\\' in fields[3]+fields[4] or not root.is_absolute() or not mount.is_absolute():
            raise Refused('Unsupported cgroup mount path')
        try: relative=group.relative_to(root)
        except ValueError: continue
        candidates.append((mount,mount/str(relative)))
    if len(candidates)!=1: raise Refused('Ambiguous/missing cgroup-v2 mount')
    mount,current=candidates[0]
    paths=[]; limits={'memory_bytes':[],'pids':[],'cpu_millicores':[]}; cpu_bandwidth=[]
    while True:
        paths.append(str(current))
        for name,filename in [('memory_bytes','memory.max'),('pids','pids.max')]:
            value=finite_limit((current/filename).read_text())
            if value is not None: limits[name].append(value)
        cpu=cpu_quota((current/'cpu.max').read_text());cpu_bandwidth.append(dict(path=str(current),**cpu))
        if cpu['cpu_millicores'] is not None: limits['cpu_millicores'].append(cpu['cpu_millicores'])
        if current==mount: break
        current=current.parent
    # Visible ancestor minimum is an upper bound even if hidden host ancestors
    # are stricter. Reading a bound does not prove descendants cannot escape it.
    return {'hard_limits':{**{k:min(v) if v else None for k,v in limits.items()},
                           'disk_bytes':None,'gpu_bytes':None},
            'cgroup_paths':paths,'cpu_bandwidth':cpu_bandwidth,'process_tree_contained':None,
            'setup_complete':None,'provider_credentials_present':None,
            'qualification':'measurements_only_not_attestation'}


def probe_current():
    if platform.system()!='Linux': raise Refused('Linux worker required')
    return measure_cgroup('/proc/self/cgroup','/proc/self/mountinfo')


def verify_completion(state):
    """Mechanical success only; inspect trusted runtime state, not stdout alone."""
    if (state.get('running') is not False or state.get('oom_killed') is not False
            or type(state.get('exit_code')) is not int or state['exit_code'] != 0):
        raise Refused('Worker failed, OOM-killed, still running or unresolved')
    return {'mechanically_successful': True, 'scientific_acceptance': False}
