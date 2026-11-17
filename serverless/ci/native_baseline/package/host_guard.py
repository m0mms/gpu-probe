"""Read-only tenant guard. Registered estate worker must create/enforce limits.
No cgroup changes, permission changes, timers, process termination or installation.
"""
import os,resource,sys
from pathlib import Path
RSS=6*2**30;HARD=8*2**30;AS=48*2**30;THREADS=3

def validate(s):
 if s['memory_max']<=0 or s['memory_max']>HARD:raise MemoryError('finite cgroup hard limit required')
 if s['memory_current']<0 or s['memory_current']>s['memory_max']:raise MemoryError('cgroup usage')
 if s['rss']<0 or s['rss']>RSS:raise MemoryError('sampled RSS')
 if not (0<s['as_soft']<=s['as_hard']<=AS):raise MemoryError('address-space limits')
 if s['threads']<1 or s['threads']>THREADS:raise RuntimeError('host thread count')
 if any(s['env'].get(k)!='3' for k in ['OPENBLAS_NUM_THREADS','OMP_NUM_THREADS','MKL_NUM_THREADS','VECLIB_MAXIMUM_THREADS']):raise RuntimeError('numerical thread environment')
 return s

def snapshot():
 if sys.platform!='linux':raise RuntimeError('Linux registered cgroup worker required')
 lines=Path('/proc/self/cgroup').read_text().splitlines();paths=[s.split(':',2)[2] for s in lines if s.startswith('0::')]
 if len(paths)!=1:raise RuntimeError('unified cgroup required')
 root=(Path('/sys/fs/cgroup')/paths[0].lstrip('/')).resolve()
 if not root.is_relative_to('/sys/fs/cgroup'):raise RuntimeError('cgroup path')
 status={k:v.strip() for k,v in (line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)}
 soft,hard=resource.getrlimit(resource.RLIMIT_AS)
 return dict(memory_max=int((root/'memory.max').read_text()),memory_current=int((root/'memory.current').read_text()),rss=int(status['VmRSS'].split()[0])*1024,threads=int(status['Threads']),as_soft=soft,as_hard=hard,env=dict(os.environ),cgroup=str(root))

class HostGuard:
 def __init__(self):self.peak_rss=0;self.peak_cgroup=0
 def __call__(self):
  s=validate(snapshot());self.peak_rss=max(self.peak_rss,s['rss']);self.peak_cgroup=max(self.peak_cgroup,s['memory_current']);return s
