"""Require visible native Linux-v2 resource controls before test payload runs."""
from pathlib import Path

def verify(values,interfaces):
    for name,limit in [('memory.max',2147483648),('memory.swap.max',0),('pids.max',256)]:
        raw=values[name].strip()
        if not raw.isdecimal() or int(raw)>limit:raise ValueError('missing/excessive '+name)
        if name!='memory.swap.max' and int(raw)==0:raise ValueError('zero '+name)
    parts=values['cpu.max'].split()
    if len(parts)!=2 or not all(v.isdecimal() for v in parts):raise ValueError('unbounded CPU')
    quota,period=map(int,parts)
    if quota<=0 or period<=0 or quota>2*period:raise ValueError('excessive CPU')
    if set(interfaces)-{'lo'}:raise ValueError('network interface present')
if __name__=='__main__':
    root=Path('/sys/fs/cgroup')
    verify({k:(root/k).read_text() for k in ('memory.max','memory.swap.max','pids.max','cpu.max')},[p.name for p in Path('/sys/class/net').iterdir()])
