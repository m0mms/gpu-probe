"""Bounded visible filesystem inventory. Runs only inside an isolated CI container."""
import ctypes,json,os,stat,subprocess,sys,sysconfig
from pathlib import Path
MAX_ENTRIES=100000
MAX_JSON=12*1024*1024
EXCLUDED={'/proc','/sys','/dev','/tmp','/checks','/etc/hosts','/etc/hostname','/etc/resolv.conf'}
ZLIB='1:1.3.dfsg+really1.3.1-1+deb13u1'

def capabilities(f):
    attrs=os.listxattr(f,follow_symlinks=False)
    return os.getxattr(f,'security.capability',follow_symlinks=False).hex() if 'security.capability' in attrs else None

def inventory(root=Path('/'),excluded=EXCLUDED,limit=MAX_ENTRIES):
    rows=[];stack=[root]
    while stack:
        directory=stack.pop()
        with os.scandir(directory) as entries:
            children=sorted(entries,key=lambda x:x.name)
        for entry in children:
            f=Path(entry.path);name='/'+str(f.relative_to(root))
            if name in excluded:continue
            s=entry.stat(follow_symlinks=False)
            item={'path':name,'mode':stat.S_IMODE(s.st_mode),'uid':s.st_uid,'gid':s.st_gid,'size':s.st_size}
            if stat.S_ISLNK(s.st_mode):item.update(kind='symlink',target=os.readlink(f))
            elif stat.S_ISDIR(s.st_mode):item['kind']='directory';stack.append(f)
            elif stat.S_ISREG(s.st_mode):item['kind']='file'
            else:item['kind']='special'
            # Capture file capabilities without following links. Any unexpected
            # xattr read failure aborts rather than claiming a complete inventory.
            cap=capabilities(f)
            if cap is not None:item['capability_hex']=cap
            rows.append(item)
            if len(rows)>limit:raise ValueError('inventory entry cap')
    return rows

def check_zlib(rows):
    found=[r for r in rows if r[0]=='zlib1g:amd64' or r[0]=='zlib1g']
    if len(found)!=1 or found[0][1]!=ZLIB:raise ValueError('zlib version mismatch')

def collect():
    if sys.platform!='linux' or sys.prefix!='/opt/venv':raise ValueError('capture environment')
    result=subprocess.run(['dpkg-query','-W','-f=${binary:Package}\t${Version}\n'],capture_output=True,check=True,timeout=15)
    if len(result.stdout)>1024*1024:raise ValueError('package output cap')
    packages=[line.split('\t') for line in result.stdout.decode().splitlines()];check_zlib(packages)
    import sqlite3,ssl,zlib
    with sqlite3.connect(':memory:') as db:options=[r[0] for r in db.execute('pragma compile_options')]
    nv=Path(sysconfig.get_paths()['purelib'])/'nvidia/cuda_nvrtc/lib/libnvrtc.so.12'
    nv_handle=ctypes.CDLL(str(nv))  # Keep loaded through maps capture.
    status={k:v.strip() for k,v in (line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line) if k in ['Uid','Gid','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp']}
    if status.get('CapEff')!='0000000000000000' or status.get('NoNewPrivs')!='1':raise ValueError('capture isolation')
    mounts=[]
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        fields=line.split();mounts.append({'mountpoint':fields[4],'options':fields[5],'fstype':fields[fields.index('-')+1]})
    unknown=[x['mountpoint'] for x in mounts if x['mountpoint']!='/' and not any(x['mountpoint']==e or x['mountpoint'].startswith(e+'/') for e in EXCLUDED)]
    if unknown:raise ValueError('unexpected mounts')
    maps=sorted({line.split(None,5)[5] for line in Path('/proc/self/maps').read_text().splitlines() if len(line.split(None,5))==6 and line.split(None,5)[5].startswith('/')})
    return {'schema':1,'scope':'Visible persistent filesystem metadata excluding declared runtime mounts; not a full image export or proof of absent vulnerable code','excluded_paths':sorted(EXCLUDED),'files':inventory(),'packages':packages,'process_status':status,'mounts':mounts,'libraries':maps,'sqlite_version':sqlite3.sqlite_version,'sqlite_compile_options':options,'openssl_version':ssl.OPENSSL_VERSION,'zlib_build_version':zlib.ZLIB_VERSION,'zlib_runtime_version':zlib.ZLIB_RUNTIME_VERSION,'native_loaded':'NVRTC only; no GPU driver or GPU execution','provider_contact':False,'gpu_execution':False}

if __name__=='__main__':
    raw=json.dumps(collect(),separators=(',',':')).encode()
    if len(raw)>MAX_JSON:raise ValueError('inventory JSON cap')
    sys.stdout.buffer.write(raw+b'\n')
