"""Fetch frozen OCI blobs through the shared byte counter; construct Docker load archives.
No registry push, CLI pull, retry or secret authentication. Anonymous pull tokens only.
"""
import gzip,hashlib,io,json,tarfile,urllib.parse
from pathlib import Path
from fetch import Fetch

def download(fetch,base,destination):
    registry=base['registry'];repo=base['repository']
    if (registry,repo) not in [('ghcr.io','m0mms/gpu-probe'),('registry-1.docker.io','library/python')]:raise ValueError('base registry')
    auth='https://ghcr.io/token?service=ghcr.io&scope=repository:m0mms/gpu-probe:pull' if registry=='ghcr.io' else 'https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull'
    b=io.BytesIO();fetch.get(auth,1048576,b);reply=json.loads(b.getvalue());token=reply.get('token',reply.get('access_token'))
    if not isinstance(token,str) or not token:raise ValueError('anonymous token')
    destination.mkdir(exist_ok=True)
    for x in base['blobs']:
        path=destination/x['digest'].split(':')[1]
        if path.exists():
            if path.stat().st_size!=x['size'] or hashlib.sha256(path.read_bytes()).hexdigest()!=x['digest'].split(':')[1]:raise ValueError('existing blob mismatch')
            continue
        with path.open('xb') as out:n,h=fetch.get('https://'+registry+'/v2/'+repo+'/blobs/'+x['digest'],x['size'],out,headers={'Authorization':'Bearer '+token})
        if n!=x['size'] or h!=x['digest'].split(':')[1]:raise ValueError('blob hash mismatch')

def docker_archive(base,blobs,work):
    work.mkdir();config=base['manifest']['config']['digest'].split(':')[1];layers=[];expanded=0
    for i,desc in enumerate(base['manifest']['layers']):
        path=blobs/desc['digest'].split(':')[1];target=work/(str(i)+'.tar');h=hashlib.sha256()
        with gzip.open(path,'rb') as src,target.open('xb') as dst:
            while True:
                b=src.read(1048576)
                if not b:break
                expanded+=len(b)
                if expanded>2000000000:raise ValueError('base expansion bound')
                dst.write(b);h.update(b)
        if 'sha256:'+h.hexdigest()!=base['config']['rootfs']['diff_ids'][i]:raise ValueError('uncompressed layer mismatch')
        layers.append(target.name)
    manifest=json.dumps([{'Config':config+'.json','RepoTags':['cpu-qualification-'+base['kind']+':base'],'Layers':layers}]).encode()
    archive=work/'load.tar'
    with tarfile.open(archive,'w') as out:
        info=tarfile.TarInfo('manifest.json');info.size=len(manifest);out.addfile(info,io.BytesIO(manifest))
        out.add(blobs/config,arcname=config+'.json',recursive=False)
        for name in layers:out.add(work/name,arcname=name,recursive=False)
    return archive

def main():
    from bounded import run
    root=Path(__file__).parent
    for base in json.loads((root/'bases.json').read_text()):
        archive=docker_archive(base,root/'base-blobs',root/('base-'+base['kind']))
        code,out,err=run(['docker','load','--input',str(archive)],timeout=180,cap=4194304)
        if code:raise RuntimeError('local base load failed')
if __name__=='__main__':main()
