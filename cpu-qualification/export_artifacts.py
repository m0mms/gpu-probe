"""Export successful stopped containers only; never push or launch images.
Docker commit/save are standard local operations. Export artifacts are candidates,
not accepted production images. No private estate module enters this package.
"""
import hashlib,io,json,tarfile,re
from pathlib import Path
from bounded import run
from qualify import require,docker,inspect_owned,verify_controls,DISK
from retain_wheel import inspect_wheel,MAX_WHEEL
TOTAL=2000000000
CONFIG_KEYS=('Env','WorkingDir','User','ExposedPorts','Volumes','OnBuild','Healthcheck','StopSignal')
class Exporter:
 def __init__(self,root,call=docker,runner=run):
  self.root=Path(root);self.root.mkdir(exist_ok=False);self.call=call;self.runner=runner;self.used=0
 def save(self,image,path):
  left=TOTAL-self.used;require(left>0,'artifact budget exhausted')
  code,out,err=self.runner(['docker','image','save','--output',str(path),image],timeout=30,cap=4194304,file_cap=left)
  require(code==0 and path.is_file() and not path.is_symlink(),'image export failed')
  self.used+=path.stat().st_size;require(self.used<=TOTAL,'artifact budget')
  h=hashlib.sha256()
  with path.open('rb') as f:
   for b in iter(lambda:f.read(1048576),b''):h.update(b)
  return {'file':path.name,'bytes':path.stat().st_size,'sha256':h.hexdigest()}
 def wheel(self,cid):
  code,out,err=self.runner(['docker','cp',cid+':/tmp/wheel/.','-'],timeout=15,cap=MAX_WHEEL+1048576)
  require(code==0,'wheel copy failed');records={}
  with tarfile.open(fileobj=io.BytesIO(out),mode='r:') as t:
   for m in t:
    if m.isdir() and m.name in ('.','./'):continue
    name=m.name.removeprefix('./');require(m.isfile() and Path(name).name==name and name not in records,'wheel archive member')
    require(name=='wheel.json' or (name.startswith('skypilot-') and name.endswith('.whl')),'unexpected wheel export')
    require(0<m.size<=(1048576 if name=='wheel.json' else MAX_WHEEL),'wheel member size')
    records[name]=t.extractfile(m).read()
  wheels=[n for n in records if n.endswith('.whl')];require(len(wheels)==1 and set(records)=={wheels[0],'wheel.json'},'wheel closure')
  payload=records[wheels[0]];require(self.used+len(payload)<=TOTAL,'artifact budget')
  target=self.root/wheels[0]
  with target.open('xb') as f:f.write(payload)
  self.used+=len(payload);actual=inspect_wheel(target);require(actual==json.loads(records['wheel.json']),'wheel receipt mismatch');return actual
 def __call__(self,kind,cid,identity,base_id):
  c=inspect_owned(cid,identity,base_id,self.call);verify_controls(c)
  require(not c['State']['Running'] and c['State']['ExitCode']==0 and not c['State'].get('OOMKilled'),'only successful stopped container')
  require(type(c.get('SizeRw')) is int and c['SizeRw']<=DISK,'export disk admission')
  base=json.loads(self.call(['image','inspect',base_id]))[0];config=base['Config']
  require(c['Config'].get('Env')==config.get('Env'),'qualification env leaked into image')
  tag='cpu-artifact-'+identity+':'+kind;image=None;result={};cleanup=False;commit_accepted=False;commit_started=False;primary=None;cleanup_error=None
  require(not self.call(['image','ls','-q',tag]).strip(),'artifact tag exists')
  try:
   if kind=='controller':result['wheel']=self.wheel(cid)
   entry=config.get('Entrypoint') or [];cmd=config.get('Cmd') or []
   if kind=='controller':entry=['/opt/controller/bin/python','-c',"raise SystemExit('controller activation remains interlocked')"];cmd=[]
   args=['commit','--change','ENTRYPOINT '+json.dumps(entry),'--change','CMD '+json.dumps(cmd),cid,tag]
   commit_started=True
   image=self.call(args,30).strip();commit_accepted=True;require(re.fullmatch(r'sha256:[0-9a-f]{64}',image),'commit image ID')
   created=json.loads(self.call(['image','inspect',tag]))[0];require(created['Id']==image and created['Config'].get('Labels',{}).get('qualification.id')==identity,'image ownership')
   cfg=created['Config'];require(cfg.get('Entrypoint')==entry and (cfg.get('Cmd') or [])==cmd,'image command')
   for k in CONFIG_KEYS:require(cfg.get(k)==config.get(k),'image config drift: '+k)
   result['image_id']=image;result['archive']=self.save(image,self.root/(kind+'-image.tar'))
  except Exception as exc:
   primary={'type':type(exc).__name__,'message':str(exc)[:300]}
  finally:
   try:
    ids=self.call(['image','ls','-q','--no-trunc',tag]).strip().splitlines()
    if ids:
     require(len(ids)==1,'ambiguous image cleanup');obj=json.loads(self.call(['image','inspect',tag]))[0]
     require(obj['Config'].get('Labels',{}).get('qualification.id')==identity,'image cleanup ownership')
     self.call(['image','rm',tag],30)
    require(not self.call(['image','ls','-q',tag]).strip(),'artifact image remains')
    require(not commit_started or commit_accepted or bool(ids),'commit outcome unresolved; runner disposal required')
    cleanup=True
   except Exception as exc:
    cleanup_error={'type':type(exc).__name__,'message':str(exc)[:300]}
  if primary is not None or cleanup_error is not None:
   raise RuntimeError(json.dumps({'primary':primary,'cleanup':cleanup_error},sort_keys=True))
  result['temporary_image_cleanup']=cleanup;result['cumulative_export_bytes']=self.used
  return result
