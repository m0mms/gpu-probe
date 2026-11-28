"""One exact artifact promotion. CI-only; never builds or runs the worker."""
import hashlib,json,os,resource,shutil,signal,subprocess,sys,tarfile,tempfile,threading,time,urllib.request,urllib.error,zipfile
from pathlib import Path
REPO='m0mms/gpu-probe';RUN=45597035902;ARTIFACT=15014275893
SOURCE='88950b166c5bd0b98ff1a0aa09534444374d9eaf'
ZIP_HASH='3275087ebc0ba73f3c4ffed7818024fbd9364f5493398dbfe45dede628284456'
ARCHIVE_HASH='10a79986c90b31bbe0c0800bd67224799b4fdc940e9e9698b45b5e915b95074f'
CONFIG='sha256:cbe81c1c4ba19f7ceded4090120bec6090ed7b5e4c7ff1664a3c1e6fb710e5d9'
TARGET='ghcr.io/m0mms/gpu-probe:native-ssh-cbe81c1c4ba1'
ARCHIVE_BYTES=631460864

def need(ok,reason):
 if not ok:raise ValueError(reason)
def hash_file(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  while chunk:=f.read(1048576):h.update(chunk)
 return h.hexdigest()
def artifact_identity(meta):
 need(meta['id']==ARTIFACT and meta['expired'] is False and meta['digest']=='sha256:'+ZIP_HASH and meta['workflow_run']['id']==RUN and meta['workflow_run']['head_sha']==SOURCE,'artifact identity')
def extract_worker(zipped,destination):
 need(hash_file(zipped)==ZIP_HASH,'artifact archive')
 with zipfile.ZipFile(zipped) as z:
  items=[i for i in z.infolist() if i.filename=='worker-image.tar']
  need(len(items)==1 and items[0].file_size==ARCHIVE_BYTES,'single bounded worker')
  with z.open(items[0]) as inp,open(destination,'xb') as out:
   total=0
   while data:=inp.read(1048576):
    total+=len(data);need(total<=ARCHIVE_BYTES,'extraction bound');out.write(data)
 need(hash_file(destination)==ARCHIVE_HASH,'worker archive identity')
def verify_worker(path):
 need(Path(path).stat().st_size==ARCHIVE_BYTES and hash_file(path)==ARCHIVE_HASH,'worker identity')
 with tarfile.open(path,'r:') as tar:
  def small(name):
   member=tar.getmember(name);need(member.isfile() and member.size<=65536,'bounded archive metadata');return tar.extractfile(member).read()
  manifest=json.loads(small('manifest.json'));need(len(manifest)==1,'single image')
  config=small(manifest[0]['Config']);need('sha256:'+hashlib.sha256(config).hexdigest()==CONFIG,'image config')
  obj=json.loads(config);need(obj['os']=='linux' and obj['architecture']=='amd64','platform')
  layers=[]
  for name in manifest[0]['Layers']:
   member=tar.getmember(name);need(member.isfile(),'regular layer');h=hashlib.sha256()
   with tar.extractfile(member) as inp:
    while data:=inp.read(1048576):h.update(data)
   layers.append('sha256:'+h.hexdigest())
  need(layers==obj['rootfs']['diff_ids'],'layer identity')
 return obj
class NoRedirect(urllib.request.HTTPRedirectHandler):
 def redirect_request(self,*a,**kw):raise ValueError('registry redirect')
def registry(tag):
 opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
 def read(path,headers={}):
  try:
   with opener.open(urllib.request.Request('https://ghcr.io'+path,headers=headers),timeout=8) as response:
    data=response.read(1048577);need(len(data)<=1048576,'registry response');return response.status,data
  except urllib.error.HTTPError as e:
   if e.code==404:return 404,b''
   raise ValueError('registry unavailable') from None
 _,raw=read('/token?service=ghcr.io&scope=repository%3Am0mms%2Fgpu-probe%3Apull')
 token=json.loads(raw)['token'];headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json'}
 status,raw=read('/v2/m0mms/gpu-probe/manifests/'+tag,headers)
 if status==404:return None
 obj=json.loads(raw);need(obj.get('config',{}).get('digest')==CONFIG,'published config mismatch')
 status,config=read('/v2/m0mms/gpu-probe/blobs/'+CONFIG,headers)
 need(status==200 and 'sha256:'+hashlib.sha256(config).hexdigest()==CONFIG,'registry config bytes')
 return {'manifest_digest':'sha256:'+hashlib.sha256(raw).hexdigest(),'config_digest':CONFIG,'config':json.loads(config)}
def require_acceptance(until,now,remaining):
 need(now+remaining<float(until),'acceptance must cover remaining operation')
def disk_bytes(root):
 total=0
 def failed(error):raise error
 for base,dirs,files in os.walk(root,followlinks=False,onerror=failed):
  for name in files:
   try:
    st=os.lstat(os.path.join(base,name))
   except FileNotFoundError:continue
   if __import__('stat').S_ISREG(st.st_mode):total+=st.st_size
 return total
def monitor_check(root,elapsed):
 try:return disk_bytes(root)<=5000000000 and elapsed<175
 except Exception:return False
def export_evidence(path,value):
 # Only explicit sanitized JSON schemas reach this function; no command logs.
 path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o644)
def read_token(stream):
 raw=stream.read(65537)
 need(0<len(raw)<=65536 and all(33<=b<=126 for b in raw),'publication token input')
 return raw.decode('ascii')

def main():
 need(os.environ['GITHUB_REPOSITORY']==REPO and os.environ['GITHUB_RUN_ATTEMPT']=='1','CI scope')
 need(os.environ['GITHUB_SHA']==os.environ['REVIEWED_SHA']==os.environ['EXPECTED_SHA'],'reviewed commit')
 require_acceptance(os.environ['ACCEPTANCE_EXPIRES'],time.time(),180)
 need(os.geteuid()==0 and os.path.ismount('/dev/shm'),'isolated CI service')
 # Parent systemd unit owns every child including this private dockerd.
 props=subprocess.check_output(['systemctl','show',os.environ['PROMOTION_UNIT'],'-p','MemoryMax','-p','MemorySwapMax','-p','TasksMax','-p','CPUQuotaPerSecUSec','-p','RuntimeMaxUSec'],timeout=5,text=True)
 need(set(props.splitlines())=={'MemoryMax=2147483648','MemorySwapMax=0','TasksMax=256','CPUQuotaPerSecUSec=2s','RuntimeMaxUSec=3min'},'CI resource controls')
 root=Path(tempfile.mkdtemp(prefix='native-promotion-',dir='/tmp'));auth=Path(tempfile.mkdtemp(prefix='native-auth-',dir='/dev/shm'))
 evidence=Path(os.environ['EVIDENCE']);evidence.mkdir(exist_ok=True)
 token=read_token(sys.stdin.buffer)
 # Do not pass the credential input descriptor to any later child.
 with open(os.devnull,'rb') as null:os.dup2(null.fileno(),0)
 env=dict(os.environ,GH_TOKEN=token,DOCKER_HOST='unix://'+str(root/'docker.sock'),DOCKER_CONFIG=str(auth),HOME=str(root/'home'))
 (root/'home').mkdir();started=time.monotonic();done=threading.Event();stage='precheck';daemon=None
 def watch():
  while not done.wait(.2):
   if not monitor_check(root,time.monotonic()-started):os.kill(os.getpid(),signal.SIGTERM);return
 def abort(*_):raise TimeoutError('promotion bound')
 signal.signal(signal.SIGTERM,abort);threading.Thread(target=watch,daemon=True).start()
 resource.setrlimit(resource.RLIMIT_FSIZE,(1073741824,1073741824))
 def run(args,stdin=None,output=None):
  # All logs are bounded files in the sampled private workspace; never print secrets.
  with open(root/'command.err','wb') as err,open(root/'command.out','wb') as out:
   p=subprocess.run(args,input=stdin,stdout=output or out,stderr=err,env=env,timeout=max(.1,175-(time.monotonic()-started)))
  need(p.returncode==0,'command failed')
  need((root/'command.out').stat().st_size<=1048576 and (root/'command.err').stat().st_size<=1048576,'command output')
  return (root/'command.out').read_bytes()
 try:
  need(registry(TARGET.split(':')[-1]) is None,'target already exists; reconcile without repush')
  stage='download'
  artifact_identity(json.loads(run(['gh','api',f'repos/{REPO}/actions/artifacts/{ARTIFACT}'])))
  with open(root/'artifact.zip','xb') as out:run(['gh','api',f'repos/{REPO}/actions/artifacts/{ARTIFACT}/zip'],output=out)
  extract_worker(root/'artifact.zip',root/'worker-image.tar');config=verify_worker(root/'worker-image.tar')
  stage='load'
  daemon=subprocess.Popen(['dockerd','--data-root='+str(root/'docker'),'--exec-root='+str(root/'exec'),'--pidfile='+str(root/'daemon.pid'),'--host='+env['DOCKER_HOST'],'--bridge=none','--iptables=false','--ip6tables=false','--ip-forward=false','--ip-masq=false','--storage-driver=overlay2'],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
  for _ in range(50):
   need(daemon.poll() is None,'private daemon exited')
   if (root/'docker.sock').exists():break
   time.sleep(.1)
  need((root/'docker.sock').exists(),'private daemon unavailable')
  run(['docker','load','--input',str(root/'worker-image.tar')])
  loaded=json.loads(run(['docker','image','inspect',CONFIG]))
  need(len(loaded)==1 and loaded[0]['Id']==CONFIG,'loaded image identity')
  run(['docker','tag',CONFIG,TARGET]);stage='push'
  run(['docker','login','ghcr.io','--username',os.environ['GITHUB_ACTOR'],'--password-stdin'],stdin=token.encode())
  require_acceptance(os.environ['ACCEPTANCE_EXPIRES'],time.time(),max(0,180-(time.monotonic()-started)))
  need(registry(TARGET.split(':')[-1]) is None,'target appeared before push')
  run(['docker','push',TARGET]);stage='verify'
  binding=registry(TARGET.split(':')[-1]);need(binding and binding['config']==config,'registry binding')
  export_evidence(evidence/'binding.json',{'target':TARGET,'archive_sha256':ARCHIVE_HASH,'config_digest':CONFIG,'registry_manifest_digest':binding['manifest_digest'],'source_run':RUN,'source_commit':SOURCE,'promotion_commit':os.environ['GITHUB_SHA'],'verified':True})
 except BaseException as e:
  export_evidence(evidence/'failure.json',{'stage':stage,'failure_class':type(e).__name__,'automatic_retry':False,'publication_may_have_happened':stage in ('push','verify')});raise
 finally:
  done.set()
  if daemon and daemon.poll() is None:
   daemon.terminate()
   try:daemon.wait(timeout=2)
   except subprocess.TimeoutExpired:daemon.kill();daemon.wait(timeout=2)
  shutil.rmtree(auth)
  # No deletion of image data until the service has killed/reaped all descendants.
  # CI VM teardown removes the owned private daemon workspace; never docker prune.
if __name__=='__main__':
 try:main()
 except BaseException:sys.exit(1)
