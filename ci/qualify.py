"""Portable synthetic qualification. No provider access or registry credentials."""
import hashlib, json, os, re, shutil, signal, sys, tarfile, time, uuid
from pathlib import Path
from bounded import run
from identity import digest, IMAGE, qualification_reference
SCRIPTS=Path(__file__).resolve().parent
ROOT=Path(os.environ['EVIDENCE_DIR']).resolve()
ROOT.mkdir(parents=True,exist_ok=True)
MODE=os.environ.get('QUALIFICATION_MODE','registry')
TAG=qualification_reference(os.environ['QUALIFY_IMAGE'],MODE)
NAME='gpu-probe-ci-'+uuid.uuid4().hex
NETWORK=NAME+'-net'; WORKER=NAME+'-worker'; CLIENT=NAME+'-client'
ENV={k:v for k,v in os.environ.items() if k in ('PATH','HOME','DOCKER_CONFIG','LANG')}
START=time.monotonic(); TEST_START=None; LOG_BYTES=0; FORCED_FAILURE_REACHED=False

def save(name,obj):
    (ROOT/name).write_text(json.dumps(obj,indent=2)+'\n')

def command(args,ok=True,timeout=120,file_cap=None):
    global LOG_BYTES
    if time.monotonic()-START>540: raise ValueError('suite overall bound')
    if TEST_START and time.monotonic()-TEST_START>120: raise ValueError('synthetic suite deadline')
    remaining=540-(time.monotonic()-START)
    if TEST_START: remaining=min(remaining,120-(time.monotonic()-TEST_START))
    code,out,err=run(args,env=ENV,timeout=min(timeout,max(.1,remaining)),file_cap=file_cap)
    LOG_BYTES+=len(out)+len(err)
    if LOG_BYTES>20*1024**2: raise ValueError('suite evidence budget exceeded')
    if ok and code:
        save('command-failure.json',{'command':args[:3],'returncode':code,'stderr':err.decode(errors='replace')})
        raise ValueError('command failed')
    return code,out,err

def d(*args,**kwargs): return command(['docker',*args],**kwargs)
def data(*args): return json.loads(d(*args)[1])
def effective(obj,memory,quota,pids):
    h=obj['HostConfig']
    assert h['Memory']==memory and h['MemorySwap']==memory
    assert h.get('NanoCpus')==quota*10**9
    assert h['PidsLimit']==pids and not h['Privileged'] and not h.get('PortBindings')
    assert not h.get('Binds') and 'no-new-privileges' in h['SecurityOpt']

def forbidden(name):
    name=name.lstrip('./')
    return (name.startswith('run/gpu-bootstrap-identity/') or
            name=='etc/gpu-paid-worker/registration.json' or
            re.fullmatch(r'etc/ssh/ssh_host_.*_key(?:\.pub)?',name) is not None or
            name.endswith('/authorized_keys') or name.endswith('/id_ed25519') or name.endswith('/id_rsa'))

def scan_image(image):
    # Save only the already-pulled image. No layer execution or extraction.
    target=ROOT/'scan-image.tar'
    try:
        d('image','save','--output',str(target),image,file_cap=1024**3)
        if target.stat().st_size>1024**3: raise ValueError('image save too large')
        expanded=0; count=0
        with tarfile.open(target,'r:') as archive:
            entries=archive.getmembers()
            manifests=[m for m in entries if m.name=='manifest.json']
            if len(manifests)!=1 or manifests[0].size>1024**2: raise ValueError('save manifest')
            desc=json.load(archive.extractfile(manifests[0]))
            if len(desc)!=1: raise ValueError('multiple saved images')
            for layer_name in desc[0]['Layers']:
                item=archive.getmember(layer_name)
                if not item.isfile(): raise ValueError('layer member type')
                with tarfile.open(fileobj=archive.extractfile(item),mode='r|*') as layer:
                    for member in layer:
                        count+=1; expanded+=member.size
                        if count>200000 or expanded>2*1024**3: raise ValueError('layer scan budget')
                        if forbidden(member.name): raise ValueError('baked identity path')
        save('baked-identity.json',{'passed':True,'members':count,'expanded_bytes':expanded,
                                  'scope':'all saved layers; forbidden identity paths, not generic secret detection'})
    finally:
        target.unlink(missing_ok=True)

def cleanup():
    # Query by unpredictable per-run ownership label; never prune global Docker state.
    try:
        for kind in ('container','network'):
            code,out,err=run(['docker',kind,'ls','--quiet',*(['--all'] if kind=='container' else []),
                             '--filter','label=gpu-probe.ci='+NAME],env=ENV,timeout=10)
            if code: raise ValueError('cleanup inventory unavailable')
            ids=out.decode().split()
            if ids:
                args=['docker',kind,'rm',*(['--force'] if kind=='container' else []),*ids]
                if run(args,env=ENV,timeout=20)[0]: raise ValueError('cleanup failed')
            if run(['docker',kind,'ls','--quiet',*(['--all'] if kind=='container' else []),
                    '--filter','label=gpu-probe.ci='+NAME],env=ENV,timeout=10)[:2] != (0,b''):
                raise ValueError('cleanup not empty')
        return True
    except Exception as exc:
        save('cleanup-failure.json',{'type':type(exc).__name__,'message':str(exc)})
        return False

def main():
    global TEST_START, FORCED_FAILURE_REACHED
    if shutil.disk_usage(ROOT).free<4*1024**3: raise ValueError('insufficient test disk')
    image=data('image','inspect',TAG)[0]
    assert image['Os']=='linux' and image['Architecture']=='amd64'
    scan_image(TAG)
    layer_count=len(image['RootFS']['Layers'])
    save('candidate-image.json',image)
    TEST_START=time.monotonic()
    d('network','create','--internal','--label','gpu-probe.ci='+NAME,NETWORK)
    flags=['--label','gpu-probe.ci='+NAME,'--network',NETWORK,'--memory','268435456','--memory-swap','268435456','--cpus','1','--pids-limit','64','--security-opt','no-new-privileges','--log-driver','local','--log-opt','max-size=1m','--log-opt','max-file=1','--log-opt','compress=false']
    d('run','--pull=never','-d','--name',CLIENT,*flags,'--entrypoint','/usr/bin/python3',TAG,'-I','-B','-c','import time;time.sleep(120)')
    import_check="import os,sys,stat;from pathlib import Path;assert os.geteuid()==10001;sys.path.insert(0,'/opt/gpu-probe');from paid_probe.capability_worker import main;p=Path('/opt/gpu-probe/paid_probe');s=p.stat();assert s.st_uid==0 and s.st_gid==0 and stat.S_IMODE(s.st_mode)==0o755;print('NONROOT_IMPORT_OK')"
    code,out,err=d('exec','--user','10001:10001',CLIENT,'/usr/bin/python3','-I','-S','-B','-c',import_check)
    assert out.strip()==b'NONROOT_IMPORT_OK'
    save('nonroot-import.json',{'uid':10001,'passed':True,'package_directory_mode':'0755','owner':'root:root','isolated_python':True})
    for key in ('key','wrongkey'):d('exec',CLIENT,'ssh-keygen','-q','-t','ed25519','-N','','-C','','-f','/tmp/'+key)
    pub=d('exec',CLIENT,'cat','/tmp/key.pub')[1].decode().strip()
    reg={'request_id':'synthetic','tenant':'synthetic','account_ref':'synthetic','request_hash':'1'*64}
    launch={'version':1,'registration':reg,'nonce':'2'*64,'authorized_public_key':pub}
    d('run','--pull=never','-d','--name',WORKER,*flags,'--env','GPU_PROBE_LAUNCH_JSON='+json.dumps(launch),'--env','RUNPOD_POD_ID=synthetic_pod',TAG)
    assert d('exec',WORKER,'id','-u','gpu-probe')[1].strip()==b'10001'
    for name in (CLIENT,WORKER):effective(data('container','inspect',name)[0],268435456,1,64)
    if os.environ.get('QUALIFICATION_FORCE_FAILURE')=='1':
        FORCED_FAILURE_REACHED=True
        raise RuntimeError('registered cleanup failure control')
    # Finite readiness observations, not repeated tests.
    record=None
    for _ in range(20):
        raw=d('logs',WORKER)[1].decode().strip()
        if raw:record=json.loads(raw);break
        time.sleep(.25)
    assert record and record['nonce']=='2'*64 and record['request_sha256']=='1'*64
    hostkey=d('exec',WORKER,'ssh-keygen','-y','-f','/run/gpu-bootstrap-identity/ssh_host_ed25519_key')[1].decode().strip()
    assert record['host_key']==hostkey
    config=d('exec',WORKER,'/usr/sbin/sshd','-T','-f','/etc/ssh/sshd_config_probe')[1].decode()
    for setting in ['permitrootlogin no','passwordauthentication no','kbdinteractiveauthentication no','permittty no','disableforwarding yes','permituserrc no','permituserenvironment no','forcecommand /usr/local/libexec/gpu-paid-worker --stdio-v1','authenticationmethods publickey']:assert setting in config.splitlines()
    d('exec',WORKER,'/usr/sbin/sshd','-t','-f','/etc/ssh/sshd_config_probe')
    listener="import socket,pathlib;s=socket.socket();s.bind(('127.0.0.1',8022));s.listen();s.settimeout(60);pathlib.Path('/tmp/listener-ready').touch();s.accept();pathlib.Path('/tmp/forward-contact').touch()"
    d('exec','-d',WORKER,'/usr/bin/python3','-c',listener)
    for _ in range(20):
        if d('exec',WORKER,'test','-f','/tmp/listener-ready',ok=False)[0]==0:break
        time.sleep(.1)
    else:raise ValueError('listener not ready')
    ip=data('container','inspect',WORKER)[0]['NetworkSettings']['Networks'][NETWORK]['IPAddress']
    reg['resource_id']='synthetic_pod';cfg={'host':ip,'host_key':hostkey,'registration':reg}
    result=json.loads(d('exec',CLIENT,'/usr/bin/python3','-I','-B','-c',(SCRIPTS/'client_tests.py').read_text(),json.dumps(cfg),timeout=75)[1])
    assert d('exec',WORKER,'test','-e','/tmp/forward-contact',ok=False)[0]==1
    # Re-entry must refuse existing state, not emit a second identity.
    entry=image['Config']['Entrypoint']
    code,out,err=d('exec',WORKER,*entry,ok=False);assert code==2 and not out
    assert json.loads(d('logs',WORKER)[1])==record
    installed=d('exec',WORKER,'cat','/opt/gpu-probe/packages.txt')[1].decode()
    for path,h in json.loads((SCRIPTS/'image-files.json').read_text())['files'].items():
        got=d('exec',WORKER,'sha256sum','/'+path)[1].decode().split()[0];assert got==h['sha256']
        metadata=d('exec',WORKER,'stat','-c','%u:%g:%a','/'+path)[1].decode().strip();assert metadata=='0:0:'+h['mode'].lstrip('0')
    save('test-result.json',{'status':'passed','client_tests':result,'effective_sshd':config,'dependency_manifest':installed,'layer_count':layer_count,'baked_identity_scan':'fresh Docker-save layer scan passed','second_start_refused':True,'forward_destination_contacted':False,'identity':record,'image_id':image['Id'],'limitations':'Synthetic local image only; no Runpod injection, live log permissions, GPU or compute qualification.'})


if __name__=='__main__':
    signal.signal(signal.SIGTERM,lambda *_: sys.exit(143))
    passed=False
    try:
        main();passed=True
    except Exception as exc:
        save('failure.json',{'type':type(exc).__name__,'message':str(exc)})
    finally:
        clean=cleanup()
        save('result.json',{'passed':passed,'cleanup_passed':clean,'seconds':round(time.monotonic()-START,2),
                            'image_reference':TAG,'qualification_mode':MODE,'registry_qualified':False,'forced_failure_reached':FORCED_FAILURE_REACHED,'provider_calls':0,'gpu_qualified':False})
    raise SystemExit(0 if passed and clean else 1)
