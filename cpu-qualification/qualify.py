"""One CPU-only container qualification with approved sampled disk stop.
No provider calls, image push, retry, or arbitrary cleanup. Optional reviewed export runs only after successful exit.
"""
import json,time,uuid
from pathlib import Path
from bounded import run
MEM=2147483648;DISK=5000000000;SECONDS=180
class Failed(RuntimeError):pass

def require(ok,message):
    if not ok:raise Failed(message)

def docker(args,timeout=5):
    code,out,err=run(['docker',*args],timeout=timeout,cap=4194304)
    require(code==0,'docker command failed: '+args[0])
    return out.decode()

def inspect_owned(target,identity,image_id,call=docker,timeout=5):
    rows=json.loads(call(['inspect','--size',target],timeout));require(len(rows)==1,'ambiguous container')
    c=rows[0];require(c['Config']['Labels'].get('qualification.id')==identity,'ownership mismatch')
    require(c['Image']==image_id,'image mismatch');return c

def verify_controls(c):
    h=c['HostConfig']
    require(h['Memory']==MEM and h['MemorySwap']==MEM,'memory/swap mismatch')
    require(h['NanoCpus']==2000000000 and h['PidsLimit']==256,'CPU/PID mismatch')
    require(h['NetworkMode']=='none' and not h['Privileged'],'network/privilege mismatch')
    require(not h.get('Devices') and not h.get('DeviceRequests') and not h.get('PortBindings'),'devices or ports')
    require('no-new-privileges' in h['SecurityOpt'],'privilege guard')
    require(h['LogConfig']=={'Type':'json-file','Config':{'max-size':'1m','max-file':'2'}},'log limit')
    require(all(m.get('RW') is False for m in c['Mounts']),'writable input mount')

def execute(kind,image,image_id,mounts,command,outdir,call=docker,clock=time.monotonic,sleep=time.sleep,on_success=None):
    require(kind in ('worker','controller'),'test kind')
    outdir=Path(outdir);outdir.mkdir(parents=True,exist_ok=True)
    intent=outdir/(kind+'-intent.json')
    identity=uuid.uuid4().hex;name='cpu-qual-'+identity
    with intent.open('x') as f:json.dump({'id':identity,'name':name,'image':image,'image_id':image_id},f)
    # Pre-existing intent prevents retry even when creation never completed.
    cid=None;owned=False;result={'kind':kind,'status':'failed','disk_hard_cap':False,'max_sampled_bytes':0,'cleanup':False}
    try:
        require(not call(['ps','-aq','--filter','name=^/'+name+'$']).strip(),'name collision')
        found=json.loads(call(['image','inspect',image]));require(len(found)==1 and found[0]['Id']==image_id,'pinned image missing/mismatched')
        args=['create','--pull','never','--platform','linux/amd64','--name',name,'--label','qualification.id='+identity,
              '--network','none','--memory',str(MEM),'--memory-swap',str(MEM),'--cpus','2','--pids-limit','256',
              '--security-opt','no-new-privileges','--log-driver','json-file','--log-opt','max-size=1m','--log-opt','max-file=2']
        for source,dest in mounts:
            source=str(Path(source).resolve(strict=True));require(',' not in source and ',' not in dest,'mount syntax')
            args+=['--mount','type=bind,src='+source+',dst='+dest+',readonly']
        args+=['--entrypoint',command[0],image,*command[1:]]
        cid=call(args,30).strip();require(len(cid)==64 and all(x in '0123456789abcdef' for x in cid),'container ID')
        c=inspect_owned(cid,identity,image_id,call);owned=True;verify_controls(c)
        start=clock();call(['start',cid],min(5,SECONDS))
        while True:
            require(clock()-start<SECONDS,'qualification deadline')
            c=inspect_owned(cid,identity,image_id,call,min(5,SECONDS-(clock()-start)))
            elapsed=clock()-start;require(elapsed<SECONDS,'qualification deadline')
            size=c.get('SizeRw');require(type(size) is int and size>=0,'missing writable-layer measurement')
            result['max_sampled_bytes']=max(result['max_sampled_bytes'],size)
            require(size<=DISK,'sampled disk threshold exceeded')
            require(not c['State'].get('OOMKilled',False),'OOM failure')
            if not c['State']['Running']:
                require(c['State']['ExitCode']==0,'qualification exit failure');break
            sleep(min(1,SECONDS-elapsed))
        result['logs']=call(['logs',cid],5)
        if on_success is not None:result['artifacts']=on_success(kind,cid,identity,image_id)
        result['status']='passed'
    except Exception as e:
        result['failure_type']=type(e).__name__;result['failure']=str(e)[:2000]
    finally:
        try:
            # Known CID was ownership-checked before start; stop it promptly,
            # before potentially slow size inspection or evidence collection.
            if cid is not None and owned:
                try:call(['kill',cid],2)
                except Exception:pass  # Already-exited is expected; re-read below.
            # A timed-out create can leave a container despite missing reply.
            target=cid or name
            ids=call(['ps','-aq','--filter','name=^/'+name+'$']).strip().splitlines()
            if ids:
                require(len(ids)==1,'ambiguous cleanup')
                rows=json.loads(call(['inspect',target],3));require(len(rows)==1,'cleanup identity')
                c=rows[0];require(c['Config']['Labels'].get('qualification.id')==identity and c['Image']==image_id,'cleanup ownership')
                result['final_state']=c['State']
                try:result['logs']=call(['logs',c['Id']],3)
                except Exception as evidence_error:result['log_collection_failure']=type(evidence_error).__name__
                call(['rm','-f',c['Id']],10)
            require(not call(['ps','-aq','--filter','name=^/'+name+'$']).strip(),'container remains')
            result['cleanup']=True
        except Exception as e:
            result['cleanup_failure']=type(e).__name__;result['status']='failed'
        (outdir/(kind+'-result.json')).write_text(json.dumps(result,indent=2)+'\n')
    require(result['status']=='passed' and result['cleanup'],'qualification or cleanup failed')
    return result
