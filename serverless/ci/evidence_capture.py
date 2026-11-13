"""Host-side bounded capture and owned-container cleanup; no image publication."""
import json,os,re
from pathlib import Path
from bounded import run
from runtime_check import image_ref,image_check
ROOT=Path(__file__).resolve().parent.parent

def main():
    e=ROOT/'evidence';e.mkdir(exist_ok=True);image=image_ref(os.environ['BUILT_IMAGE_ID'])
    code,out,err=run(['docker','image','inspect',image])
    if code:raise ValueError('capture image inspect')
    obj=json.loads(out)[0];image_check(obj,image)
    name='serverless-evidence-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    if not re.fullmatch('serverless-evidence-[0-9]+-[0-9]+',name):raise ValueError('capture identity')
    try:
        args=['docker','run','--name',name,'--network','none','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=64m','--memory','1g','--memory-swap','1g','--cpus','2','--pids-limit','64','--cap-drop','ALL','--security-opt','no-new-privileges','--mount','type=bind,src='+str(ROOT/'ci')+',dst=/checks,readonly','--entrypoint','python',image,'-B','/checks/capture_inventory.py']
        code,out,err=run(args,timeout=180,cap=16*1024**2)
        (e/'capture-status.json').write_text(json.dumps({'exit_code':code,'stderr':err.decode(errors='replace'),'image_id':image,'source_sha':os.environ['GITHUB_SHA']})+'\n')
        if code:raise ValueError('capture failed')
        payload=json.loads(out)
        if payload.get('schema')!=1 or payload.get('gpu_execution') is not False or payload.get('provider_contact') is not False or not payload.get('files'):raise ValueError('capture payload')
        payload['image_id']=image;payload['source_sha']=os.environ['GITHUB_SHA']
        (e/'filesystem-library-inventory.json').write_text(json.dumps(payload,separators=(',',':'))+'\n')
    finally:
        run(['docker','rm','-f',name],timeout=30)
        code,out,err=run(['docker','ps','-aq','--filter','name=^/'+name+'$'],timeout=30)
        clean=code==0 and not out.strip()
        (e/'capture-cleanup.json').write_text(json.dumps({'owned_container':name,'clear':clean})+'\n')
        if not clean:raise ValueError('capture cleanup unverified')
if __name__=='__main__':main()
