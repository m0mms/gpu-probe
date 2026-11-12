import json,os,re,sys
from pathlib import Path
from bounded import run
ROOT=Path(__file__).resolve().parent.parent
E=ROOT/'evidence'
def image_ref(value):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',value):raise ValueError('image identity')
    return value

def image_check(obj,image):
    if obj['Id']!=image or obj['Os']!='linux' or obj['Architecture']!='amd64':raise ValueError('image/platform')
    cfg=obj['Config']
    if cfg.get('Entrypoint')!=['python','-B','/qualification/bootstrap.py'] or cfg.get('Cmd') not in [None,[]] or cfg.get('ExposedPorts'):raise ValueError('entrypoint/ports')
    return True

def main():
    E.mkdir(exist_ok=True);image=image_ref(os.environ['BUILT_IMAGE_ID'])
    code,out,err=run(['docker','image','inspect',image]);
    if code:raise ValueError('inspect image')
    obj=json.loads(out)[0];image_check(obj,image)
    (E/'image.json').write_text(json.dumps({'image_id':image,'source_sha':os.environ['GITHUB_SHA'],'size':obj['Size'],'platform':'linux/amd64'})+'\n')
    name='serverless-validation-'+os.environ['GITHUB_RUN_ID']+'-'+os.environ['GITHUB_RUN_ATTEMPT']
    if not re.fullmatch(r'serverless-validation-[0-9]+-[0-9]+',name):raise ValueError('run identity')
    try:
        args=['docker','run','--name',name,'--network','none','--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=256m','--memory','2g','--memory-swap','2g','--cpus','2','--pids-limit','256','--cap-drop','ALL','--security-opt','no-new-privileges','--mount','type=bind,src='+str(ROOT/'ci')+',dst=/checks,readonly','--entrypoint','python',image,'-B','/checks/installed_checks.py']
        code,out,err=run(args,timeout=180,cap=1024*1024)
        (E/'runtime.json').write_text(json.dumps({'exit_code':code,'stdout':out.decode(errors='replace'),'stderr':err.decode(errors='replace')})+'\n')
        expected={'sdk_installed_checks':True,'nvrtc_compile_and_negative_control':True,'gpu_execution':False,'provider_contact':False}
        if code or json.loads(out)!=expected:raise ValueError('installed checks failed')
    finally:
        run(['docker','rm','-f',name],timeout=30)
        code,out,err=run(['docker','ps','-aq','--filter','name=^/'+name+'$'],timeout=30)
        clean=code==0 and not out.strip()
        (E/'cleanup.json').write_text(json.dumps({'owned_container':name,'clear':clean})+'\n')
        if not clean:raise ValueError('cleanup unverified')
if __name__=='__main__':main()
