"""Nonpublishing bounded preflight; fixed stages, no credential or stderr output."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import selectors
import signal
import time

REPO='m0mms/gpu-probe'
FAILED_RUN=40650684308
PUBLISHER_SHA='518fea48ed7d87fbdcee6c822a8a7f75d3c0d045'
ROOT='baa2ea26e8841b68741f8d14984692b97cd0c2f3'
TAG='qualification-20261022'
ARCHIVE_SHA='e314c9f954e099310aa31332f98fa9fb8e7ebbe64ff5f097772211fd04157fbd'
IMAGE_SHA='f40fb0c91f94d4aee25747c5880bad7236df56c3d856f24630cb5f19cac0a00c'
SKOPEO='/usr/bin/skopeo'
STAGES={'context','repository','failed_run','diagnostic_history','release','disk','tmpfs','archive_download','archive_hash','tool_version','local_manifest'}
class CheckFailed(Exception):pass
class CommandFailed(Exception):pass

def require(ok):
    if not ok:raise CheckFailed()

def command(args):
    r=subprocess.run(args,capture_output=True,timeout=180)
    if r.returncode:raise CommandFailed()
    return r.stdout

def api(path):return json.loads(command(['gh','api','repos/'+REPO+path]))

def stage(name,fn):
    require(name in STAGES)
    print(json.dumps({'stage':name,'status':'started'}),flush=True)
    try:result=fn()
    except Exception as e:
        category=('check_failed' if isinstance(e,CheckFailed) else
                  'command_failed' if isinstance(e,CommandFailed) else
                  'timeout' if isinstance(e,subprocess.TimeoutExpired) else
                  'unexpected_error')
        print(json.dumps({'stage':name,'status':'failed','category':category}),flush=True)
        raise CheckFailed() from None
    print(json.dumps({'stage':name,'status':'passed'}),flush=True)
    return result

def context(env):
    require(env.get('GITHUB_REPOSITORY')==REPO and env.get('GITHUB_REPOSITORY_ID')=='1430654983')
    require(env.get('GITHUB_REPOSITORY_OWNER_ID')=='474625' and env.get('GITHUB_ACTOR')=='m0mms')
    require(env.get('GITHUB_EVENT_NAME')=='workflow_dispatch' and env.get('GITHUB_REF')=='refs/heads/main')
    require(env.get('GITHUB_RUN_ATTEMPT')=='1' and env.get('RUNNER_ENVIRONMENT')=='github-hosted')
    require(re.fullmatch('[0-9a-f]{40}',env.get('NATIVE_INSPECTION_APPROVED_SHA','')) is not None)
    require(env['NATIVE_INSPECTION_APPROVED_SHA']==env.get('GITHUB_SHA'))

def repository():
    r=api('');require((r['id'],r['owner']['id'],r['visibility'],r['default_branch'])==(1430654983,474625,'public','main'))

def failed_run():
    r=api('/actions/runs/'+str(FAILED_RUN))
    require(r['id']==FAILED_RUN and r['run_attempt']==1 and r['conclusion']=='failure' and r['head_sha']==PUBLISHER_SHA)
    h=api('/actions/workflows/publish-native-qualification.yml/runs?per_page=100')
    require(h['total_count']==1 and len(h['workflow_runs'])==1 and h['workflow_runs'][0]['id']==FAILED_RUN)

def diagnostic_history():
    r=api('/actions/workflows/diagnose-native-inspection.yml/runs?per_page=100')
    require(r['total_count']==1 and len(r['workflow_runs'])==1)
    x=r['workflow_runs'][0];require(str(x['id'])==os.environ['GITHUB_RUN_ID'] and x['head_sha']==os.environ['GITHUB_SHA'])

def release():
    r=api('/releases/tags/'+TAG);t=api('/git/ref/tags/'+TAG)
    require(not r['draft'] and not r['prerelease'] and r['tag_name']==TAG)
    require(t['object']=={'sha':ROOT,'type':'commit','url':'https://api.github.com/repos/'+REPO+'/git/commits/'+ROOT})
    a=[x for x in r['assets'] if x['name']=='worker.oci.tar'];require(len(a)==1)
    require(a[0]['size']==47472640 and a[0]['digest']=='sha256:'+ARCHIVE_SHA and a[0]['state']=='uploaded')

def archive_hash(path):
    require(path.stat().st_size==47472640)
    with path.open('rb') as f:require(hashlib.file_digest(f,'sha256').hexdigest()==ARCHIVE_SHA)

def bounded_command(args,env,timeout=180,limit=65536):
    """Memory-only combined output; kill process group on timeout or output cap."""
    proc=subprocess.Popen(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                          start_new_session=True)
    data=bytearray(); reason=None; deadline=time.monotonic()+timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout,selectors.EVENT_READ)
            while selector.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:reason='timeout';break
                for key,_ in selector.select(min(remaining,0.2)):
                    chunk=os.read(key.fileobj.fileno(),min(4096,limit+1-len(data)))
                    if not chunk:selector.unregister(key.fileobj);continue
                    data.extend(chunk)
                    if len(data)>limit:reason='output_limit';break
                if reason:break
        if reason:
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
        try:code=proc.wait(timeout=max(0.1,deadline-time.monotonic()))
        except subprocess.TimeoutExpired:
            reason='timeout'
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            code=proc.wait(timeout=5)
        return {'returncode':code,'boundary':reason,'output':bytes(data[:limit])}
    finally:
        if proc.poll() is None:
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            proc.wait(timeout=5)
        proc.stdout.close()

def safe_detail(raw,directory):
    # Only output of fixed, credential-free local inspection of a public archive.
    text=raw.decode('utf-8',errors='replace').replace(directory,'<work>')
    text=re.sub(r'(?i)(bearer\s+)[^\s"\\]+',r'\1<redacted>',text)
    text=re.sub(r'(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+','<redacted>',text)
    text=''.join(c if c.isprintable() else ' ' for c in text)
    return text[:4096]

def inspect_archive(path):
    directory=str(path.parent)
    env={'PATH':'/usr/bin:/bin','HOME':directory,'TMPDIR':directory,'LANG':'C.UTF-8'}
    result=bounded_command([SKOPEO,'inspect','--raw','oci-archive:'+str(path)],env,timeout=300)
    raw=result.pop('output')
    matched=result['returncode']==0 and result['boundary'] is None and hashlib.sha256(raw).hexdigest()==IMAGE_SHA
    record={'stage':'local_manifest',**result,'manifest_matches':matched}
    if not matched:record['detail']=safe_detail(raw,directory)
    print(json.dumps(record),flush=True)
    return matched

def main():
    stage('context',lambda:context(os.environ));stage('repository',repository)
    stage('failed_run',failed_run);stage('diagnostic_history',diagnostic_history);stage('release',release)
    stage('disk',lambda:require(shutil.disk_usage(os.environ['RUNNER_TEMP']).free>=2*1024**3))
    with tempfile.TemporaryDirectory(prefix='native-inspection-',dir=os.environ['RUNNER_TEMP']) as directory:
        path=Path(directory)/'worker.oci.tar'
        stage('archive_download',lambda:command(['gh','release','download',TAG,'--repo',REPO,'--pattern','worker.oci.tar','--dir',directory]))
        os.environ.pop('GH_TOKEN',None)
        stage('archive_hash',lambda:archive_hash(path))
        version=command([SKOPEO,'--version']).decode().strip()
        require(re.fullmatch(r'skopeo version [0-9][0-9A-Za-z.+~: _-]{0,100}',version) is not None)
        print(json.dumps({'stage':'tool_version','version':version}),flush=True)
        ok=inspect_archive(path)
    print(json.dumps({'status':'inspection_passed' if ok else 'inspection_failed','publishing_attempted':False}),flush=True)
    return 0 if ok else 1

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print('{"status":"diagnostic_stopped","publishing_attempted":false}',flush=True)
        raise SystemExit(1) from None
