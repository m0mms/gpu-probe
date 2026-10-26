"""Nonpublishing bounded preflight; fixed stages, no credential or stderr output."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

REPO='m0mms/gpu-probe'
FAILED_RUN=40344860824
PUBLISHER_SHA='9183b0c56f408954ae648af2e294297650627c05'
ROOT='baa2ea26e8841b68741f8d14984692b97cd0c2f3'
TAG='qualification-20261022'
ARCHIVE_SHA='e314c9f954e099310aa31332f98fa9fb8e7ebbe64ff5f097772211fd04157fbd'
IMAGE_SHA='f40fb0c91f94d4aee25747c5880bad7236df56c3d856f24630cb5f19cac0a00c'
SKOPEO='quay.io/skopeo/stable@sha256:309ce24d7a87ca4eb35fc6dd9d91af7c4750d7f24578f633c6effd75c81f315d'
STAGES={'context','repository','failed_run','diagnostic_history','release','disk','tmpfs','archive_download','archive_hash','skopeo_pull','local_manifest'}
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
    require(re.fullmatch('[0-9a-f]{40}',env.get('DIAGNOSTIC_APPROVED_SHA','')) is not None)
    require(env['DIAGNOSTIC_APPROVED_SHA']==env.get('GITHUB_SHA'))

def repository():
    r=api('');require((r['id'],r['owner']['id'],r['visibility'],r['default_branch'])==(1430654983,474625,'public','main'))

def failed_run():
    r=api('/actions/runs/'+str(FAILED_RUN))
    require(r['id']==FAILED_RUN and r['run_attempt']==1 and r['conclusion']=='failure' and r['head_sha']==PUBLISHER_SHA)
    h=api('/actions/workflows/publish-qualification.yml/runs?per_page=100')
    require(h['total_count']==1 and len(h['workflow_runs'])==1 and h['workflow_runs'][0]['id']==FAILED_RUN)

def diagnostic_history():
    r=api('/actions/workflows/diagnose-qualification.yml/runs?per_page=100')
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

def local_manifest(path):
    require(hashlib.sha256(command(['docker','run','--rm','--pull=never','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--memory=512m','--memory-swap=512m','--cpus=1','--pids-limit=32','--log-driver=none','--tmpfs','/var/tmp:rw,noexec,nosuid,nodev,size=134217728,mode=1777','--mount',f'type=bind,src={path},dst=/input/image.tar,readonly',SKOPEO,'inspect','--raw','oci-archive:/input/image.tar'])).hexdigest()==IMAGE_SHA)

def main():
    stage('context',lambda:context(os.environ));stage('repository',repository)
    stage('failed_run',failed_run);stage('diagnostic_history',diagnostic_history);stage('release',release)
    stage('disk',lambda:require(shutil.disk_usage(os.environ['RUNNER_TEMP']).free>=2*1024**3))
    stage('tmpfs',lambda:require(command(['findmnt','-n','-o','FSTYPE','-T','/dev/shm']).strip()==b'tmpfs'))
    with tempfile.TemporaryDirectory(prefix='gpu-probe-diagnostic-',dir=os.environ['RUNNER_TEMP']) as directory:
        path=Path(directory)/'worker.oci.tar'
        stage('archive_download',lambda:command(['gh','release','download',TAG,'--repo',REPO,'--pattern','worker.oci.tar','--dir',directory]))
        os.environ.pop('GH_TOKEN',None)
        stage('archive_hash',lambda:archive_hash(path))
        stage('skopeo_pull',lambda:command(['docker','pull',SKOPEO]))
        stage('local_manifest',lambda:local_manifest(path))
    print(json.dumps({'status':'pre_registry_stages_passed','publishing_attempted':False,'registry_authentication_tested':False}),flush=True)

if __name__=='__main__':
    try:main()
    except Exception:
        print('{"status":"diagnostic_stopped","publishing_attempted":false}',flush=True)
        raise SystemExit(1) from None
