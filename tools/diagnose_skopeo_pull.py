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
import time
import signal

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
    require(re.fullmatch('[0-9a-f]{40}',env.get('PULL_DIAGNOSTIC_APPROVED_SHA','')) is not None)
    require(env['PULL_DIAGNOSTIC_APPROVED_SHA']==env.get('GITHUB_SHA'))

def repository():
    r=api('');require((r['id'],r['owner']['id'],r['visibility'],r['default_branch'])==(1430654983,474625,'public','main'))

def failed_run():
    r=api('/actions/runs/'+str(FAILED_RUN))
    require(r['id']==FAILED_RUN and r['run_attempt']==1 and r['conclusion']=='failure' and r['head_sha']==PUBLISHER_SHA)
    h=api('/actions/workflows/publish-qualification.yml/runs?per_page=100')
    require(h['total_count']==1 and len(h['workflow_runs'])==1 and h['workflow_runs'][0]['id']==FAILED_RUN)

def diagnostic_history():
    previous=api('/actions/workflows/diagnose-qualification.yml/runs?per_page=100')
    require(previous['total_count']==1 and len(previous['workflow_runs'])==1)
    prior=previous['workflow_runs'][0]
    require(prior['id']==40462807070 and prior['run_attempt']==1 and prior['conclusion']=='failure'
            and prior['head_sha']=='b6b6470ee068a40fb3b9ef89ea24e81cf7af6a77')
    current=api('/actions/workflows/diagnose-skopeo-pull.yml/runs?per_page=100')
    require(current['total_count']==1 and len(current['workflow_runs'])==1)
    item=current['workflow_runs'][0]
    require(str(item['id'])==os.environ['GITHUB_RUN_ID'] and item['head_sha']==os.environ['GITHUB_SHA']
            and item['run_attempt']==1)

# These are observed message patterns, not asserted root causes. Never emit raw output.
PATTERNS={
    'daemon_unavailable':(b'cannot connect to the docker daemon',b'is the docker daemon running'),
    'permission_denied':(b'permission denied',),
    'manifest_unknown':(b'manifest unknown',b'manifest not found'),
    'platform_unavailable':(b'no matching manifest',),
    'authentication_denied':(b'unauthorized',b'authentication required',b'access denied',b'denied:'),
    'rate_limited':(b'toomanyrequests',b'too many requests',),
    'dns_failure':(b'no such host',b'temporary failure in name resolution'),
    'tls_failure':(b'x509:',b'tls handshake',b'certificate verify failed'),
    'connection_failure':(b'connection refused',b'connection reset',b'network is unreachable'),
    'network_timeout':(b'i/o timeout',b'context deadline exceeded'),
    'storage_failure':(b'no space left on device',),
}

def classify(data):
    lower=data.lower()
    labels=sorted(k for k,patterns in PATTERNS.items() if any(p in lower for p in patterns))
    return labels or ['unclassified']

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
        return {'returncode':code,'boundary':reason,'message_patterns':classify(bytes(data[:limit])) if code or reason else []}
    finally:
        if proc.poll() is None:
            try:os.killpg(proc.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            proc.wait(timeout=5)
        proc.stdout.close()

def docker_diagnostic(directory):
    # Deliberately exclude inherited credentials, proxies and Docker context overrides.
    env={'PATH':os.environ['PATH'],'HOME':directory,'DOCKER_CONFIG':directory,
         'LANG':'C.UTF-8','DOCKER_HOST':'unix:///var/run/docker.sock'}
    for name,args in [('docker_daemon',['docker','--config',directory,'info','--format','{{.ServerVersion}}']),
                      ('pinned_pull',['docker','--config',directory,'pull',SKOPEO])]:
        result=bounded_command(args,env)
        print(json.dumps({'stage':name,**result}),flush=True)
        if result['returncode'] or result['boundary']:return False
    return True

def main():
    stage('context',lambda:context(os.environ));stage('repository',repository)
    stage('failed_run',failed_run);stage('diagnostic_history',diagnostic_history)
    stage('disk',lambda:require(shutil.disk_usage(os.environ['RUNNER_TEMP']).free>=2*1024**3))
    os.environ.pop('GH_TOKEN',None)
    with tempfile.TemporaryDirectory(prefix='skopeo-pull-diagnostic-',dir=os.environ['RUNNER_TEMP']) as directory:
        ok=docker_diagnostic(directory)
    print(json.dumps({'status':'pull_passed' if ok else 'pull_diagnostic_failed',
                      'publishing_attempted':False,'registry_login_attempted':False}),flush=True)
    return 0 if ok else 1

if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print('{"status":"diagnostic_stopped","publishing_attempted":false}',flush=True)
        raise SystemExit(1) from None
