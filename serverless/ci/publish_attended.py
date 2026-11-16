"""Publish only the already-built synthetic image; no rebuild or GPU call."""
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from bounded import run
from attended_release import main as gate, ROOT
from runtime_check import image_ref


def main():
    gate()
    sha=os.environ['GITHUB_SHA']
    if not re.fullmatch('[0-9a-f]{40}',sha) or os.environ.get('GITHUB_REPOSITORY')!='m0mms/gpu-probe':
        raise ValueError('publication destination')
    image=image_ref(os.environ['BUILT_IMAGE_ID'])
    tag='ghcr.io/m0mms/gpu-probe:attended-20261116-'+sha
    with tempfile.TemporaryDirectory() as temp:
        env=dict(os.environ,DOCKER_CONFIG=temp)
        token=env.pop('PUBLISH_TOKEN')
        result=subprocess.run(['docker','login','ghcr.io','-u',os.environ['GITHUB_ACTOR'],'--password-stdin'],
                              input=token.encode(),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30,env=env)
        del token
        if result.returncode:raise ValueError('registry login')
        code,_,_=run(['docker','tag',image,tag],env=env)
        if code:raise ValueError('image tag')
        code,out,err=run(['docker','push',tag],env=env,timeout=240)
        if code:raise ValueError('publication failed; reconcile, do not rebuild')
        code,out,err=run(['docker','image','inspect',tag],env=env)
        if code:raise ValueError('published digest unavailable')
        obj=json.loads(out)[0]
        digests=[d for d in obj['RepoDigests'] if re.fullmatch('ghcr.io/m0mms/gpu-probe@sha256:[0-9a-f]{64}',d)]
        if obj['Id']!=image or len(digests)!=1:raise ValueError('published binding')
        (ROOT/'evidence/publication.json').write_text(json.dumps({'image_id':image,'source_sha':sha,'tag':tag,'digest':digests[0],
                                                               'gpu_execution':False})+'\n')


if __name__=='__main__':main()
