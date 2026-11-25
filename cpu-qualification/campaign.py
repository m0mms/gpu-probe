"""Exact sequential CPU campaign. This script never pulls or publishes images."""
import json,os,platform,shutil,time
from pathlib import Path
from qualify import execute,require
ROOT=Path(__file__).resolve().parent
IMAGES=[('worker','cpu-qualification-worker:base','sha256:7dbd83bfc8ab838945c09ed6ebf6923d259d54a272ea4348f2f587a861c49445'),('controller','cpu-qualification-controller:base','sha256:896edfbcbf0c29ad15681617a8886cb9871b7f24c5fde4606114c8ee6bfe4c70')]
def preflight():
 require(platform.system()=='Linux' and platform.machine()=='x86_64','native Linux amd64 required')
 require(os.environ.get('GITHUB_REPOSITORY')=='m0mms/gpu-probe','repository')
 require(os.environ.get('GITHUB_RUN_ATTEMPT')=='1','rerun refused')
 expected=os.environ.get('EXPECTED_SHA','');reviewed=os.environ.get('REVIEWED_SHA','');actual=os.environ.get('GITHUB_SHA','')
 require(len(expected)==40 and expected==reviewed==actual,'exact reviewed commit')
 require(shutil.disk_usage(ROOT).free>=8000000000,'free disk admission')
 mem=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines());require(int(mem['MemAvailable'].split()[0])*1024>=3*1024**3,'memory admission')
def sequence(executor=execute,exporter=None,clock=time.monotonic):
 started=clock()
 for kind,image,image_id in IMAGES:
  if exporter is not None:require(clock()-started<=40,'insufficient campaign budget for next bounded build/export/cleanup')
  # An exception from worker prevents entering controller; no retry handler.
  executor(kind,image,image_id,[(ROOT/'inputs','/inputs'),(ROOT,'/control')],['python','-B','/control/deadline.py',kind],ROOT/'evidence',**({'on_success':exporter} if exporter is not None else {}))
def main():
 preflight()
 from export_artifacts import Exporter
 sequence(exporter=Exporter(ROOT/'artifacts'))
if __name__=='__main__':
 import sys
 if sys.argv[1:]==['preflight']:preflight()
 else:main()
