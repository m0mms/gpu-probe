import json,os,re
from pathlib import Path
from bounded import run
nodes=json.loads(os.environ['BUILDER_NODES'])
if len(nodes)!=1 or not re.fullmatch('[a-zA-Z0-9_-]{1,100}',nodes[0]['name']):raise ValueError('builder identity')
name='buildx_buildkit_'+nodes[0]['name']
code,out,err=run(['docker','container','inspect',name],timeout=30)
if code:raise ValueError('builder inspection')
x=json.loads(out)[0];h=x['HostConfig']
if h.get('Memory')!=4*2**30 or h.get('MemorySwap')!=4*2**30 or h.get('CpuPeriod')!=100000 or h.get('CpuQuota')!=200000 or x['State']['Running'] is not True:raise ValueError('builder limits')
p=Path('evidence');p.mkdir(exist_ok=True);(p/'builder.json').write_text(json.dumps({'name':name,'id':x['Id'],'memory':h['Memory'],'cpu_quota':h['CpuQuota'],'privileged':h.get('Privileged'),'limits_scope':'Builder only, not Docker daemon or disk'})+'\n')
