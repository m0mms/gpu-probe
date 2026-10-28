# Runs inside the isolated synthetic SSH client container. No user keys.
import subprocess,json,sys,os
cfg=json.loads(sys.argv[1]);host=cfg['host'];key=cfg['host_key']
open('/tmp/known_hosts','w').write(host+' '+key+'\n')
base=['ssh','-F','/dev/null','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/tmp/known_hosts','-o','GlobalKnownHostsFile=/dev/null','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ConnectTimeout=3','-o','ConnectionAttempts=1','-o','LogLevel=INFO','-i','/tmp/key']
results=[];transports=[]
def call(name,extra,command=None,data=b'',user='gpu-probe'):
    argv=base+extra+[user+'@'+host]+([command] if command is not None else [])
    p=subprocess.run(argv,input=data,capture_output=True,timeout=8)
    if len(p.stdout)+len(p.stderr)>262144:raise ValueError('SSH output bound')
    evidence={'case':name,'returncode':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')}
    transports.append(evidence);print(json.dumps(evidence),file=sys.stderr,flush=True)
    return p
cmd='/usr/local/libexec/gpu-paid-worker --stdio-v1'
frame={'protocol_version':1,'operation':'probe','binding':cfg['registration'],'payload':{}}
p=call('probe',[],cmd,(json.dumps(frame)+'\n').encode())
print(json.dumps({'case':'exact_probe_transport','returncode':p.returncode,'stdout':p.stdout.decode(errors='replace'),'stderr':p.stderr.decode(errors='replace')}),file=sys.stderr,flush=True)
r=json.loads(p.stdout)
assert p.returncode==0 and r['binding']==cfg['registration'] and r['compute_admitted'] is False
results.append({'case':'exact_probe_nonroot','passed':True,'compute_admitted':False})
p=call('shell',[],'echo UNAUTHORIZED_SHELL_MARKER');assert p.returncode!=0 and b'UNAUTHORIZED_SHELL_MARKER' not in p.stdout
results.append({'case':'arbitrary_command','passed':True})
p=call('root',[],cmd,user='root');assert p.returncode!=0 and b'Permission denied' in p.stderr
results.append({'case':'root_denied','passed':True})
p=call('password',['-o','PubkeyAuthentication=no','-o','PreferredAuthentications=password'],cmd);assert p.returncode!=0 and b'Permission denied' in p.stderr
results.append({'case':'password_denied','passed':True})
# Replace the only selected identity with a separate synthetic key.
old=base[base.index('-i')+1];base[base.index('-i')+1]='/tmp/wrongkey'
p=call('wrongkey',[],cmd);assert p.returncode!=0 and b'Permission denied' in p.stderr
base[base.index('-i')+1]=old
results.append({'case':'unknown_key','passed':True})
p=call('pty',['-tt'],cmd);assert b'PTY allocation request failed' in p.stderr
results.append({'case':'pty_denied','passed':True})
p=call('forward',['-W','127.0.0.1:8022']);assert p.returncode!=0 and b'administratively prohibited' in p.stderr
results.append({'case':'forwarding_denied','passed':True})
print(json.dumps({'cases':results,'probe':r,'transports':transports}))
