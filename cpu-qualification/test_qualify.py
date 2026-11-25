import json,tempfile,unittest
from pathlib import Path
from qualify import *
class Fake:
 def __init__(self,size=1,exit_code=0,failcreate=False):
  self.size=size;self.exit=exit_code;self.failcreate=failcreate;self.exists=False;self.identity=None;self.name=None;self.calls=[];self.t=0
 def clock(self):return self.t
 def sleep(self,t):self.t+=t
 def __call__(self,args,timeout=5):
  self.calls.append(args)
  if args[0]=='ps':return 'a'*64 if self.exists else ''
  if args[:2]==['image','inspect']:return json.dumps([{'Id':'sha256:'+'b'*64}])
  if args[0]=='create':
   self.exists=True;self.identity=args[args.index('--label')+1].split('=')[1]
   if self.failcreate:raise TimeoutError()
   return 'a'*64
  if args[0]=='inspect':
   return json.dumps([dict(Id='a'*64,Image='sha256:'+'b'*64,Config={'Labels':{'qualification.id':self.identity}},HostConfig=dict(Memory=MEM,MemorySwap=MEM,NanoCpus=2000000000,PidsLimit=256,NetworkMode='none',Privileged=False,SecurityOpt=['no-new-privileges'],LogConfig={'Type':'json-file','Config':{'max-size':'1m','max-file':'2'}}),Mounts=[],SizeRw=self.size,State=dict(Running=False,ExitCode=self.exit,OOMKilled=False))])
  if args[0]=='rm':self.exists=False
  return ''
class Tests(unittest.TestCase):
 def execute(self,f,path):return execute('worker','image@sha256:'+'b'*64,'sha256:'+'b'*64,[],['/bin/sh','/test'],path,f,f.clock,f.sleep)
 def test_pass_and_cleanup(self):
  with tempfile.TemporaryDirectory() as d:
   f=Fake();self.assertEqual(self.execute(f,d)['status'],'passed');self.assertFalse(f.exists)
 def test_disk_exceeded_cleanup(self):
  with tempfile.TemporaryDirectory() as d:
   f=Fake(size=DISK+1)
   with self.assertRaises(Failed):self.execute(f,d)
   self.assertFalse(f.exists)
 def test_failed_worker_and_no_retry(self):
  with tempfile.TemporaryDirectory() as d:
   f=Fake(exit_code=1)
   with self.assertRaises(Failed):self.execute(f,d)
   with self.assertRaises(FileExistsError):self.execute(f,d)
   self.assertEqual(sum(x[0]=='create' for x in f.calls),1)
 def test_lost_create_reply_reconciled(self):
  with tempfile.TemporaryDirectory() as d:
   f=Fake(failcreate=True)
   with self.assertRaises(Failed):self.execute(f,d)
   self.assertFalse(f.exists)
 def test_deadline_cleanup(self):
  with tempfile.TemporaryDirectory() as d:
   f=Fake();base=f.__call__
   def call(args,timeout=5):
    out=base(args,timeout)
    if args[0]=='inspect' and any(c[0]=='start' for c in f.calls):
     f.t+=90;rows=json.loads(out);rows[0]['State']['Running']=True;return json.dumps(rows)
    return out
   with self.assertRaises(Failed):execute('worker','image@sha256:'+'b'*64,'sha256:'+'b'*64,[],['/bin/sh','/test'],d,call,f.clock,f.sleep)
   self.assertFalse(f.exists)
 def test_controller_skipped_after_worker_failure(self):
  from campaign import sequence
  calls=[]
  def fail(kind,*a):calls.append(kind);raise Failed('worker')
  with self.assertRaises(Failed):sequence(fail)
  self.assertEqual(calls,['worker'])
 def test_failure_logs_before_removal(self):
  with tempfile.TemporaryDirectory() as d:
   f=Fake(exit_code=1)
   with self.assertRaises(Failed):self.execute(f,d)
   names=[x[0] for x in f.calls];self.assertLess(names.index('kill'),names.index('logs'));self.assertLess(names.index('logs'),names.index('rm'))
 def test_control_mismatch(self):
  f=Fake();f.identity='x';c=json.loads(f(['inspect']))[0];c['HostConfig']['MemorySwap']=-1
  with self.assertRaises(Failed):verify_controls(c)
if __name__=='__main__':unittest.main()
