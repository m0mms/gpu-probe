import io,json,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
from export_artifacts import Exporter,CONFIG_KEYS
from retain_wheel import retain
from qualify import Failed
class ArtifactTests(unittest.TestCase):
 def wheel(self,p,name='skypilot-1-py3-none-any.whl',metadata=b'Name: skypilot\nVersion: 1\n'):
  with zipfile.ZipFile(p/name,'w') as z:z.writestr('skypilot-1.dist-info/METADATA',metadata)
 def test_exact_one_wheel_and_receipt(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d);self.wheel(p);r=retain(p);self.assertEqual(json.loads((p/'wheel.json').read_text()),r)
 def test_multiple_and_wrong_wheels_refuse(self):
  for multiple in (False,True):
   with tempfile.TemporaryDirectory() as d:
    p=Path(d);self.wheel(p,metadata=b'Name: other\n')
    if multiple:self.wheel(p,'skypilot-2-py3-none-any.whl')
    with self.assertRaises(ValueError):retain(p)
 def exporter_fixture(self,root,fail=None):
  state={'exists':False,'calls':[]};identity='a'*32;image='sha256:'+'c'*64
  config={'Env':['BASE=1'],'Entrypoint':['/base'],'Cmd':['run']}
  created={'Id':image,'Config':dict(config,Labels={'qualification.id':identity})}
  def call(args,timeout=5):
   state['calls'].append(args)
   if args[:2]==['image','ls']:return image if state['exists'] else ''
   if args[:2]==['image','inspect']:return json.dumps([{'Config':config}] if args[2]=='base' else [created])
   if args[0]=='commit':
    state['exists']=True
    if fail=='lost_commit':raise TimeoutError('fixture')
    return image
   if args[:2]==['image','rm']:state['exists']=False;return ''
   raise AssertionError(args)
  def runner(args,**kw):
   self.assertEqual(kw['file_cap'],2000000000);self.assertEqual(kw['timeout'],30)
   if fail=='save':return 1,b'',b'fixture'
   Path(args[args.index('--output')+1]).write_bytes(b'archive');return 0,b'',b''
  c={'Config':config,'State':{'Running':False,'ExitCode':0,'OOMKilled':False},'SizeRw':1}
  return Exporter(root,call,runner),state,c,identity
 def test_success_commit_restores_commands_and_cleans_image(self):
  with tempfile.TemporaryDirectory() as d:
   ex,s,c,i=self.exporter_fixture(Path(d)/'out')
   with patch('export_artifacts.inspect_owned',return_value=c),patch('export_artifacts.verify_controls'):
    r=ex('worker','cid',i,'base')
   self.assertTrue(r['temporary_image_cleanup']);self.assertFalse(s['exists'])
   commit=next(x for x in s['calls'] if x[0]=='commit');self.assertIn('ENTRYPOINT ["/base"]',commit);self.assertIn('CMD ["run"]',commit)
 def test_failed_save_or_lost_commit_still_cleans_owned_image(self):
  for fail in ('save','lost_commit'):
   with self.subTest(fail=fail),tempfile.TemporaryDirectory() as d:
    ex,s,c,i=self.exporter_fixture(Path(d)/'out',fail)
    with patch('export_artifacts.inspect_owned',return_value=c),patch('export_artifacts.verify_controls'),self.assertRaises(Exception):ex('worker','cid',i,'base')
    self.assertFalse(s['exists'])
 def test_running_or_failed_container_never_committed(self):
  for state in ({'Running':True,'ExitCode':0},{'Running':False,'ExitCode':1}):
   with tempfile.TemporaryDirectory() as d:
    ex,s,c,i=self.exporter_fixture(Path(d)/'out');c['State']=state
    with patch('export_artifacts.inspect_owned',return_value=c),patch('export_artifacts.verify_controls'),self.assertRaises(Failed):ex('worker','cid',i,'base')
    self.assertFalse(s['calls'])
 def test_qualification_callback_failure_cleans_container(self):
  from test_qualify import Fake
  from qualify import execute
  with tempfile.TemporaryDirectory() as d:
   f=Fake()
   def fail(*args):raise RuntimeError('export fixture')
   with self.assertRaises(Failed):execute('worker','base','sha256:'+'b'*64,[],['/bin/sh','/test'],d,f,f.clock,f.sleep,on_success=fail)
   self.assertFalse(f.exists)
class ExportBoundaryTests(unittest.TestCase):
 def test_aggregate_export_budget_refuses_oversize(self):
  with tempfile.TemporaryDirectory() as d:
   def runner(args,**kw):
    Path(args[args.index('--output')+1]).write_bytes(b'12345678');return 0,b'',b''
   ex=Exporter(Path(d)/'out',runner=runner);ex.used=1999999993
   with self.assertRaises(Failed):ex.save('image',ex.root/'x.tar')
 def test_wheel_tar_traversal_refused(self):
  import tarfile
  raw=io.BytesIO()
  with tarfile.open(fileobj=raw,mode='w') as t:
   m=tarfile.TarInfo('../escape.whl');m.size=1;t.addfile(m,io.BytesIO(b'x'))
  with tempfile.TemporaryDirectory() as d:
   ex=Exporter(Path(d)/'out',runner=lambda *a,**k:(0,raw.getvalue(),b''))
   with self.assertRaises(Failed):ex.wheel('cid')
   self.assertFalse(list(ex.root.iterdir()))
 def test_config_drift_refuses_save_and_cleans(self):
  with tempfile.TemporaryDirectory() as d:
   owner=ArtifactTests();ex,s,c,i=owner.exporter_fixture(Path(d)/'out');original=ex.call
   def call(args,timeout=5):
    out=original(args,timeout)
    if args[:2]==['image','inspect'] and args[2]!='base':
     rows=json.loads(out);rows[0]['Config']['Env']=['UNEXPECTED=1'];return json.dumps(rows)
    return out
   ex.call=call
   with patch('export_artifacts.inspect_owned',return_value=c),patch('export_artifacts.verify_controls'),self.assertRaises(RuntimeError):ex('worker','cid',i,'base')
   self.assertFalse(s['exists']);self.assertFalse(list(ex.root.iterdir()))
class FailureEvidenceTests(unittest.TestCase):
 def test_primary_and_cleanup_errors_both_retained(self):
  with tempfile.TemporaryDirectory() as d:
   owner=ArtifactTests();ex,s,c,i=owner.exporter_fixture(Path(d)/'out','save');original=ex.call
   def call(args,timeout=5):
    if args[:2]==['image','rm']:raise OSError('cleanup fixture')
    return original(args,timeout)
   ex.call=call
   with patch('export_artifacts.inspect_owned',return_value=c),patch('export_artifacts.verify_controls'),self.assertRaises(RuntimeError) as caught:ex('worker','cid',i,'base')
   evidence=json.loads(str(caught.exception));self.assertEqual(evidence['primary']['message'],'image export failed');self.assertEqual(evidence['cleanup']['message'],'cleanup fixture')
 def test_campaign_reserves_complete_next_stage(self):
  from campaign import sequence
  calls=[];times=iter([0,0,41])
  def execute(kind,*args,**kw):calls.append(kind)
  with self.assertRaises(Failed):sequence(executor=execute,exporter=object(),clock=lambda:next(times))
  self.assertEqual(calls,['worker'])
if __name__=='__main__':unittest.main()
