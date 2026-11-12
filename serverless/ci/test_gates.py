import copy,json,unittest,os,tempfile
from pathlib import Path
from unittest.mock import patch
import runtime_check as runtime
from preflight import admission,verify_image
from security_scan import assess,expected_packages
from runtime_check import image_check
class GateTests(unittest.TestCase):
 def test_frozen_context(self):self.assertTrue(verify_image())
 def test_source_admission(self):
  env={'GITHUB_SHA':'a'*40,'EXPECTED_SHA':'a'*40,'REVIEWED_SHA':'a'*40,'GITHUB_REPOSITORY':'m0mms/gpu-probe','GITHUB_EVENT_NAME':'workflow_dispatch'}
  self.assertEqual(admission(env),'a'*40)
  for k in env:
   with self.assertRaises(ValueError):admission(dict(env,**{k:'bad'}))
 def test_lock_inventory(self):
  p=expected_packages();self.assertEqual(len(p),105);self.assertEqual(p['runpod'],'2.2.1')
 def test_scan_requires_complete_coverage(self):
  r={'Metadata':{'ImageID':'sha256:x','OS':{'Family':'debian','Name':'12.12'}},'Results':[{'Class':'os-pkgs','Type':'debian','Packages':[{'Name':'libc6','Version':'x'}]},{'Class':'lang-pkgs','Type':'python-pkg','Packages':[{'Name':'Runpod','Version':'2.2.1'}]}]}
  self.assertTrue(assess(r,'sha256:x',{'runpod':'2.2.1'})['passed'])
  for bad in [dict(r,Metadata={}),dict(r,Results=r['Results'][:1]),dict(r,Results=[]),dict(r,Results=r['Results'][1:])]:
   with self.assertRaises(ValueError):assess(bad,'sha256:x',{'runpod':'2.2.1'})
  with self.assertRaises(ValueError):assess(r,'sha256:x',{'runpod':'2.2.2'})
  for field in ['Vulnerabilities','ExperimentalModifiedFindings']:
   bad=copy.deepcopy(r);bad['Results'][1][field]=[{'id':'finding'}]
   self.assertFalse(assess(bad,'sha256:x',{'runpod':'2.2.1'})['passed'])
 def test_image_entrypoint_ports(self):
  o={'Id':'sha256:x','Os':'linux','Architecture':'amd64','Config':{'Entrypoint':['python','-B','/qualification/bootstrap.py'],'Cmd':[]}}
  self.assertTrue(image_check(o,'sha256:x'))
  for change in [{'ExposedPorts':{'22/tcp':{}}},{'Entrypoint':['sh']},{'Cmd':['--rp_debugger']}]:
   with self.assertRaises(ValueError):image_check(dict(o,Config=dict(o['Config'],**change)),'sha256:x')
class CleanupTests(unittest.TestCase):
 def test_timeout_still_cleans_owned_container_and_fails(self):
  image='sha256:'+'a'*64
  obj={'Id':image,'Os':'linux','Architecture':'amd64','Size':1,'Config':{'Entrypoint':['python','-B','/qualification/bootstrap.py'],'Cmd':[]}}
  with tempfile.TemporaryDirectory() as tmp:
   root=Path(tmp);(root/'ci').mkdir()
   replies=[(0,json.dumps([obj]).encode(),b''),TimeoutError('forced'),(0,b'',b''),(0,b'',b'')]
   with patch.object(runtime,'ROOT',root),patch.object(runtime,'E',root/'evidence'),patch.dict(os.environ,{'BUILT_IMAGE_ID':image,'GITHUB_SHA':'a'*40,'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}),patch.object(runtime,'run',side_effect=replies) as run:
    with self.assertRaises(TimeoutError):runtime.main()
   self.assertEqual(run.call_args_list[2].args[0],['docker','rm','-f','serverless-validation-123-1'])
   self.assertTrue(json.loads((root/'evidence/cleanup.json').read_text())['clear'])
if __name__=='__main__':unittest.main()
