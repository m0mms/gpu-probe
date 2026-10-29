import copy
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import unittest
from release_receipt import validate_receipt, verify_run
from security_scan import assess
SHA='a'*40
D='sha256:'+'b'*64
class ReleaseTests(unittest.TestCase):
 def test_receipt(self):
  x={'repository':'m0mms/gpu-probe','source_sha':SHA,'run_id':'42','attempt':1,'tag':'ghcr.io/m0mms/gpu-probe:candidate-'+SHA+'-42-1','digest':D}
  raw=json.dumps(x).encode(); h=hashlib.sha256(raw).hexdigest(); self.assertEqual(validate_receipt(raw,h,'42',SHA),D)
  for args in [(raw,'0'*64,'42',SHA),(raw,h,'43',SHA),(raw,h,'42','c'*40)]:
   with self.assertRaises(ValueError): validate_receipt(*args)
  for key,value in [('repository','other/repo'),('attempt',2),('tag','latest'),('digest','bad')]:
   y=dict(x); y[key]=value; raw=json.dumps(y).encode()
   with self.assertRaises(ValueError): validate_receipt(raw,hashlib.sha256(raw).hexdigest(),'42',SHA)
 def test_run(self):
  x={'id':42,'head_sha':SHA,'event':'workflow_dispatch','status':'completed','conclusion':'success','run_attempt':1,'path':'.github/workflows/worker-security.yml','repository':{'id':1430654983},'updated_at':datetime.now(timezone.utc).isoformat()}
  verify_run(x,'42',SHA,'worker-security.yml')
  for key,value in [('event','pull_request'),('head_sha','c'*40),('conclusion','failure'),('run_attempt',2),('repository',{'id':4}),('path','wrong.yml'),('updated_at',(datetime.now(timezone.utc)-timedelta(days=2)).isoformat())]:
   y=copy.deepcopy(x); y[key]=value
   with self.assertRaises(ValueError): verify_run(y,'42',SHA,'worker-security.yml')
 def report(self):
  packages=json.loads(Path(__file__).with_name('expected-packages.json').read_text())
  return {'Metadata':{'OS':{'Family':'debian','Name':'12.13'},'ImageID':D},'Results':[{'Class':'os-pkgs','Type':'debian','Packages':[{'Name':n,'Version':v} for n,v in packages.items()]}]}
 def test_coverage(self):
  self.assertTrue(assess(self.report(),D)['passed'])
  for change in ('distro','identity','inventory','missing'):
   x=self.report()
   if change=='distro': x['Metadata']['OS']['Family']='alpine'
   elif change=='identity': x['Metadata']['ImageID']='sha256:'+'c'*64
   elif change=='inventory': x['Results'][0]['Packages'].pop()
   else: x['Results']=[]
   with self.assertRaises(ValueError): assess(x,D)
 def test_findings(self):
  for key in ('Vulnerabilities','ExperimentalModifiedFindings'):
   x=self.report(); x['Results'][0][key]=[{'VulnerabilityID':'synthetic','Severity':'LOW'}]
   self.assertFalse(assess(x,D)['passed'])

 def test_freshness_checked_after_environment_gate(self):
  path=Path(__file__).resolve().parent.parent/'.github/workflows/worker-release.yml'
  publish=path.read_text().split('  publish:\n',1)[1]
  self.assertIn('environment: worker-publication',publish)
  self.assertIn('actions: read',publish)
  check=publish.index('name: Recheck security run after environment approval')
  self.assertLess(check,publish.index('uses: docker/login-action@'))
  self.assertIn('SOURCE_RUN_ID: ${{ inputs.security_run_id }}',publish[check:])
  self.assertIn('EXPECTED_SHA: ${{ github.sha }}',publish[check:])
