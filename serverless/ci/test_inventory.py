import copy,json,unittest
from pathlib import Path
from unittest.mock import patch
import security_scan as scan
ROOT='opt/venv/lib/python3.11/site-packages/'
def row(name='packaging',version='26.3',prefix=''):
 return {'Name':name,'Version':version,'FilePath':ROOT+prefix+name+'-'+version+'.dist-info/METADATA'}
def report(packages):
 return {'Metadata':{'ImageID':'sha256:test','OS':{'Family':'debian','Name':'13'}},'Results':[{'Class':'os-pkgs','Type':'debian','Packages':[{'Name':'libc6','Version':'x'}]},{'Class':'lang-pkgs','Type':'python-pkg','Packages':packages}]}
class InventoryTests(unittest.TestCase):
 def test_vendored_copy_does_not_mask_correct_install(self):
  r=report([row(),row(version='24.2',prefix='setuptools/_vendor/')])
  r['Results'][1]['Vulnerabilities']=[{'PkgName':'packaging','PkgPath':r['Results'][1]['Packages'][1]['FilePath'],'Severity':'HIGH'}]
  result=scan.assess(r,'sha256:test',{'packaging':'26.3'})
  self.assertEqual(result['findings'],1);self.assertFalse(result['passed']);self.assertEqual(result['other_python_installations'],1)
 def test_vendor_cannot_substitute_for_top_level(self):
  with self.assertRaises(ValueError):scan.assess(report([row(prefix='setuptools/_vendor/')]),'sha256:test',{'packaging':'26.3'})
 def test_wrong_or_conflicting_top_level_fails(self):
  for packages in [[row(version='24.2')],[row(),row(version='24.2')]]:
   with self.assertRaises(ValueError):scan.assess(report(packages),'sha256:test',{'packaging':'26.3'})
 def test_missing_or_forged_location_fails(self):
  for location in ['',ROOT+'../../packaging-26.3.dist-info/METADATA',ROOT+'other-26.3.dist-info/METADATA',ROOT+'packaging-24.2.dist-info/METADATA']:
   x=row();x['FilePath']=location
   with self.assertRaises(ValueError):scan.assess(report([x]),'sha256:test',{'packaging':'26.3'})
if __name__=='__main__':unittest.main()
