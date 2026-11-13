import json,os,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import capture_inventory as c
import evidence_capture as h
class CaptureTests(unittest.TestCase):
 @patch.object(c,'capabilities',return_value=None)
 def test_tree_does_not_follow_links_and_records_modes(self,_cap):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);(p/'dir').mkdir();(p/'dir/file').write_text('x');(p/'link').symlink_to('/outside');(p/'dir/file').chmod(0o4755)
   rows={x['path']:x for x in c.inventory(p,excluded=set())}
   self.assertEqual(rows['/link']['kind'],'symlink');self.assertEqual(rows['/link']['target'],'/outside');self.assertEqual(rows['/dir/file']['mode'],(p/'dir/file').stat().st_mode & 0o7777)
 @patch.object(c,'capabilities',return_value=None)
 def test_exclusions_and_entry_cap(self,_cap):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);(p/'skip').mkdir();(p/'skip/file').write_text('x');(p/'keep').write_text('x')
   self.assertEqual([x['path'] for x in c.inventory(p,excluded={'/skip'})],['/keep'])
   with self.assertRaises(ValueError):c.inventory(p,excluded=set(),limit=1)
 def test_unreadable_metadata_fails(self):
  with tempfile.TemporaryDirectory() as t:
   p=Path(t);(p/'file').write_text('x')
   with patch.object(c,'capabilities',side_effect=PermissionError('forced')):
    with self.assertRaises(PermissionError):c.inventory(p)
 def test_capability_value_is_retained(self):
  with patch.object(c.os,'listxattr',create=True,return_value=['security.capability']),patch.object(c.os,'getxattr',create=True,return_value=b'abc'):
   self.assertEqual(c.capabilities(Path('/fixture')),'616263')
 def test_exact_zlib_required(self):
  c.check_zlib([['zlib1g:amd64',c.ZLIB]])
  for rows in [[],[['zlib1g','old']],[['zlib1g',c.ZLIB],['zlib1g:amd64',c.ZLIB]]]:
   with self.assertRaises(ValueError):c.check_zlib(rows)
 def test_capture_timeout_cleans_and_preserves_failure(self):
  image='sha256:'+'a'*64;obj={'Id':image,'Os':'linux','Architecture':'amd64','Config':{'Entrypoint':['python','-B','/qualification/bootstrap.py'],'Cmd':[]}}
  with tempfile.TemporaryDirectory() as t:
   with patch.object(h,'ROOT',Path(t)),patch.dict(os.environ,{'BUILT_IMAGE_ID':image,'GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'a'*40}),patch.object(h,'run',side_effect=[(0,json.dumps([obj]).encode(),b''),TimeoutError('forced'),(0,b'',b''),(0,b'',b'')]) as run:
    with self.assertRaises(TimeoutError):h.main()
   self.assertEqual(run.call_args_list[2].args[0],['docker','rm','-f','serverless-evidence-123-1'])
   self.assertTrue(json.loads((Path(t)/'evidence/capture-cleanup.json').read_text())['clear'])
if __name__=='__main__':unittest.main()
