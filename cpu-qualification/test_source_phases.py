import hashlib,io,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from staging import Tree,extract_source
class PhaseTests(unittest.TestCase):
 def archive(self,root):
  a=root/'source.tar.gz'
  with tarfile.open(a,'w:gz') as t:
   for n in ('sky/setup_files/setup.py','sky/setup_files/MANIFEST.in','data.txt'):
    b=b'synthetic fixture\n';m=tarfile.TarInfo('src/'+n);m.size=len(b);t.addfile(m,io.BytesIO(b))
   for n in ('setup.py','MANIFEST.in'):
    m=tarfile.TarInfo('src/'+n);m.type=tarfile.SYMTYPE;m.linkname='sky/setup_files/'+n;t.addfile(m)
  return a,hashlib.sha256(a.read_bytes()).hexdigest()
 def test_success_reports_phases_and_same_output(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();a,h=self.archive(root);events=[]
   with Tree(root,'out') as tree:r=extract_source(tree,a,h,'src',{},10000,events.append)
   self.assertEqual(events,['source_inventory_begin','source_inventory_complete','source_extraction_begin','source_extraction_complete'])
   self.assertEqual(r['files'],3);self.assertEqual(r['links'],2)
   self.assertEqual((root/'out'/'data.txt').read_bytes(),b'synthetic fixture\n')
 def test_inventory_failure_has_no_false_completion(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();a,h=self.archive(root);events=[]
   with Tree(root,'out') as tree:
    with self.assertRaises(Exception):extract_source(tree,a,'0'*64,'src',{},10000,events.append)
   self.assertEqual(events,['source_inventory_begin'])
 def test_extraction_failure_has_no_false_completion(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();a,h=self.archive(root);events=[]
   with Tree(root,'out') as tree,patch.object(tree,'write',side_effect=OSError('fixture')):
    with self.assertRaises(OSError):extract_source(tree,a,h,'src',{},10000,events.append)
   self.assertEqual(events,['source_inventory_begin','source_inventory_complete','source_extraction_begin'])
 def test_default_callback_remains_optional(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d).resolve();a,h=self.archive(root)
   with Tree(root,'out') as tree:r=extract_source(tree,a,h,'src',{},10000)
   self.assertEqual(r['files'],3)
if __name__=='__main__':unittest.main()
