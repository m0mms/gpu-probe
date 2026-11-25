import hashlib,io,os,random,tarfile,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from staging import Tree,extract_source
from source_stage import source_inventory

class ForwardTests(unittest.TestCase):
 def fixture(self,root,extra=None):
  files={'sky/setup_files/setup.py':b'setup fixture\n','sky/setup_files/MANIFEST.in':b'include fixture\n','bin/tool':b'#!/bin/sh\nexit 0\n','data':random.Random(42).randbytes(131072)}
  a=root/'source.tar.gz'
  with tarfile.open(a,'w:gz') as t:
   for n,b in files.items():
    m=tarfile.TarInfo('src/'+n);m.size=len(b);m.mode=0o755 if n=='bin/tool' else 0o644;t.addfile(m,io.BytesIO(b))
   for n,target in [('setup.py','sky/setup_files/setup.py'),('MANIFEST.in','sky/setup_files/MANIFEST.in')]:
    m=tarfile.TarInfo('src/'+n);m.type=tarfile.SYMTYPE;m.linkname=target;t.addfile(m)
   if extra:extra(t)
  return a,hashlib.sha256(a.read_bytes()).hexdigest(),files
 def test_golden_contents_modes_links_and_overlay(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d).resolve();a,h,files=self.fixture(r);candidate=r/'patch';candidate.write_bytes(b'new data')
   patches={'data':{'original_sha256':hashlib.sha256(files['data']).hexdigest(),'candidate_path':str(candidate),'candidate_sha256':hashlib.sha256(candidate.read_bytes()).hexdigest()}}
   with Tree(r,'out') as tree:result=extract_source(tree,a,h,'src',patches,200000)
   for n,b in files.items():self.assertEqual((r/'out'/n).read_bytes(),b'new data' if n=='data' else b)
   self.assertEqual((r/'out/bin/tool').stat().st_mode&0o777,0o700)
   self.assertEqual(os.readlink(r/'out/setup.py'),'sky/setup_files/setup.py');self.assertEqual(result['links'],2)
 def test_streams_never_seek_backwards_during_tar_pass(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d).resolve();a,h,files=self.fixture(r);original=tarfile.open;modes=[]
   class ForwardReader:
    def __init__(self,raw):self.raw=raw
    def read(self,n=-1):return self.raw.read(n)
    def tell(self):return self.raw.tell()
    def seek(self,*args):raise AssertionError('tar pass must not seek')
   def opened(*args,**kw):
    modes.append(kw['mode']);kw['fileobj']=ForwardReader(kw['fileobj']);return original(*args,**kw)
   with patch('tarfile.open',side_effect=opened),Tree(r,'out') as tree:extract_source(tree,a,h,'src',{},200000)
   self.assertEqual(modes,['r|gz','r|gz'])
 def test_changed_expected_member_hash_refuses_copy(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d).resolve();a,h,_=self.fixture(r);checked=source_inventory(a,h,'src',{});checked['member_sha256']['data']='0'*64
   with Tree(r,'out') as tree,patch('staging.source_inventory',return_value=checked):
    with self.assertRaises(Exception):extract_source(tree,a,h,'src',{},200000)
    self.assertTrue(tree.failed)
 def test_wrong_original_overlay_hash_refused(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d).resolve();a,h,_=self.fixture(r);p=r/'patch';p.write_bytes(b'x')
   with self.assertRaises(Exception):source_inventory(a,h,'src',{'data':{'original_sha256':'0'*64,'candidate_path':str(p),'candidate_sha256':hashlib.sha256(b'x').hexdigest()}})
 def test_expansion_budget_refused_before_writes(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d).resolve();a,h,_=self.fixture(r)
   with Tree(r,'out') as tree:
    with self.assertRaises(Exception):extract_source(tree,a,h,'src',{},100)
    self.assertEqual(tree.bytes,0)
 def test_unsafe_members_still_rejected_before_writes(self):
  def escaped(t):
   m=tarfile.TarInfo('src/../escape');m.size=1;t.addfile(m,io.BytesIO(b'x'))
  def link(t):
   m=tarfile.TarInfo('src/bad');m.type=tarfile.SYMTYPE;m.linkname='../../escape';t.addfile(m)
  def duplicate(t):
   m=tarfile.TarInfo('src/data');m.size=1;t.addfile(m,io.BytesIO(b'x'))
  for extra in (escaped,link,duplicate):
   with self.subTest(case=extra.__name__),tempfile.TemporaryDirectory() as d:
    r=Path(d).resolve();a,h,_=self.fixture(r,extra)
    with Tree(r,'out') as tree:
     with self.assertRaises(Exception):extract_source(tree,a,h,'src',{},200000)
     self.assertEqual(tree.bytes,0)
if __name__=='__main__':unittest.main()
