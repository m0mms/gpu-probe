import hashlib,io,unittest,json
from pathlib import Path
from fetch import Fetch
class Response(io.BytesIO):
 def __init__(self,data):super().__init__(data);self.headers={"Content-Length":str(len(data))};self.consumed=0
 def read(self,n=-1):
  b=super().read(n);self.consumed+=len(b);return b
 def __enter__(self):return self
 def __exit__(self,*args):self.close()
class Opener:
 def __init__(self,data):self.data=data
 def open(self,*a,**k):self.response=Response(self.data);return self.response
class Tests(unittest.TestCase):
 def test_hash_and_aggregate_budget(self):
  f=Fetch(10,6);f.opener=Opener(b'abc');sink=io.BytesIO()
  self.assertEqual(f.get('https://files.pythonhosted.org/a',3,sink),(3,hashlib.sha256(b'abc').hexdigest()));self.assertEqual(f.left,1)
  with self.assertRaises(ValueError):f.get('https://files.pythonhosted.org/b',3,io.BytesIO())
 def test_aggregate_boundary_consumes_no_extra_byte(self):
  f=Fetch(1,0);f.opener=Opener(b'abc')
  with self.assertRaises(ValueError):f.get('https://files.pythonhosted.org/a',3,io.BytesIO())
  self.assertEqual(f.opener.response.consumed,1);self.assertEqual(f.left,0)
 def test_response_larger_than_lock(self):
  f=Fetch(100,0);f.opener=Opener(b'abcd')
  with self.assertRaises(ValueError):f.get('https://files.pythonhosted.org/a',3,io.BytesIO())
 def test_unknown_host_refused_before_read(self):
  f=Fetch(100,0)
  with self.assertRaises(ValueError):f.get('https://example.org/a',3,io.BytesIO())
class ManifestTests(unittest.TestCase):
 def test_all_locked_input_urls_pass_real_fetch_policy(self):
  lock=json.loads((Path(__file__).parent/'inputs.json').read_text())
  self.assertEqual(len(lock['files']),168)
  for entry in lock['files']:
   url=entry.get('url') or entry['metadata_url']
   with self.subTest(name=entry['name'],url=url):
    f=Fetch(1,0);f.opener=Opener(b'x')
    self.assertEqual(f.get(url,1,io.BytesIO()),(1,hashlib.sha256(b'x').hexdigest()))
 def test_debian_security_variants_still_refused(self):
  for url in ('http://security.debian.org/a','https://security.debian.org.evil.example/a','https://evil.security.debian.org/a'):
   with self.subTest(url=url):
    f=Fetch(1,0);f.opener=Opener(b'x')
    with self.assertRaises(ValueError):f.get(url,1,io.BytesIO())
    self.assertFalse(hasattr(f.opener,'response'))
if __name__=='__main__':unittest.main()
