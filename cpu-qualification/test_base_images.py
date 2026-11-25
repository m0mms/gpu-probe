import gzip,hashlib,io,json,tarfile,tempfile,unittest,urllib.request
from pathlib import Path
from base_images import docker_archive
from fetch import Redirect
class Tests(unittest.TestCase):
 def test_archive_preserves_config_and_layer(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);blob=root/'blobs';blob.mkdir();raw=io.BytesIO()
   with tarfile.open(fileobj=raw,mode='w') as t:
    info=tarfile.TarInfo('test');info.size=3;t.addfile(info,io.BytesIO(b'abc'))
   layer=raw.getvalue();compressed=gzip.compress(layer);digest=hashlib.sha256(compressed).hexdigest();(blob/digest).write_bytes(compressed)
   config={'rootfs':{'type':'layers','diff_ids':['sha256:'+hashlib.sha256(layer).hexdigest()]}};b=json.dumps(config).encode();c=hashlib.sha256(b).hexdigest();(blob/c).write_bytes(b)
   base={'kind':'worker','config':config,'manifest':{'config':{'digest':'sha256:'+c},'layers':[{'digest':'sha256:'+digest}]}}
   out=docker_archive(base,blob,root/'work')
   with tarfile.open(out) as t:
    m=json.load(t.extractfile('manifest.json'))[0];self.assertEqual(t.extractfile(m['Config']).read(),b);self.assertEqual(t.extractfile(m['Layers'][0]).read(),layer)
 def test_cross_host_redirect_drops_token(self):
  req=urllib.request.Request('https://ghcr.io/v2/a',headers={'Authorization':'Bearer private'})
  out=Redirect().redirect_request(req,None,302,'',{},'https://pkg-containers.githubusercontent.com/a')
  self.assertFalse(out.has_header('Authorization'))
 def test_unknown_redirect_refused(self):
  req=urllib.request.Request('https://ghcr.io/v2/a')
  with self.assertRaises(ValueError):Redirect().redirect_request(req,None,302,'',{},'https://example.org/a')
if __name__=='__main__':unittest.main()
