import copy,hashlib,io,json,tarfile,tempfile,unittest,zipfile
from pathlib import Path
from unittest.mock import patch
import promote as p
class Tests(unittest.TestCase):
 def test_artifact_binding(self):
  v={'id':p.ARTIFACT,'expired':False,'digest':'sha256:'+p.ZIP_HASH,'workflow_run':{'id':p.RUN,'head_sha':p.SOURCE}}
  p.artifact_identity(v)
  for k,bad in [('id',0),('expired',True),('digest','bad'),('workflow_run',{'id':p.RUN,'head_sha':'bad'})]:
   x=copy.deepcopy(v);x[k]=bad
   with self.subTest(k=k),self.assertRaises(ValueError):p.artifact_identity(x)
 def test_extract_only_worker_and_refuse_changed_identity(self):
  with tempfile.TemporaryDirectory() as d:
   d=Path(d);z=d/'a.zip';out=d/'worker.tar';worker=b'worker'
   with zipfile.ZipFile(z,'w') as f:f.writestr('worker-image.tar',worker);f.writestr('../escape',b'no')
   with patch.multiple(p,ZIP_HASH=p.hash_file(z),ARCHIVE_BYTES=len(worker),ARCHIVE_HASH=hashlib.sha256(worker).hexdigest()):
    p.extract_worker(z,out);self.assertEqual(out.read_bytes(),worker);self.assertEqual(len(list(d.iterdir())),2)
   with self.assertRaises(ValueError):p.extract_worker(z,d/'other')
 def test_streamed_image_config_and_layers(self):
  with tempfile.TemporaryDirectory() as d:
   f=Path(d)/'image.tar';layer=b'layer';cfg=json.dumps({'os':'linux','architecture':'amd64','rootfs':{'diff_ids':['sha256:'+hashlib.sha256(layer).hexdigest()]}}).encode()
   with tarfile.open(f,'w') as tar:
    for name,data in [('manifest.json',json.dumps([{'Config':'config.json','Layers':['layer.tar']}]).encode()),('config.json',cfg),('layer.tar',layer)]:
     info=tarfile.TarInfo(name);info.size=len(data);tar.addfile(info,io.BytesIO(data))
   with patch.multiple(p,ARCHIVE_BYTES=f.stat().st_size,ARCHIVE_HASH=p.hash_file(f),CONFIG='sha256:'+hashlib.sha256(cfg).hexdigest()):
    self.assertEqual(p.verify_worker(f)['architecture'],'amd64')
    with patch.object(p,'CONFIG','sha256:'+'0'*64),self.assertRaises(ValueError):p.verify_worker(f)
 def test_acceptance_covers_whole_operation(self):
  p.require_acceptance(300,100,180)
  for now in (121,300):
   with self.assertRaises(ValueError):p.require_acceptance(300,now,180)
 def test_monitor_errors_fail_closed(self):
  with patch.object(p,'disk_bytes',side_effect=PermissionError()):self.assertFalse(p.monitor_check('/unused',1))
  with patch.object(p,'disk_bytes',return_value=5000000001):self.assertFalse(p.monitor_check('/unused',1))
  with patch.object(p,'disk_bytes',return_value=0):self.assertFalse(p.monitor_check('/unused',175))
 def test_scandir_failure_refuses_monitoring(self):
  with patch.object(p.os,'scandir',side_effect=PermissionError()):self.assertFalse(p.monitor_check('/unused',1))
 def test_disappearing_file_is_tolerated(self):
  with patch.object(p.os,'walk',return_value=[('/tmp',[],['gone'])]),patch.object(p.os,'lstat',side_effect=FileNotFoundError()):self.assertEqual(p.disk_bytes('/tmp'),0)
 def test_evidence_is_readable_and_sanitized(self):
  with tempfile.TemporaryDirectory() as d:
   f=Path(d)/'failure.json';p.export_evidence(f,{'stage':'push','failure_class':'ValueError'})
   self.assertEqual(f.stat().st_mode&0o777,0o644);self.assertEqual(json.loads(f.read_text())['stage'],'push')
 def test_redirect_refused(self):
  with self.assertRaises(ValueError):p.NoRedirect().redirect_request()
if __name__=='__main__':unittest.main()
