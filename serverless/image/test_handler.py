import json, subprocess, unittest
from unittest.mock import patch
import handler as h
from receipt import PASS as BASE, accepted
PASS = dict(BASE, evidence={"package_freeze":"2f5f212e97f3858c250ea383370b2fb95604c248d7beb388b1b06825c42af288", "native_identity":dict(driver_sha256="a"*64,nvrtc_sha256="b"*64,ptx_sha256="c"*64,compile_log_sha256="d"*64,device_ordinal=0,compute=[8,6],driver_version=12090,nvrtc_version=[12,9]), "peak_sampled_rss":1024,"effective_memory_limit":8*2**30,"hidden_ancestors_verified":False,"provider_admission_verified":False})
class AdapterTests(unittest.TestCase):
 def setUp(self):h.USED=False
 def test_invalid_input_never_executes(self):
  with patch.object(h,'execute') as run:
   for value in (None,{}, {'input':{'test':'bad'}}, {'input':dict(h.REQUEST,code='secret')}):
    self.assertEqual(h.handler(value),{'status':'synthetic_native_fail','reason':'invalid_request'})
   run.assert_not_called()
 def test_failure_consumes_attempt_without_exception(self):
  with patch.object(h,'execute',side_effect=ValueError('secret')) as run:
   self.assertEqual(h.handler({'input':h.REQUEST}),{'status':'synthetic_native_fail','reason':'qualification_failed','stage':'handler_internal'})
   self.assertEqual(h.handler({'input':h.REQUEST}),{'status':'synthetic_native_fail','reason':'attempt_already_used'})
   self.assertEqual(run.call_count,1)
 def test_timeout_and_bad_receipt_fail_closed(self):
  with patch.object(h.subprocess,'run',side_effect=subprocess.TimeoutExpired('secret',110)):
   self.assertEqual(h.handler({'input':h.REQUEST})['reason'],'qualification_failed')
  for payload in ({},dict(PASS,env='secret'),dict(PASS,elements=257.0),dict(PASS,numeric_exact=1),'not-json'):
   h.USED=False
   with patch.object(h.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(payload).encode())):
    self.assertEqual(h.handler({'input':h.REQUEST})['status'],'synthetic_native_fail')
 def test_success_and_duplicate(self):
  with patch.object(h.subprocess,'run',return_value=subprocess.CompletedProcess([],0,json.dumps(PASS).encode())) as run:
   self.assertEqual(h.handler({'input':h.REQUEST}),PASS)
   self.assertEqual(h.handler({'input':h.REQUEST})['reason'],'attempt_already_used')
   self.assertEqual(run.call_count,1)
 def test_real_runner_refuses_unprepared_environment(self):
  self.assertEqual(h.handler({'input':h.REQUEST}),{'status':'synthetic_native_fail','reason':'qualification_failed','stage':'attempt_claim'})
 def test_client_requires_bound_exact_success(self):
  good={'id':'job1','status':'COMPLETED','output':PASS.copy()}
  self.assertTrue(accepted(good,'job1'))
  for bad in (None,{},dict(good,id='other'),dict(good,status='FAILED'),dict(good,error='x'),dict(good,output={'status':'synthetic_native_fail','reason':'qualification_failed'}),dict(good,output=dict(PASS,elements=257.0)),dict(good,output=dict(PASS,extra=True)),dict(good,output=dict(PASS,numeric_exact=1))):
   self.assertFalse(accepted(bad,'job1'))
  self.assertFalse(accepted(good,''))
if __name__=='__main__':unittest.main()
