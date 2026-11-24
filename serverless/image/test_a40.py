import copy,unittest
from test_complete_admission import Tests as Fixtures
from receipt import valid_output
from test_handler import PASS
class A40Tests(unittest.TestCase):
 def test_exact_a40_admission(self):
  fixture=Fixtures();fixture.setUp()
  for major,minor,ok in [(8,6,True),(8,9,False),(8,0,False),(9,0,False)]:
   cu,nv,_=fixture.fake_libraries(versions={'major':major,'minor':minor,'driver':13020})
   if ok:self.assertEqual(fixture.observe_with(libs=[cu,nv])['compute'],[8,6])
   else:
    with self.assertRaisesRegex(ValueError,'unsupported_runtime'):fixture.observe_with(libs=[cu,nv])
 def test_exact_a40_receipt(self):
  self.assertTrue(valid_output(PASS))
  for compute in ([8,9],[8,0],[9,0],[8.0,6],[8,6.0]):
   out=copy.deepcopy(PASS);out['evidence']['native_identity']['compute']=compute
   self.assertFalse(valid_output(out))
if __name__=='__main__':unittest.main()
