import unittest
from resource_guard import verify
class Tests(unittest.TestCase):
 def good(self):return {'memory.max':'2147483648','memory.swap.max':'0','pids.max':'256','cpu.max':'200000 100000'}
 def test_good(self):verify(self.good(),['lo'])
 def test_each_unbounded_guard(self):
  for key in self.good():
   v=self.good();v[key]='max'
   with self.assertRaises(ValueError):verify(v,['lo'])
 def test_swap_and_network(self):
  v=self.good();v['memory.swap.max']='1'
  with self.assertRaises(ValueError):verify(v,['lo'])
  with self.assertRaises(ValueError):verify(self.good(),['lo','eth0'])
if __name__=='__main__':unittest.main()
