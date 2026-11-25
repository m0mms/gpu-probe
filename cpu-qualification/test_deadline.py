import unittest
from deadline import remaining
class Tests(unittest.TestCase):
 def stat(self,ticks):return '1 (python (worker)) '+' '.join(['S']+['0']*18+[str(ticks)]+['0']*5)
 def test_budget_includes_startup(self):self.assertEqual(remaining(self.stat(10000),110,100),165)
 def test_expired(self):
  with self.assertRaises(ValueError):remaining(self.stat(10000),281,100)
if __name__=='__main__':unittest.main()
