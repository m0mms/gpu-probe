"""Release source and installed-check contracts; no container/provider calls."""
import ast,hashlib,importlib.util,json,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT/'image'))
class Tests(unittest.TestCase):
 def test_qualified_guard_hashes(self):
  lock=json.loads((ROOT/'ci/v1-qualified-guard.json').read_text())
  self.assertEqual(set(lock),{'admission_diagnostics.py','attended_guard.py','cgroup_alias.py','cgroup_v1.py'})
  for n,h in lock.items():self.assertEqual(hashlib.sha256((ROOT/'image'/n).read_bytes()).hexdigest(),h)
 def test_v2_function_unchanged_except_dispatch(self):
  def tree(p):return ast.parse(p.read_text())
  old=tree(ROOT/'ci/native_baseline/attended_guard.py');new=tree(ROOT/'image/attended_guard.py')
  f=next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name=='memory_observation')
  self.assertIsInstance(f.body[1],ast.ImportFrom);self.assertEqual(f.body[1].module,'cgroup_v1');self.assertIsInstance(f.body[2],ast.If)
  del f.body[1:3]
  self.assertEqual(ast.dump(old,include_attributes=False),ast.dump(new,include_attributes=False))
 def test_native_and_dependency_invariants(self):
  lock=json.loads((ROOT/'ci/v1-invariants.json').read_text())
  for n,h in lock.items():self.assertEqual(hashlib.sha256((ROOT/'image'/n).read_bytes()).hexdigest(),h)
 def test_installed_v1_suite_matches_source_tests(self):
  source=ast.parse((ROOT/'image/test_cgroup_v1.py').read_text());installed=ast.parse((ROOT/'ci/installed_v1_tests.py').read_text())
  cls=next(n for n in source.body if isinstance(n,ast.ClassDef) and n.name=='Tests');cls.body=[n for n in cls.body if not (isinstance(n,ast.FunctionDef) and n.name=='test_native_package_and_process_guards_unchanged')]
  self.assertEqual(ast.dump(source,include_attributes=False),ast.dump(installed,include_attributes=False))
 def test_v1_failure_blocks_installed_linux_check(self):
  import cgroup_linux_check as c
  from types import SimpleNamespace
  with patch.object(c.Path,'read_text',return_value='inert'),patch.object(c.guard,'layout_counts',return_value={'cgroup_layout_oversize':False,'mount_malformed':0,'mount_v2_records':1}),patch('unittest.TextTestRunner.run',return_value=SimpleNamespace(testsRun=14,wasSuccessful=lambda:False)),patch.object(c.guard,'memory_observation') as obs:
   with self.assertRaisesRegex(ValueError,'v1 observer controls'):c.check()
   obs.assert_not_called()
 def test_runtime_receipt_requires_v1_fields(self):
  for name in ('installed_checks.py','runtime_check.py'):
   source=(ROOT/'ci'/name).read_text()
   self.assertIn("'v1_observer_simulation_checks':True",source);self.assertIn("'v1_observer_test_count':14",source);self.assertIn("'v1_guard_source_binding':True",source)
