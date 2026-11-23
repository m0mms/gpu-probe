import ast,copy,hashlib,json,unittest
from pathlib import Path
import admission_diagnostics as d
import attended_guard as g
from failure import failed,valid_failure
from receipt import accepted
M='31 22 0:27 / /sys/fs/cgroup ro,nosuid - cgroup2 cgroup rw'
V1='32 22 0:28 / /sys/fs/cgroup/memory ro - cgroup cgroup rw,memory'
class LayoutTests(unittest.TestCase):
 def test_v2_and_hybrid_discrimination(self):
  v=g.layout_counts('0::/',M)
  self.assertEqual((v['mount_v2_records'],v['mount_v1_memory_records'],v['mount_malformed']),(1,0,0))
  h=g.layout_counts('7:cpu,memory:/job\n0::/job',V1)
  self.assertEqual((h['cgroup_v1_memory_memberships'],h['cgroup_unified_memberships'],h['mount_v1_memory_records'],h['mount_v2_records']),(1,1,1,0))
  both=g.layout_counts('7:memory:/job\n0::/job',M+'\n'+V1)
  self.assertEqual((both['mount_v1_memory_records'],both['mount_v2_records']),(1,1))
 def test_valid_mount_variants(self):
  for text in [M.replace(' - ',' shared:3 master:1 - '),M.replace('cgroup2 cgroup','cgroup2 none'),M.replace('/sys/fs/cgroup','/sys/fs/cgroup\\040space')]:
   self.assertEqual(g.layout_counts('0::/',text)['mount_v2_records'],1)
  self.assertEqual(g.layout_counts('0::/',V1.replace('rw,memory','rw,notmemory'))['mount_v1_memory_records'],0)
 def test_malformed_and_tokens_not_identity(self):
  for text in [M.replace(' - ','\t-\t'),M.replace('31 22','bad 22'),M.replace('0:27','bad'),M.replace(' ro,nosuid',''),M+' extra']:
   v=g.layout_counts('0::/',text);self.assertEqual(v['mount_malformed'],1);self.assertEqual(v['mount_v2_records'],0);self.assertEqual(v['mount_cgroup2_tokens'],1)
  v=g.layout_counts('0::/',M.replace('cgroup2 cgroup','tmpfs cgroup2'))
  self.assertEqual(v['mount_cgroup2_tokens'],1);self.assertEqual(v['mount_v2_records'],0)
 def test_membership_malformed_and_bounds(self):
  v=g.layout_counts('bad\n0:memory:/\n1::/\n1:memory:relative', '')
  self.assertEqual(v['cgroup_membership_malformed'],4)
  for cg,mt in [('x'*(1024*1024+1),M),('0::/','x'*(1024*1024+1))]:
   v=g.layout_counts(cg,mt);self.assertEqual(v['cgroup_layout_oversize'],1);self.assertEqual(sum(v.values()),1)
  self.assertEqual(g.layout_counts('','')['mount_records'],0)
 def test_hybrid_requires_verified_v1_view(self):
  from unittest.mock import patch
  from cgroup_v1 import V1View
  d.reset()
  with patch.object(V1View,'__enter__',side_effect=RuntimeError('unverified')):
   with self.assertRaises(RuntimeError):g.memory_observation('7:memory:/job\n0::/job',V1,lambda p:'1')
  out=dict(failed('runtime_admission'),admission=d.snapshot())
  self.assertEqual(out['admission']['code'],'v1_mapping')
  self.assertEqual(out['admission']['facts']['mount_v1_memory_records'],1)
  self.assertTrue(valid_failure(out));self.assertFalse(accepted({'id':'j','status':'COMPLETED','output':out},'j'))
 def test_privacy_and_counter_reset(self):
  d.reset();g.layout_counts('7:memory:/SECRET',V1.replace('/sys/fs/cgroup/memory','/SECRET'))
  for cg,mt in [('7:memory:/SECRET\n0::/SECRET',V1),('0::/','')]:
   from unittest.mock import patch
   from cgroup_v1 import V1View
   with patch.object(V1View,'__enter__',side_effect=RuntimeError('unverified')):
    with self.assertRaises(RuntimeError):g.memory_observation(cg,mt,lambda p:'1')
   self.assertNotIn('SECRET',json.dumps(d.snapshot()));self.assertTrue(d.valid(d.snapshot()))
  self.assertEqual(d.snapshot()['facts']['mount_v1_memory_records'],0)
  for value in [True,'1',2**63]:
   self.assertFalse(d.valid({'code':'cgroup_mapping','facts':{'mount_v2_records':value}}))
 def test_admission_source_unchanged_except_diagnostic_call(self):
  expected={'establish': '106c43fd3bb7333ac03e05f47ba46610a3c2c7f9c10e9fe7889c9364d3efd638', 'memory_observation': '5e54ab38069912f3fed0bed39af1143a6e10f1b1ccd783b351f358bad5f0a9eb', 'read_views': '8910ce874e2bea68c5195ac623df0b15200e7a204669f123cf058deacb519d56', 'validate_process': 'd874628306be3d185ec0433c86267561a71664580b9c2c521563c010c49f4dca', 'AttendedGuard': '209d32f64ac8783e3c60a89810815964414bff9e98924fe065d5a0e9966b98a0'}
  source=Path(g.__file__).read_text()
  diagnostic="    mark('cgroup_unified', **layout_counts(cgroup_text, mount_text))\n"
  dispatch="    from cgroup_v1 import membership, observe\n    if membership(cgroup_text) is not None:\n        mark('cgroup_unified', **layout_counts(cgroup_text, mount_text))\n        return observe(cgroup_text, mount_text)\n"
  self.assertEqual(source.count(dispatch),1)
  source=source.replace(dispatch,'')
  self.assertEqual(source.count(diagnostic),1)
  source=source.replace(diagnostic,'')
  nodes={n.name:n for n in ast.parse(source).body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
  for name,digest in expected.items():
   self.assertEqual(hashlib.sha256(ast.get_source_segment(source,nodes[name]).encode()).hexdigest(),digest,name)
