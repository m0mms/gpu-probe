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
 def test_hybrid_still_refuses_before_memory_reads(self):
  d.reset()
  def forbidden(p):raise AssertionError('no guessed memory path')
  with self.assertRaises(RuntimeError):g.memory_observation('7:memory:/job\n0::/job',V1,forbidden)
  out=dict(failed('runtime_admission'),admission=d.snapshot())
  self.assertEqual(out['admission']['code'],'cgroup_mapping')
  self.assertEqual(out['admission']['facts']['mount_v1_memory_records'],1)
  self.assertTrue(valid_failure(out));self.assertFalse(accepted({'id':'j','status':'COMPLETED','output':out},'j'))
 def test_privacy_and_counter_reset(self):
  d.reset();g.layout_counts('7:memory:/SECRET',V1.replace('/sys/fs/cgroup/memory','/SECRET'))
  for cg,mt in [('7:memory:/SECRET\n0::/SECRET',V1),('0::/','')]:
   with self.assertRaises(RuntimeError):g.memory_observation(cg,mt,lambda p:'1')
   self.assertNotIn('SECRET',json.dumps(d.snapshot()));self.assertTrue(d.valid(d.snapshot()))
  self.assertEqual(d.snapshot()['facts']['mount_v1_memory_records'],0)
  for value in [True,'1',2**63]:
   self.assertFalse(d.valid({'code':'cgroup_mapping','facts':{'mount_v2_records':value}}))
 def test_admission_ast_unchanged_except_diagnostic_call(self):
  expected={'establish': '5a26d25f49d9eab80d6f14cee22149792da4ebb21ce3304175d3309b4bad0776', 'memory_observation': '48e07cee7199cd6b8dd89227a0430f754f328489b84ffc058a00cc778a4b999e', 'read_views': '0f3b355284eedfee849812dcce342dc2f266f7e7999481e8c0a2545b45043e63', 'validate_process': 'a78768e0b5b53d2b182e2a48825aa660e82b14f724cd88ca4d7c1a75d9e00f08', 'AttendedGuard': '14a105a794cf449a07d00f9bb69414fbdb999f360e43c8f520b7088dd194d572'}
  new=ast.parse(Path(g.__file__).read_text())
  newnodes={n.name:n for n in new.body if isinstance(n,(ast.FunctionDef,ast.ClassDef))}
  node=copy.deepcopy(newnodes['memory_observation']);node.body=[n for n in node.body if not (isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and any(isinstance(k.value,ast.Call) and isinstance(k.value.func,ast.Name) and k.value.func.id=='layout_counts' for k in n.value.keywords))]
  newnodes['memory_observation']=node
  for name,digest in expected.items():self.assertEqual(hashlib.sha256(ast.dump(newnodes[name]).encode()).hexdigest(),digest,name)
