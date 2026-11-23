import copy,json,os,unittest
from pathlib import Path,PurePosixPath
from unittest.mock import patch
import cgroup_v1 as v
import attended_guard as g
import admission_diagnostics as d
from failure import failed,valid_failure
from receipt import accepted

G=2**30
CG='7:memory:/job\n0::/job'
M='32 22 0:28 / /sys/fs/cgroup/memory ro - cgroup cgroup rw,memory'

class View:
 data={};changes={};verify_error=False;entered=0;closed=0
 def __init__(self,matches,records,cg,mt):self.counts={}
 def __enter__(self):type(self).entered+=1;return self
 def __exit__(self,*args):type(self).closed+=1
 def verify(self):
  if self.verify_error:raise RuntimeError('identity or topology changed')
 def file(self,p):
  self.counts[p]=self.counts.get(p,0)+1
  if self.counts[p]>1 and p in self.changes:return self.changes[p]
  return self.data[p]

class Tests(unittest.TestCase):
 def setUp(self):
  d.reset();View.entered=View.closed=0;View.changes={};View.verify_error=False
  View.data={}
  for path,limit in [('/sys/fs/cgroup/memory/job',32*G),('/sys/fs/cgroup/memory',64*G)]:
   View.data.update({path+'/memory.limit_in_bytes':str(limit),path+'/memory.usage_in_bytes':'1',path+'/memory.use_hierarchy':'1',path+'/memory.stat':'cache 0\nhierarchical_memory_limit '+str(limit)+'\n'})
 def observe(self,cg=CG,m=M):return v.observe(cg,m,View)
 def test_finite_leaf_and_ancestor_ceiling(self):
  out=self.observe();self.assertEqual(out['effective_limit'],32*G);self.assertFalse(out['hidden_ancestors_verified']);self.assertEqual(len(out['visible_ancestors']),2);self.assertEqual(View.closed,1)
  View.data['/sys/fs/cgroup/memory/job/memory.stat']='hierarchical_memory_limit '+str(16*G)
  View.data['/sys/fs/cgroup/memory/memory.stat']='hierarchical_memory_limit '+str(16*G)
  self.assertEqual(self.observe()['effective_limit'],16*G)
 def test_namespaced_root_and_mount_subtree(self):
  # Slash may denote a namespaced leaf; no inference of global root or parents.
  out=self.observe('7:memory:/\n0::/',M);self.assertEqual(len(out['visible_ancestors']),1)
  out=self.observe(CG,M.replace('0:28 / /sys','0:28 /job /sys'));self.assertEqual(len(out['visible_ancestors']),1)
 def test_hierarchy_disabled_or_missing(self):
  for x in ('0','2','-1','max',''):
   View.data['/sys/fs/cgroup/memory/job/memory.use_hierarchy']=x
   with self.assertRaises((RuntimeError,MemoryError)):self.observe()
  del View.data['/sys/fs/cgroup/memory/job/memory.use_hierarchy']
  with self.assertRaises(KeyError):self.observe()
 def test_unlimited_leaf_not_rescued_by_parent(self):
  for raw in ('9223372036854771712',str(65*G),'0','-1','max',str(2**63)):
   View.data['/sys/fs/cgroup/memory/job/memory.limit_in_bytes']=raw
   View.data['/sys/fs/cgroup/memory/job/memory.stat']='hierarchical_memory_limit '+str(G)
   with self.assertRaises((RuntimeError,MemoryError)):self.observe()
 def test_boundary_and_parent_unlimited(self):
  leaf='/sys/fs/cgroup/memory/job';root='/sys/fs/cgroup/memory'
  for n in [leaf,root]:
   lim=64*G if n==leaf else 9223372036854771712
   View.data[n+'/memory.limit_in_bytes']=str(lim);View.data[n+'/memory.stat']='hierarchical_memory_limit '+str(lim)
  self.assertEqual(self.observe()['effective_limit'],64*G)
 def test_usage_over_effective_and_bad_numeric(self):
  for raw in (str(33*G),'-1','1.0','1\n2','+'+'1','1'*33):
   View.data['/sys/fs/cgroup/memory/job/memory.usage_in_bytes']=raw
   with self.assertRaises((RuntimeError,MemoryError)):self.observe()
 def test_stat_schema_and_inconsistent_hierarchy(self):
  key='/sys/fs/cgroup/memory/job/memory.stat'
  for text in ['cache 1','hierarchical_memory_limit 0','hierarchical_memory_limit 1\nhierarchical_memory_limit 2','hierarchical_memory_limit -1','hierarchical_memory_limit 1 2','x'* (v.BOUND+1),'hierarchical_memory_limit '+str(33*G)]:
   View.data[key]=text
   with self.assertRaises((RuntimeError,MemoryError)):self.observe()
  View.data[key]='hierarchical_memory_limit '+str(32*G)
  View.data['/sys/fs/cgroup/memory/memory.stat']='hierarchical_memory_limit '+str(16*G)
  with self.assertRaises(MemoryError):self.observe()
 def test_stability_and_identity_refuse_and_close(self):
  for suffix,raw in [('memory.limit_in_bytes',str(31*G)),('memory.use_hierarchy','0'),('memory.stat','hierarchical_memory_limit 1')]:
   View.changes={'/sys/fs/cgroup/memory/job/'+suffix:raw}
   with self.assertRaises(RuntimeError):self.observe()
  View.changes={};View.verify_error=True
  with self.assertRaises(RuntimeError):self.observe()
  self.assertEqual(View.entered,View.closed)
 def test_ambiguous_missing_and_wrong_controller_mounts(self):
  for mt in [M+'\n'+M,M+'\n'+M.replace('/sys/fs/cgroup/memory','/alias'),'',M.replace('rw,memory','rw,notmemory'),M.replace(' - cgroup ',' - cgroup2 '),M.replace('0:28','bad'),M.replace(' / /sys',' /outside /sys'),M.replace(' - ','\t-\t')]:
   with self.assertRaises(RuntimeError):self.observe(m=mt)
  self.assertEqual(View.entered,0)
 def test_membership_path_and_bounds(self):
  for cg in ['7:memory:/../job','7:memory:/job\\040x','7:memory:relative','7:memory:/a//b','7:memory:/job\n8:memory:/other','7:memory,memory:/job','0:memory:/job','bad',CG+'\n0::/','7:memory:/'+('x'*v.BOUND)]:
   with self.assertRaises(RuntimeError):self.observe(cg=cg)
  self.assertEqual(View.entered,0)
  self.assertIsNone(v.membership('0::/job'));self.assertIsNone(v.membership('7:cpu:/job\n0::/job'))
 def test_no_fallback_and_diagnostics_redaction(self):
  with patch.object(v,'observe',side_effect=MemoryError('SECRET')) as observe:
   with self.assertRaises(MemoryError):g.memory_observation(CG,M,lambda p: self.fail('v2 fallback forbidden'))
   observe.assert_called_once()
  View.data['/sys/fs/cgroup/memory/job/memory.limit_in_bytes']=str(65*G)
  with self.assertRaises(MemoryError):self.observe()
  out=dict(failed('runtime_admission'),admission=d.snapshot());self.assertTrue(valid_failure(out));self.assertNotIn('SECRET',json.dumps(out));self.assertNotIn('/sys',json.dumps(out));self.assertFalse(accepted(dict(id='j',status='COMPLETED',output=out),'j'))
 def test_view_file_allowlist_identity_flags_and_close(self):
  view=v.V1View.__new__(v.V1View);view.fds={'/safe':9};view.path_records={'/safe':('32',(0,28))}
  for name in v.FILES:
   with patch.object(v.os,'open',return_value=12) as op,patch.object(v.os,'close') as close,patch.object(view,'verify_fd') as verify,patch.object(v,'read_fd',return_value='1'):
    self.assertEqual(view.file('/safe/'+name),'1');self.assertEqual(op.call_args.kwargs,{'dir_fd':9});self.assertEqual(op.call_args.args[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC);verify.assert_called_once_with(12,('32',(0,28)));close.assert_called_once_with(12)
  with patch.object(v.os,'open') as op:
   with self.assertRaises(RuntimeError):view.file('/safe/memory.max')
   op.assert_not_called()
  with patch.object(v.os,'open',return_value=12),patch.object(v.os,'close') as close,patch.object(view,'verify_fd',side_effect=RuntimeError('wrong identity')):
   with self.assertRaises(RuntimeError):view.file('/safe/memory.stat')
   close.assert_called_once_with(12)
 def test_fd_identity_and_membership_verification_inherited_unchanged(self):
  from cgroup_alias import AliasView
  for name in ('verify_fd','verify','__enter__','close'):
   self.assertIs(getattr(v.V1View,name),getattr(AliasView,name))
 def test_visible_directory_bound(self):
  cg=PurePosixPath('/mount')/('/'.join(['x']*257))
  with self.assertRaises(RuntimeError):v.V1View([(cg,PurePosixPath('/mount'))],[('32',(0,28))],CG,M)
 def test_native_package_and_process_guards_unchanged(self):
  import hashlib
  root=Path(__file__).resolve().parent
  manifest=json.loads((root.parent/'ci/v1-invariants.json').read_text())
  for n,h in manifest.items():self.assertEqual(hashlib.sha256((root/n).read_bytes()).hexdigest(),h,n)
