import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
import admission as a
import attended_guard as g
import admission_diagnostics as d
from failure import failed, valid_failure
from receipt import accepted
import handler
import subprocess

MOUNT='1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw'
GIB=2**30

class Tests(unittest.TestCase):
 def setUp(self):d.reset()
 def assert_code(self, code):self.assertEqual(d.snapshot()['code'],code)
 def test_cgroup_refusal_paths(self):
  cases=[('','',{},'cgroup_unified'),('0::/../x',MOUNT,{},'cgroup_path'),
   ('0::/',MOUNT.replace('/sys/fs/cgroup','/bad\\040mount'),{},'cgroup_mount'),
   ('0::/',MOUNT+'\n'+MOUNT,{},'cgroup_mapping'),('0::/','',{},'cgroup_mapping'),
   ('0::/',MOUNT,{'memory.max':OSError()},'memory_max_read'),
   ('0::/',MOUNT,{'memory.max':'bad'},'memory_max_parse'),
   ('0::/',MOUNT,{'memory.current':OSError()},'memory_current_read'),
   ('0::/',MOUNT,{'memory.current':'bad'},'memory_current_parse'),
   ('0::/',MOUNT,{'memory.current':'-1'},'memory_observation'),
   ('0::/',MOUNT,{'memory.max':'0'},'memory_observation'),
   ('0::/',MOUNT,{'memory.max':'1','memory.current':'2'},'memory_observation'),
   ('0::/',MOUNT,{'memory.max':'max'},'memory_ceiling'),
   ('0::/',MOUNT,{'memory.max':str(65*GIB)},'memory_ceiling')]
  for cg,mount,overrides,code in cases:
   with self.subTest(code=code,overrides=overrides):
    d.reset()
    def read(path):
     key=Path(path).name;v=overrides.get(key,str(64*GIB) if key=='memory.max' else '1')
     if isinstance(v,Exception):raise v
     return v
    with self.assertRaises((RuntimeError,ValueError,MemoryError,OSError)):g.memory_observation(cg,mount,read)
    self.assert_code(code)
  self.assertEqual(g.memory_observation('0::/',MOUNT,lambda p:str(64*GIB) if p.endswith('max') else '1')['effective_limit'],64*GIB)
 def test_process_limits_unchanged(self):
  env={k:'3' for k in g.ENV_KEYS}
  for args,code in [((7*GIB,1,(48*GIB,48*GIB),env),'process_rss'),
    ((1,1,(49*GIB,49*GIB),env),'process_as'),((1,4,(48*GIB,48*GIB),env),'process_threads'),
    ((1,1,(48*GIB,48*GIB),{}),'process_environment')]:
   with self.assertRaises((MemoryError,RuntimeError)):g.validate_process(*args)
   self.assert_code(code)
  g.validate_process(6*GIB,3,(48*GIB,48*GIB),env)
 def test_proc_and_limits_failure_paths(self):
  base={'/proc/self/cgroup':'0::/','/proc/self/mountinfo':MOUNT,
        '/sys/fs/cgroup/memory.max':str(8*GIB),'/sys/fs/cgroup/memory.current':'1',
        '/proc/self/status':'VmRSS: 1 kB\nThreads: 1'}
  cases=[('/proc/self/cgroup',OSError(),'cgroup_read'),('/proc/self/mountinfo',OSError(),'mount_read'),
         ('/proc/self/status',OSError(),'status_read'),('/proc/self/status','Threads: 1','rss_parse'),
         ('/proc/self/status','VmRSS: 1 kB\nThreads: bad','threads_parse')]
  for key,value,code in cases:
   def read(path):
    v=value if str(path)==key else base[str(path)]
    if isinstance(v,Exception):raise v
    return v
   with patch.object(g.sys,'platform','linux'),patch.object(g.Path,'read_text',read):
    with self.assertRaises((OSError,ValueError,KeyError)):g.AttendedGuard()()
    self.assert_code(code)
  with patch.object(g.sys,'platform','not-linux'):
   with self.assertRaises(RuntimeError):g.AttendedGuard()()
   self.assert_code('platform')
  with patch.object(g.sys,'platform','linux'),patch.object(g.Path,'read_text',lambda p:base[str(p)]),patch.object(g.resource,'getrlimit',side_effect=OSError()):
   with self.assertRaises(OSError):g.AttendedGuard()()
   self.assert_code('limits_read')
 def test_driver_missing_ambiguous_and_binding(self):
  with tempfile.TemporaryDirectory() as temp:
   p=Path(temp);one=p/'one';two=p/'two';one.write_bytes(b'a');two.write_bytes(b'b')
   for paths,count in [([],0),([one,two],2)]:
    with self.assertRaises(ValueError):a.driver_path(paths)
    self.assert_code('driver_discovery');self.assertEqual(d.snapshot()['facts']['driver_resolved_count'],count)
   self.assertEqual(a.driver_path([one]),one.resolve())
 def fake_libraries(self, fail=None, versions=None):
  values={'count':1,'driver':12090,'major':8,'minor':6,'vm':12,'vn':9};values.update(versions or {})
  cu=Mock();nv=Mock();order=[]
  def call(name,*args):
   order.append(name)
   if name==fail:return 999
   if name=='cuDeviceGetCount':args[0]._obj.value=values['count']
   if name=='cuDeviceGet':args[0]._obj.value=0
   if name=='cuDriverGetVersion':args[0]._obj.value=values['driver']
   if name=='cuDeviceGetAttribute':args[0]._obj.value=values['major' if args[1]==75 else 'minor']
   if name=='nvrtcVersion':args[0]._obj.value=values['vm'];args[1]._obj.value=values['vn']
   return 0
  for name in ['cuInit','cuDeviceGetCount','cuDeviceGet','cuDriverGetVersion','cuDeviceGetAttribute']:
   getattr(cu,name).side_effect=lambda *args,n=name:call(n,*args)
  nv.nvrtcVersion.side_effect=lambda *args:call('nvrtcVersion',*args)
  return cu,nv,order
 def observe_with(self, guard=None, libs=None, bind=None):
  with patch.object(a,'driver_path',return_value=Path('/fixed')),patch.object(a,'bound_file',side_effect=bind,return_value={'path':'/fixed','sha256':'a'*64}),patch.object(a.C,'CDLL',side_effect=libs):
   return a.observe(guard or Mock())
 def test_binding_and_loading_failures_stop(self):
  for index,code in [(0,'driver_binding'),(1,'nvrtc_binding')]:
   seq=[{'path':'/fixed','sha256':'a'*64}]*index+[OSError('SECRET')]
   with self.assertRaises(OSError):self.observe_with(bind=seq,libs=AssertionError('must not load'))
   self.assert_code(code)
  for seq,code in [([OSError('SECRET')],'driver_load'),([Mock(),OSError('SECRET')],'nvrtc_load')]:
   with self.assertRaises(OSError):self.observe_with(libs=seq)
   self.assert_code(code)
 def test_each_native_call_return_failure(self):
  pairs=[('cuInit','cu_init'),('cuDeviceGetCount','device_count'),('cuDeviceGet','device_select'),('cuDriverGetVersion','driver_version'),('cuDeviceGetAttribute','compute_major'),('nvrtcVersion','nvrtc_version')]
  for name,code in pairs:
   cu,nv,order=self.fake_libraries(fail=name)
   with self.assertRaises(ValueError):self.observe_with(libs=[cu,nv])
   self.assert_code(code);self.assertEqual(order[-1],name);self.assertEqual(d.snapshot()['facts']['native_return'],999)
  cu,nv,order=self.fake_libraries();cu.cuDeviceGetAttribute.side_effect=[0,999]
  with self.assertRaises(ValueError):self.observe_with(libs=[cu,nv])
  self.assert_code('compute_minor')
 def test_missing_native_symbol(self):
  cu=object()
  with self.assertRaises(AttributeError):self.observe_with(libs=[cu,Mock()])
  self.assert_code('cu_init')
 def test_compatibility_and_both_guards(self):
  for values,code in [({'count':2},'one_device'),({'driver':12080},'runtime_compatibility'),({'vm':11},'runtime_compatibility'),({'vn':8},'runtime_compatibility'),({'major':9},'runtime_compatibility'),({'minor':8},'runtime_compatibility')]:
   cu,nv,_=self.fake_libraries(versions=values)
   with self.assertRaises(ValueError):self.observe_with(libs=[cu,nv])
   self.assert_code(code)
  for seq,code in [([MemoryError('SECRET')],'guard_before'),([None,MemoryError('SECRET')],'guard_after')]:
   cu,nv,_=self.fake_libraries()
   with self.assertRaises(MemoryError):self.observe_with(guard=Mock(side_effect=seq),libs=[cu,nv])
   self.assert_code(code)
  cu,nv,_=self.fake_libraries();guard=Mock();out=self.observe_with(guard=guard,libs=[cu,nv])
  self.assertEqual(out['compute'],[8,6]);self.assertEqual(guard.call_count,2);self.assert_code('admission_complete')
 def test_strict_end_to_end_failure_schema(self):
  d.mark('runtime_compatibility',driver_version=12080,secret='SECRET',rss=True,threads=2**80)
  output=dict(failed('runtime_admission'),admission=d.snapshot())
  self.assertTrue(valid_failure(output));self.assertNotIn('SECRET',json.dumps(output));self.assertLess(len(json.dumps(output)),2048)
  self.assertFalse(accepted({'id':'j','status':'COMPLETED','output':output},'j'))
  with patch.object(handler.subprocess,'run',return_value=subprocess.CompletedProcess([],1,json.dumps(output).encode())):
   self.assertEqual(handler.execute(),output)
  for bad in [{'code':'SECRET','facts':{}},{'code':'driver_load','facts':{'path':'SECRET'}},{'code':'driver_load','facts':{'rss':True}},{'code':'driver_load','facts':{'rss':2**80}}]:
   self.assertFalse(valid_failure(dict(output,admission=bad)))
  self.assertFalse(valid_failure(dict(output,stage='native_qualification')))

if __name__=='__main__':unittest.main()
