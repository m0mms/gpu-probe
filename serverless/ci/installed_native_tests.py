import ast,copy,hashlib,io,json,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
import native_diagnostics as d
from native_operations import OPERATIONS
from failure import failed,valid_failure
from receipt import accepted
import handler
ROOT=Path('/qualification')
BASE=Path(__file__).resolve().parent/'native_baseline'
sys.path.insert(0,str(ROOT/'package'))
import qualification as q
from test_qualification import SimulatedNative

class Tests(unittest.TestCase):
 def setUp(self):
  d.reset();SimulatedNative.fault=None;SimulatedNative.instances=[]
  self.config=dict(driver={},nvrtc={},device=0,compute=[8,9],driver_version=12000,nvrtc_version=[12,0])
 def probe(self,guard=lambda:None):return q.qualify(self.config,native_type=SimulatedNative,guard=guard)
 def payload(self):return dict(failed('native_qualification'),native=d.snapshot())
 def test_each_static_site_preserves_exception_and_bounded_schema(self):
  for site in OPERATIONS:
   d.reset();error=RuntimeError('SECRET')
   def fail():raise error
   with self.assertRaises(RuntimeError) as c:d.invoke(site,fail)
   self.assertIs(c.exception,error)
   self.assertEqual(d.snapshot()['first']['operation'],site)
   self.assertTrue(d.valid(d.snapshot()));self.assertNotIn('SECRET',json.dumps(d.snapshot()))
 def test_native_status_and_cleanup_do_not_replace_original(self):
  native=next(k for k,v in OPERATIONS.items() if v['native_status'] and not v['cleanup'])
  cleanup=next(k for k,v in OPERATIONS.items() if v['native_status'] and v['cleanup'])
  self.assertEqual(d.invoke(native,lambda:700),700)
  self.assertEqual(d.invoke(cleanup,lambda:201),201)
  s=d.snapshot();self.assertEqual(s['first']['status'],700);self.assertEqual(s['cleanup']['status'],201)
  self.assertTrue(d.valid(s));self.assertEqual(s['terminal']['operation'],cleanup)
  d.reset();self.assertEqual(d.invoke(native,lambda:2**50),2**50);self.assertIsNone(d.snapshot()['first']['status']);self.assertTrue(d.valid(d.snapshot()))
 def test_faults_distinguishable_and_never_accepted(self):
  first={}
  for fault in ['upload','download','launch','wrong_numeric','missing_tail','free','close','wrong_negative','negative_note','negative_leak','accepted_invalid']:
   d.reset();SimulatedNative.fault=fault;SimulatedNative.instances=[]
   with self.assertRaises(RuntimeError):self.probe()
   out=self.payload();self.assertTrue(valid_failure(out),fault)
   self.assertFalse(accepted(dict(id='j',status='COMPLETED',output=out),'j'))
   self.assertIsNotNone(out['native']['first']);first[fault]=out['native']['first']['operation']
   self.assertEqual(out['native']['phase'],'negative_control' if fault in ['wrong_negative','negative_note','negative_leak','accepted_invalid'] else 'positive')
  self.assertEqual(len({first[x] for x in ['upload','download','launch','free','close']}),5)
 def test_guard_integrity_and_reset(self):
  def denied():raise MemoryError('SECRET')
  with self.assertRaises(MemoryError):self.probe(denied)
  self.assertEqual(SimulatedNative.instances,[]);self.assertIn('.guard.',d.snapshot()['first']['operation'])
  d.reset()
  with patch.object(q,'digest',return_value='0'*64):
   with self.assertRaises(RuntimeError):self.probe()
  self.assertIn('.verify_package.',d.snapshot()['first']['operation'])
  d.reset();self.assertIsNone(d.snapshot()['first'])
 def test_handler_and_controller_sanitizer_preserve_finite_failure(self):
  SimulatedNative.fault='launch'
  with self.assertRaises(RuntimeError):self.probe()
  out=self.payload()
  with patch.object(handler.subprocess,'run',return_value=subprocess.CompletedProcess([],1,json.dumps(out).encode())):
   self.assertEqual(handler.execute(),out)
 def test_strict_schema(self):
  site=next(iter(OPERATIONS));d.invoke(site,lambda:None)
  valid=d.snapshot()
  for bad in [None,[],dict(valid,extra=1),dict(valid,phase=[]),dict(valid,phase='SECRET')]:self.assertFalse(d.valid(bad))
  for event in [[],{},dict(operation=[],kind='exception',status=None),dict(operation='SECRET',kind='exception',status=None),dict(operation=site,kind='exception',status=True),dict(operation=site,kind=[],status=None)]:
   bad=dict(valid,first=event,terminal=event);self.assertFalse(d.valid(bad))
  out=dict(failed('runtime_admission'),native=valid);self.assertFalse(valid_failure(out))
  out=dict(failed('native_qualification'),native=valid,admission={});self.assertFalse(valid_failure(out))
 def test_runner_channel_no_exception_or_logs(self):
  code="""import runner,native_diagnostics as d,os
from native_operations import OPERATIONS
def broken():
 runner.STAGE='native_qualification'
 d.reset()
 def fail():
  print('SECRET_LOG',flush=True)
  os.write(2,b'SECRET_STDERR')
  raise RuntimeError('SECRET_EXCEPTION')
 d.invoke(next(iter(OPERATIONS)),fail)
runner.run=broken
raise SystemExit(runner.main())
"""
  r=subprocess.run([sys.executable,'-B','-c',code],cwd=ROOT,capture_output=True,timeout=10)
  self.assertEqual(r.returncode,1);self.assertEqual(r.stderr,b'');self.assertNotIn(b'SECRET',r.stdout);self.assertTrue(valid_failure(json.loads(r.stdout)))
 def test_strip_diagnostics_restores_original_ast(self):
  class Strip(ast.NodeTransformer):
   def visit_Call(self,n):
    if isinstance(n.func,ast.Attribute) and isinstance(n.func.value,ast.Name) and n.func.value.id=='_nd':return self.visit(n.args[1] if n.func.attr=='raising' else n.args[1].body)
    return self.generic_visit(n)
  for name in ['qualification.py','native.py','runtime.py']:
   old=ast.parse((BASE/'package'/name).read_text());new=ast.parse((ROOT/'package'/name).read_text())
   new.body=new.body[1:]
   if name=='qualification.py':
    f=next(n for n in new.body if isinstance(n,ast.FunctionDef) and n.name=='qualify')
    f.body=[n for n in f.body if not (isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and n.value.func.attr=='negative_phase')]
   new=Strip().visit(new)
   self.assertEqual(ast.dump(new,include_attributes=False),ast.dump(old,include_attributes=False),name)
  for name in ['attended_guard.py','admission.py','cgroup_alias.py','package/host_guard.py','package/probe.cu','package/invalid.cu']:
   self.assertEqual((ROOT/name).read_bytes(),(BASE/name).read_bytes(),name)
 def test_diagnostic_copies_identical(self):
  for name in ['native_diagnostics.py','native_operations.py']:self.assertEqual((ROOT/name).read_bytes(),(ROOT/'package'/name).read_bytes())
 def test_call_labels_match_immediate_operation(self):
  for name in ['qualification.py','native.py','runtime.py']:
   tree=ast.parse((ROOT/'package'/name).read_text())
   for node in ast.walk(tree):
    if not (isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and isinstance(node.func.value,ast.Name) and node.func.value.id=='_nd' and node.func.attr=='invoke'):continue
    site=node.args[0].value;call=node.args[1].body
    self.assertIsInstance(call,ast.Call)
    actual=call.func.attr if isinstance(call.func,ast.Attribute) else call.func.id if isinstance(call.func,ast.Name) else 'call'
    self.assertEqual(site.rsplit('.',2)[1],actual,site)
 def test_real_chained_operation_faults(self):
  with self.assertRaises(FileNotFoundError):q.digest('/definitely-absent-cdma-native-diagnostic-file')
  self.assertEqual(d.snapshot()['first']['operation'],'qualification.digest.read_bytes.1')
  d.reset()
  class FakeHash:
   def hexdigest(self):raise RuntimeError('SECRET')
  with patch.object(q.hashlib,'sha256',return_value=FakeHash()):
   with self.assertRaises(RuntimeError):q.digest(__file__)
  self.assertEqual(d.snapshot()['first']['operation'],'qualification.digest.hexdigest.1')
 def test_actual_native_compile_then_destructor_failure(self):
  import native
  class Function:
   def __init__(self,name):self.name=name
   def __call__(self,*a):
    name=self.name
    values={'cuDriverGetVersion':12090,'cuDeviceGet':0,'cuCtxCreate_v2':1,'nvrtcCreateProgram':2,'nvrtcGetProgramLogSize':128}
    if name in values:a[0]._obj.value=values[name]
    elif name=='nvrtcVersion':a[0]._obj.value=12;a[1]._obj.value=9
    elif name=='cuDeviceGetAttribute':a[0]._obj.value=8 if a[1]==75 else 9
    elif name=='cuMemGetInfo_v2':a[0]._obj.value=8*2**30;a[1]._obj.value=8*2**30
    elif name=='nvrtcGetProgramLog':a[1].value=b'intentional_native_qualification_compile_failure'
    elif name=='nvrtcCompileProgram':return 6
    elif name=='nvrtcDestroyProgram':return 7
    return 0
  class Library:
   def __init__(self):self.functions={}
   def __getattr__(self,name):return self.functions.setdefault(name,Function(name))
  kernel=(ROOT/'package/invalid.cu').resolve()
  cfg=dict(self.config,kernel={'path':str(kernel),'sha256':hashlib.sha256(kernel.read_bytes()).hexdigest()},driver_version=12090,nvrtc_version=[12,9])
  # Real Native constructor/cleanup and ctypes shapes; only libraries/file admission simulated.
  with patch.object(native,'verify_file',return_value=kernel),patch.object(native.C,'CDLL',side_effect=lambda path:Library()):
   with self.assertRaises(RuntimeError):native.Native(cfg,lambda:None)
  s=d.snapshot();self.assertTrue(d.valid(s));self.assertEqual(s['first']['operation'],'native.Native.__init__.nvrtcCompileProgram.1');self.assertEqual(s['first']['status'],6)
  self.assertEqual(s['cleanup']['operation'],'native.Native.__init__.nvrtcDestroyProgram.1');self.assertEqual(s['cleanup']['status'],7)
