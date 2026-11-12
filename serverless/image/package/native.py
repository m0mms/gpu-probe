"""Portable native adapter draft, derived from registered gpu.py/gpu_runtime.py.
No library discovery, installation or default destination. No release entrypoint.
Native ABI, CUDA arithmetic and device behavior require backend qualification.
"""
import ctypes as C
import hashlib
from pathlib import Path
from runtime import Runtime,require

def sha(path):
 h=hashlib.sha256()
 with Path(path).open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()

def verify_file(item):
 p=Path(item['path'])
 require(p.is_absolute() and p.is_file() and str(p.resolve())==str(p),'explicit resolved file required')
 require(sha(p)==item['sha256'],'runtime file hash mismatch');return p

def bind(lib,name,args):
 f=getattr(lib,name);f.restype=C.c_int;f.argtypes=args;return f

class Native:
 def check(self,status):
  if status:raise RuntimeError('CUDA/NVRTC status '+str(status))
 def __init__(self,config,guard):
  self.ctx=None;self.mod=None;self.alloc={};self.cleanup_errors=[];self.fingerprint={};guard()
  require(set(config)=={'driver','nvrtc','kernel','device','compute','driver_version','nvrtc_version'},'native configuration fields')
  driver,nvrtc,kernel=(verify_file(config[k]) for k in ['driver','nvrtc','kernel'])
  require(type(config['device'])is int and config['device']>=0,'device index')
  self.cu=C.CDLL(str(driver));self.nv=C.CDLL(str(nvrtc));P=C.c_void_p;PP=C.POINTER(P);IP=C.POINTER(C.c_int);SP=C.POINTER(C.c_size_t);DP=C.POINTER(C.c_uint64)
  defs={'cuInit':[C.c_uint],'cuDriverGetVersion':[IP],'cuDeviceGet':[IP,C.c_int],'cuDeviceGetAttribute':[IP,C.c_int,C.c_int],'cuCtxCreate_v2':[PP,C.c_uint,C.c_int],'cuCtxDestroy_v2':[P],'cuCtxSynchronize':[],'cuMemGetInfo_v2':[SP,SP],'cuMemAlloc_v2':[DP,C.c_size_t],'cuMemFree_v2':[C.c_uint64],'cuMemcpyHtoD_v2':[C.c_uint64,P,C.c_size_t],'cuMemcpyDtoH_v2':[P,C.c_uint64,C.c_size_t],'cuModuleLoadData':[PP,P],'cuModuleGetFunction':[PP,P,C.c_char_p],'cuLaunchKernel':[P,C.c_uint,C.c_uint,C.c_uint,C.c_uint,C.c_uint,C.c_uint,C.c_uint,P,C.POINTER(P),C.POINTER(P)]}
  for name,args in defs.items():bind(self.cu,name,args)
  defs={'nvrtcVersion':[IP,IP],'nvrtcCreateProgram':[PP,C.c_char_p,C.c_char_p,C.c_int,C.POINTER(C.c_char_p),C.POINTER(C.c_char_p)],'nvrtcCompileProgram':[P,C.c_int,C.POINTER(C.c_char_p)],'nvrtcGetProgramLogSize':[P,SP],'nvrtcGetProgramLog':[P,P],'nvrtcGetPTXSize':[P,SP],'nvrtcGetPTX':[P,P],'nvrtcDestroyProgram':[PP]}
  for name,args in defs.items():bind(self.nv,name,args)
  try:
   self.check(self.cu.cuInit(0));dv=C.c_int();self.check(self.cu.cuDriverGetVersion(C.byref(dv)));vma=C.c_int();vmi=C.c_int();self.check(self.nv.nvrtcVersion(C.byref(vma),C.byref(vmi)))
   require(dv.value==config['driver_version'] and [vma.value,vmi.value]==config['nvrtc_version'],'driver/compiler version binding')
   device=C.c_int();self.check(self.cu.cuDeviceGet(C.byref(device),config['device']));ma=C.c_int();mi=C.c_int();self.check(self.cu.cuDeviceGetAttribute(C.byref(ma),75,device));self.check(self.cu.cuDeviceGetAttribute(C.byref(mi),76,device));require([ma.value,mi.value]==config['compute'],'compute capability binding')
   self.ctx=P();self.check(self.cu.cuCtxCreate_v2(C.byref(self.ctx),0,device));guard()
   # Check context/device charge before compilation as well as Runtime audits.
   from runtime import LIMIT
   free,total=self.memory();require(0<=free<=total and total-free<=LIMIT,'context device memory')
   source=kernel.read_bytes();require(hashlib.sha256(source).hexdigest()==config['kernel']['sha256'],'kernel changed before compile')
   prog=P();self.check(self.nv.nvrtcCreateProgram(C.byref(prog),source,b'kernel.cu',0,None,None))
   try:
    options=(C.c_char_p*1)(f'--gpu-architecture=compute_{ma.value}{mi.value}'.encode());status=self.nv.nvrtcCompileProgram(prog,1,options);size=C.c_size_t();self.check(self.nv.nvrtcGetProgramLogSize(prog,C.byref(size)));log=C.create_string_buffer(size.value);self.check(self.nv.nvrtcGetProgramLog(prog,log))
    if status:raise RuntimeError('NVRTC compile failed: '+log.value.decode(errors='replace'))
    self.check(self.nv.nvrtcGetPTXSize(prog,C.byref(size)));ptx=C.create_string_buffer(size.value);self.check(self.nv.nvrtcGetPTX(prog,ptx));self.mod=P();self.check(self.cu.cuModuleLoadData(C.byref(self.mod),ptx));guard()
    self.fingerprint=dict(config=config,ptx_sha256=hashlib.sha256(ptx.raw).hexdigest(),compile_log_sha256=hashlib.sha256(log.raw).hexdigest())
   finally:self.check(self.nv.nvrtcDestroyProgram(C.byref(prog)))
  except BaseException as error:
   try:self.close()
   except BaseException as cleanup:error.add_note('Native cleanup unresolved: '+repr(cleanup))
   raise
 def memory(self):
  free=C.c_size_t();total=C.c_size_t();self.check(self.cu.cuMemGetInfo_v2(C.byref(free),C.byref(total)));return free.value,total.value
 def allocate(self,size):
  p=C.c_uint64();self.check(self.cu.cuMemAlloc_v2(C.byref(p),size));self.alloc[p.value]=p;return p
 def free(self,p):self.check(self.cu.cuMemFree_v2(p));del self.alloc[p.value]
 def copy_in(self,p,v):self.check(self.cu.cuMemcpyHtoD_v2(p,C.c_void_p(v.ctypes.data),v.nbytes))
 def copy_out(self,v,p):self.check(self.cu.cuMemcpyDtoH_v2(C.c_void_p(v.ctypes.data),p,v.nbytes))
 def synchronize(self):self.check(self.cu.cuCtxSynchronize())
 def launch(self,name,grid,block,args):
  fn=C.c_void_p();self.check(self.cu.cuModuleGetFunction(C.byref(fn),self.mod,name.encode()));params=(C.c_void_p*len(args))(*[C.cast(C.pointer(x),C.c_void_p) for x in args]);self.check(self.cu.cuLaunchKernel(fn,grid,1,1,block,1,1,0,None,params,None))
 def close(self):
  if self.ctx is None:return
  errors=[]
  try:self.synchronize()
  except BaseException as e:errors.append(repr(e))
  for p in list(self.alloc.values()):
   try:self.free(p)
   except BaseException as e:errors.append(repr(e))
  try:
   self.check(self.cu.cuCtxDestroy_v2(self.ctx));self.ctx=None;self.mod=None;self.alloc.clear()
  except BaseException as e:errors.append(repr(e))
  self.cleanup_errors.extend(errors)
  if errors:raise RuntimeError('Native cleanup errors: '+repr(errors))

def _create_runtime(config,guard):
 """Private future worker seam; public launch remains disabled in runtime.py."""
 backend=Native(config,guard)
 return Runtime(backend,guard)
