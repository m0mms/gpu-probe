import native_diagnostics as _nd
"""Portable native adapter draft, derived from registered gpu.py/gpu_runtime.py.
No library discovery, installation or default destination. No release entrypoint.
Native ABI, CUDA arithmetic and device behavior require backend qualification.
"""
import ctypes as C
import hashlib
from pathlib import Path
from runtime import Runtime,require

def sha(path):
 h=_nd.invoke('native.sha.sha256.1', lambda: (hashlib.sha256()))
 with _nd.invoke('native.sha.open.1', lambda: (_nd.invoke('native.sha.Path.1', lambda: (Path(path))).open('rb'))) as f:
  for b in _nd.invoke('native.sha.iter.1', lambda: (iter(lambda:_nd.invoke('native.sha.read.1', lambda: (f.read(1<<20))),b''))):_nd.invoke('native.sha.update.1', lambda: (h.update(b)))
 return _nd.invoke('native.sha.hexdigest.1', lambda: (h.hexdigest()))

def verify_file(item):
 p=_nd.invoke('native.verify_file.Path.1', lambda: (Path(item['path'])))
 _nd.invoke('native.verify_file.require.1', lambda: (require(_nd.invoke('native.verify_file.is_absolute.1', lambda: (p.is_absolute())) and _nd.invoke('native.verify_file.is_file.1', lambda: (p.is_file())) and _nd.invoke('native.verify_file.str.1', lambda: (str(_nd.invoke('native.verify_file.resolve.1', lambda: (p.resolve())))))==_nd.invoke('native.verify_file.str.2', lambda: (str(p))),'explicit resolved file required')))
 _nd.invoke('native.verify_file.require.2', lambda: (require(_nd.invoke('native.verify_file.sha.1', lambda: (sha(p)))==item['sha256'],'runtime file hash mismatch')));return p

def bind(lib,name,args):
 f=_nd.invoke('native.bind.getattr.1', lambda: (getattr(lib,name)));f.restype=C.c_int;f.argtypes=args;return f

class Native:
 def check(self,status):
  if status:raise _nd.invoke('native.Native.check.RuntimeError.1', lambda: (RuntimeError('CUDA/NVRTC status '+_nd.invoke('native.Native.check.str.1', lambda: (str(status))))))
 def __init__(self,config,guard):
  self.ctx=None;self.mod=None;self.alloc={};self.cleanup_errors=[];self.fingerprint={};_nd.invoke('native.Native.__init__.guard.1', lambda: (guard()))
  _nd.invoke('native.Native.__init__.require.1', lambda: (require(_nd.invoke('native.Native.__init__.set.1', lambda: (set(config)))=={'driver','nvrtc','kernel','device','compute','driver_version','nvrtc_version'},'native configuration fields')))
  driver,nvrtc,kernel=(_nd.invoke('native.Native.__init__.verify_file.1', lambda: (verify_file(config[k]))) for k in ['driver','nvrtc','kernel'])
  _nd.invoke('native.Native.__init__.require.2', lambda: (require(_nd.invoke('native.Native.__init__.type.1', lambda: (type(config['device'])))is int and config['device']>=0,'device index')))
  self.cu=_nd.invoke('native.Native.__init__.CDLL.1', lambda: (C.CDLL(_nd.invoke('native.Native.__init__.str.1', lambda: (str(driver))))));self.nv=_nd.invoke('native.Native.__init__.CDLL.2', lambda: (C.CDLL(_nd.invoke('native.Native.__init__.str.2', lambda: (str(nvrtc))))));P=C.c_void_p;PP=_nd.invoke('native.Native.__init__.POINTER.1', lambda: (C.POINTER(P)));IP=_nd.invoke('native.Native.__init__.POINTER.2', lambda: (C.POINTER(C.c_int)));SP=_nd.invoke('native.Native.__init__.POINTER.3', lambda: (C.POINTER(C.c_size_t)));DP=_nd.invoke('native.Native.__init__.POINTER.4', lambda: (C.POINTER(C.c_uint64)))
  defs={'cuInit':[C.c_uint],'cuDriverGetVersion':[IP],'cuDeviceGet':[IP,C.c_int],'cuDeviceGetAttribute':[IP,C.c_int,C.c_int],'cuCtxCreate_v2':[PP,C.c_uint,C.c_int],'cuCtxDestroy_v2':[P],'cuCtxSynchronize':[],'cuMemGetInfo_v2':[SP,SP],'cuMemAlloc_v2':[DP,C.c_size_t],'cuMemFree_v2':[C.c_uint64],'cuMemcpyHtoD_v2':[C.c_uint64,P,C.c_size_t],'cuMemcpyDtoH_v2':[P,C.c_uint64,C.c_size_t],'cuModuleLoadData':[PP,P],'cuModuleGetFunction':[PP,P,C.c_char_p],'cuLaunchKernel':[P,C.c_uint,C.c_uint,C.c_uint,C.c_uint,C.c_uint,C.c_uint,C.c_uint,P,_nd.invoke('native.Native.__init__.POINTER.5', lambda: (C.POINTER(P))),_nd.invoke('native.Native.__init__.POINTER.6', lambda: (C.POINTER(P)))]}
  for name,args in _nd.invoke('native.Native.__init__.items.1', lambda: (defs.items())):_nd.invoke('native.Native.__init__.bind.1', lambda: (bind(self.cu,name,args)))
  defs={'nvrtcVersion':[IP,IP],'nvrtcCreateProgram':[PP,C.c_char_p,C.c_char_p,C.c_int,_nd.invoke('native.Native.__init__.POINTER.7', lambda: (C.POINTER(C.c_char_p))),_nd.invoke('native.Native.__init__.POINTER.8', lambda: (C.POINTER(C.c_char_p)))],'nvrtcCompileProgram':[P,C.c_int,_nd.invoke('native.Native.__init__.POINTER.9', lambda: (C.POINTER(C.c_char_p)))],'nvrtcGetProgramLogSize':[P,SP],'nvrtcGetProgramLog':[P,P],'nvrtcGetPTXSize':[P,SP],'nvrtcGetPTX':[P,P],'nvrtcDestroyProgram':[PP]}
  for name,args in _nd.invoke('native.Native.__init__.items.2', lambda: (defs.items())):_nd.invoke('native.Native.__init__.bind.2', lambda: (bind(self.nv,name,args)))
  try:
   _nd.invoke('native.Native.__init__.check.1', lambda: (self.check(_nd.invoke('native.Native.__init__.cuInit.1', lambda: (self.cu.cuInit(0))))));dv=_nd.invoke('native.Native.__init__.c_int.1', lambda: (C.c_int()));_nd.invoke('native.Native.__init__.check.2', lambda: (self.check(_nd.invoke('native.Native.__init__.cuDriverGetVersion.1', lambda: (self.cu.cuDriverGetVersion(_nd.invoke('native.Native.__init__.byref.1', lambda: (C.byref(dv)))))))));vma=_nd.invoke('native.Native.__init__.c_int.2', lambda: (C.c_int()));vmi=_nd.invoke('native.Native.__init__.c_int.3', lambda: (C.c_int()));_nd.invoke('native.Native.__init__.check.3', lambda: (self.check(_nd.invoke('native.Native.__init__.nvrtcVersion.1', lambda: (self.nv.nvrtcVersion(_nd.invoke('native.Native.__init__.byref.2', lambda: (C.byref(vma))),_nd.invoke('native.Native.__init__.byref.3', lambda: (C.byref(vmi)))))))))
   _nd.invoke('native.Native.__init__.require.3', lambda: (require(dv.value==config['driver_version'] and [vma.value,vmi.value]==config['nvrtc_version'],'driver/compiler version binding')))
   device=_nd.invoke('native.Native.__init__.c_int.4', lambda: (C.c_int()));_nd.invoke('native.Native.__init__.check.4', lambda: (self.check(_nd.invoke('native.Native.__init__.cuDeviceGet.1', lambda: (self.cu.cuDeviceGet(_nd.invoke('native.Native.__init__.byref.4', lambda: (C.byref(device))),config['device']))))));ma=_nd.invoke('native.Native.__init__.c_int.5', lambda: (C.c_int()));mi=_nd.invoke('native.Native.__init__.c_int.6', lambda: (C.c_int()));_nd.invoke('native.Native.__init__.check.5', lambda: (self.check(_nd.invoke('native.Native.__init__.cuDeviceGetAttribute.1', lambda: (self.cu.cuDeviceGetAttribute(_nd.invoke('native.Native.__init__.byref.5', lambda: (C.byref(ma))),75,device))))));_nd.invoke('native.Native.__init__.check.6', lambda: (self.check(_nd.invoke('native.Native.__init__.cuDeviceGetAttribute.2', lambda: (self.cu.cuDeviceGetAttribute(_nd.invoke('native.Native.__init__.byref.6', lambda: (C.byref(mi))),76,device))))));_nd.invoke('native.Native.__init__.require.4', lambda: (require([ma.value,mi.value]==config['compute'],'compute capability binding')))
   self.ctx=_nd.invoke('native.Native.__init__.P.1', lambda: (P()));_nd.invoke('native.Native.__init__.check.7', lambda: (self.check(_nd.invoke('native.Native.__init__.cuCtxCreate_v2.1', lambda: (self.cu.cuCtxCreate_v2(_nd.invoke('native.Native.__init__.byref.7', lambda: (C.byref(self.ctx))),0,device))))));_nd.invoke('native.Native.__init__.guard.2', lambda: (guard()))
   # Check context/device charge before compilation as well as Runtime audits.
   from runtime import LIMIT
   free,total=_nd.invoke('native.Native.__init__.memory.1', lambda: (self.memory()));_nd.invoke('native.Native.__init__.require.5', lambda: (require(0<=free<=total and total-free<=LIMIT,'context device memory')))
   source=_nd.invoke('native.Native.__init__.read_bytes.1', lambda: (kernel.read_bytes()));_nd.invoke('native.Native.__init__.require.6', lambda: (require(_nd.invoke('native.Native.__init__.hexdigest.1', lambda: (_nd.invoke('native.Native.__init__.sha256.1', lambda: (hashlib.sha256(source))).hexdigest()))==config['kernel']['sha256'],'kernel changed before compile')))
   prog=_nd.invoke('native.Native.__init__.P.2', lambda: (P()));_nd.invoke('native.Native.__init__.check.8', lambda: (self.check(_nd.invoke('native.Native.__init__.nvrtcCreateProgram.1', lambda: (self.nv.nvrtcCreateProgram(_nd.invoke('native.Native.__init__.byref.8', lambda: (C.byref(prog))),source,b'kernel.cu',0,None,None))))))
   try:
    options=_nd.invoke('native.Native.__init__.call.1', lambda: ((C.c_char_p*1)(_nd.invoke('native.Native.__init__.encode.1', lambda: (f'--gpu-architecture=compute_{ma.value}{mi.value}'.encode())))));status=_nd.invoke('native.Native.__init__.nvrtcCompileProgram.1', lambda: (self.nv.nvrtcCompileProgram(prog,1,options)));size=_nd.invoke('native.Native.__init__.c_size_t.1', lambda: (C.c_size_t()));_nd.invoke('native.Native.__init__.check.9', lambda: (self.check(_nd.invoke('native.Native.__init__.nvrtcGetProgramLogSize.1', lambda: (self.nv.nvrtcGetProgramLogSize(prog,_nd.invoke('native.Native.__init__.byref.9', lambda: (C.byref(size)))))))));log=_nd.invoke('native.Native.__init__.create_string_buffer.1', lambda: (C.create_string_buffer(size.value)));_nd.invoke('native.Native.__init__.check.10', lambda: (self.check(_nd.invoke('native.Native.__init__.nvrtcGetProgramLog.1', lambda: (self.nv.nvrtcGetProgramLog(prog,log))))))
    if status:raise _nd.invoke('native.Native.__init__.RuntimeError.1', lambda: (RuntimeError('NVRTC compile failed: '+_nd.invoke('native.Native.__init__.decode.1', lambda: (log.value.decode(errors='replace'))))))
    _nd.invoke('native.Native.__init__.check.11', lambda: (self.check(_nd.invoke('native.Native.__init__.nvrtcGetPTXSize.1', lambda: (self.nv.nvrtcGetPTXSize(prog,_nd.invoke('native.Native.__init__.byref.10', lambda: (C.byref(size)))))))));ptx=_nd.invoke('native.Native.__init__.create_string_buffer.2', lambda: (C.create_string_buffer(size.value)));_nd.invoke('native.Native.__init__.check.12', lambda: (self.check(_nd.invoke('native.Native.__init__.nvrtcGetPTX.1', lambda: (self.nv.nvrtcGetPTX(prog,ptx))))));self.mod=_nd.invoke('native.Native.__init__.P.3', lambda: (P()));_nd.invoke('native.Native.__init__.check.13', lambda: (self.check(_nd.invoke('native.Native.__init__.cuModuleLoadData.1', lambda: (self.cu.cuModuleLoadData(_nd.invoke('native.Native.__init__.byref.11', lambda: (C.byref(self.mod))),ptx))))));_nd.invoke('native.Native.__init__.guard.3', lambda: (guard()))
    self.fingerprint=_nd.invoke('native.Native.__init__.dict.1', lambda: (dict(config=config,ptx_sha256=_nd.invoke('native.Native.__init__.hexdigest.2', lambda: (_nd.invoke('native.Native.__init__.sha256.2', lambda: (hashlib.sha256(ptx.raw))).hexdigest())),compile_log_sha256=_nd.invoke('native.Native.__init__.hexdigest.3', lambda: (_nd.invoke('native.Native.__init__.sha256.3', lambda: (hashlib.sha256(log.raw))).hexdigest())))))
   finally:_nd.invoke('native.Native.__init__.check.14', lambda: (self.check(_nd.invoke('native.Native.__init__.nvrtcDestroyProgram.1', lambda: (self.nv.nvrtcDestroyProgram(_nd.invoke('native.Native.__init__.byref.12', lambda: (C.byref(prog)))))))))
  except BaseException as error:
   try:_nd.invoke('native.Native.__init__.close.1', lambda: (self.close()))
   except BaseException as cleanup:_nd.invoke('native.Native.__init__.add_note.1', lambda: (error.add_note('Native cleanup unresolved: '+_nd.invoke('native.Native.__init__.repr.1', lambda: (repr(cleanup))))))
   raise
 def memory(self):
  free=_nd.invoke('native.Native.memory.c_size_t.1', lambda: (C.c_size_t()));total=_nd.invoke('native.Native.memory.c_size_t.2', lambda: (C.c_size_t()));_nd.invoke('native.Native.memory.check.1', lambda: (self.check(_nd.invoke('native.Native.memory.cuMemGetInfo_v2.1', lambda: (self.cu.cuMemGetInfo_v2(_nd.invoke('native.Native.memory.byref.1', lambda: (C.byref(free))),_nd.invoke('native.Native.memory.byref.2', lambda: (C.byref(total)))))))));return free.value,total.value
 def allocate(self,size):
  p=_nd.invoke('native.Native.allocate.c_uint64.1', lambda: (C.c_uint64()));_nd.invoke('native.Native.allocate.check.1', lambda: (self.check(_nd.invoke('native.Native.allocate.cuMemAlloc_v2.1', lambda: (self.cu.cuMemAlloc_v2(_nd.invoke('native.Native.allocate.byref.1', lambda: (C.byref(p))),size))))));self.alloc[p.value]=p;return p
 def free(self,p):_nd.invoke('native.Native.free.check.1', lambda: (self.check(_nd.invoke('native.Native.free.cuMemFree_v2.1', lambda: (self.cu.cuMemFree_v2(p))))));del self.alloc[p.value]
 def copy_in(self,p,v):_nd.invoke('native.Native.copy_in.check.1', lambda: (self.check(_nd.invoke('native.Native.copy_in.cuMemcpyHtoD_v2.1', lambda: (self.cu.cuMemcpyHtoD_v2(p,_nd.invoke('native.Native.copy_in.c_void_p.1', lambda: (C.c_void_p(v.ctypes.data))),v.nbytes))))))
 def copy_out(self,v,p):_nd.invoke('native.Native.copy_out.check.1', lambda: (self.check(_nd.invoke('native.Native.copy_out.cuMemcpyDtoH_v2.1', lambda: (self.cu.cuMemcpyDtoH_v2(_nd.invoke('native.Native.copy_out.c_void_p.1', lambda: (C.c_void_p(v.ctypes.data))),p,v.nbytes))))))
 def synchronize(self):_nd.invoke('native.Native.synchronize.check.1', lambda: (self.check(_nd.invoke('native.Native.synchronize.cuCtxSynchronize.1', lambda: (self.cu.cuCtxSynchronize())))))
 def launch(self,name,grid,block,args):
  fn=_nd.invoke('native.Native.launch.c_void_p.1', lambda: (C.c_void_p()));_nd.invoke('native.Native.launch.check.1', lambda: (self.check(_nd.invoke('native.Native.launch.cuModuleGetFunction.1', lambda: (self.cu.cuModuleGetFunction(_nd.invoke('native.Native.launch.byref.1', lambda: (C.byref(fn))),self.mod,_nd.invoke('native.Native.launch.encode.1', lambda: (name.encode()))))))));params=_nd.invoke('native.Native.launch.call.1', lambda: ((C.c_void_p*_nd.invoke('native.Native.launch.len.1', lambda: (len(args))))(*[_nd.invoke('native.Native.launch.cast.1', lambda: (C.cast(_nd.invoke('native.Native.launch.pointer.1', lambda: (C.pointer(x))),C.c_void_p))) for x in args])));_nd.invoke('native.Native.launch.check.2', lambda: (self.check(_nd.invoke('native.Native.launch.cuLaunchKernel.1', lambda: (self.cu.cuLaunchKernel(fn,grid,1,1,block,1,1,0,None,params,None))))))
 def close(self):
  if self.ctx is None:return
  errors=[]
  try:_nd.invoke('native.Native.close.synchronize.1', lambda: (self.synchronize()))
  except BaseException as e:_nd.invoke('native.Native.close.append.1', lambda: (errors.append(_nd.invoke('native.Native.close.repr.1', lambda: (repr(e))))))
  for p in _nd.invoke('native.Native.close.list.1', lambda: (list(_nd.invoke('native.Native.close.values.1', lambda: (self.alloc.values()))))):
   try:_nd.invoke('native.Native.close.free.1', lambda: (self.free(p)))
   except BaseException as e:_nd.invoke('native.Native.close.append.2', lambda: (errors.append(_nd.invoke('native.Native.close.repr.2', lambda: (repr(e))))))
  try:
   _nd.invoke('native.Native.close.check.1', lambda: (self.check(_nd.invoke('native.Native.close.cuCtxDestroy_v2.1', lambda: (self.cu.cuCtxDestroy_v2(self.ctx))))));self.ctx=None;self.mod=None;_nd.invoke('native.Native.close.clear.1', lambda: (self.alloc.clear()))
  except BaseException as e:_nd.invoke('native.Native.close.append.3', lambda: (errors.append(_nd.invoke('native.Native.close.repr.3', lambda: (repr(e))))))
  _nd.invoke('native.Native.close.extend.1', lambda: (self.cleanup_errors.extend(errors)))
  if errors:raise _nd.invoke('native.Native.close.RuntimeError.1', lambda: (RuntimeError('Native cleanup errors: '+_nd.invoke('native.Native.close.repr.4', lambda: (repr(errors))))))

def _create_runtime(config,guard):
 """Private future worker seam; public launch remains disabled in runtime.py."""
 backend=_nd.invoke('native._create_runtime.Native.1', lambda: (Native(config,guard)))
 return _nd.invoke('native._create_runtime.Runtime.1', lambda: (Runtime(backend,guard)))

