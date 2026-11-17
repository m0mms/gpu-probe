import native_diagnostics as _nd
"""Tenant CUDA runtime lifecycle. No provisioning, credentials or launch entrypoint."""
import ctypes as C
import functools
import numpy as np
LIMIT=3758096384
RESERVE=268435456
KERNELS={'corrfeat','base','polyfeat','scalarfeat'}

def require(ok,message):
 if not ok:raise _nd.invoke('runtime.require.RuntimeError.1', lambda: (RuntimeError(message)))

def admit(size,tracked,free,total):
 _nd.invoke('runtime.admit.require.1', lambda: (require(_nd.invoke('runtime.admit.type.1', lambda: (type(size)))is int and size>0 and 0<=free<=total,'allocation schema')))
 if tracked+size>LIMIT-RESERVE or total-free+size+RESERVE>LIMIT or size+RESERVE>free:raise _nd.invoke('runtime.admit.MemoryError.1', lambda: (MemoryError('GPU allocation guard')))

def guarded(fn):
 @functools.wraps(fn)
 def call(self,*args,**kwargs):
  _nd.invoke('runtime.guarded.call.require.1', lambda: (require(not self.closed and not self.failed,'runtime closed or failed')))
  try:return _nd.invoke('runtime.guarded.call.fn.1', lambda: (fn(self,*args,**kwargs)))
  except BaseException as error:
   self.failed=True
   try:_nd.invoke('runtime.guarded.call.close.1', lambda: (self.close()))
   except BaseException as cleanup:_nd.invoke('runtime.guarded.call.add_note.1', lambda: (error.add_note('Cleanup unresolved: '+_nd.invoke('runtime.guarded.call.repr.1', lambda: (repr(cleanup))))))
   raise
 return call

class Runtime:
 def __init__(self,backend,host_guard):
  self.backend=backend;self.host_guard=host_guard;self.alloc=[];self.failed=False;self.closed=False;self.peak=0;self.peak_device=0;self.cleanup_errors=[]
  try:_nd.invoke('runtime.Runtime.__init__.audit.1', lambda: (self.audit()))
  except BaseException as error:
   self.failed=True
   try:_nd.invoke('runtime.Runtime.__init__.close.1', lambda: (self.close()))
   except BaseException as cleanup:_nd.invoke('runtime.Runtime.__init__.add_note.1', lambda: (error.add_note('Cleanup unresolved: '+_nd.invoke('runtime.Runtime.__init__.repr.1', lambda: (repr(cleanup))))))
   raise
 @guarded
 def audit(self):
  _nd.invoke('runtime.Runtime.audit.host_guard.1', lambda: (self.host_guard()));free,total=_nd.invoke('runtime.Runtime.audit.memory.1', lambda: (self.backend.memory()));tracked=_nd.invoke('runtime.Runtime.audit.sum.1', lambda: (sum(n for p,n in self.alloc)))
  _nd.invoke('runtime.Runtime.audit.require.1', lambda: (require(0<=free<=total and tracked<=LIMIT-RESERVE and total-free<=LIMIT,'GPU memory audit')))
  self.peak=_nd.invoke('runtime.Runtime.audit.max.1', lambda: (max(self.peak,tracked)));self.peak_device=_nd.invoke('runtime.Runtime.audit.max.2', lambda: (max(self.peak_device,total-free)))
 @guarded
 def upload(self,values):
  _nd.invoke('runtime.Runtime.upload.audit.1', lambda: (self.audit()));v=_nd.invoke('runtime.Runtime.upload.ascontiguousarray.1', lambda: (np.ascontiguousarray(values)))
  _nd.invoke('runtime.Runtime.upload.require.1', lambda: (require(v.dtype.kind in 'fciu' and not v.dtype.hasobject,'upload numeric dtype')))
  free,total=_nd.invoke('runtime.Runtime.upload.memory.1', lambda: (self.backend.memory()));_nd.invoke('runtime.Runtime.upload.admit.1', lambda: (admit(v.nbytes,_nd.invoke('runtime.Runtime.upload.sum.1', lambda: (sum(n for p,n in self.alloc))),free,total)))
  p=_nd.invoke('runtime.Runtime.upload.allocate.1', lambda: (self.backend.allocate(v.nbytes)));_nd.invoke('runtime.Runtime.upload.append.1', lambda: (self.alloc.append((p,v.nbytes))));_nd.invoke('runtime.Runtime.upload.copy_in.1', lambda: (self.backend.copy_in(p,v)));_nd.invoke('runtime.Runtime.upload.synchronize.1', lambda: (self.backend.synchronize()));_nd.invoke('runtime.Runtime.upload.audit.2', lambda: (self.audit()));return p
 @guarded
 def get(self,p,n):
  _nd.invoke('runtime.Runtime.get.require.1', lambda: (require(_nd.invoke('runtime.Runtime.get.type.1', lambda: (type(n)))is int and n>0,'download size')));address=p.value
  _nd.invoke('runtime.Runtime.get.require.2', lambda: (require(_nd.invoke('runtime.Runtime.get.any.1', lambda: (any(q.value<=address and address+8*n<=q.value+size for q,size in self.alloc))),'download allocation bounds')))
  _nd.invoke('runtime.Runtime.get.audit.1', lambda: (self.audit()));_nd.invoke('runtime.Runtime.get.synchronize.1', lambda: (self.backend.synchronize()));out=_nd.invoke('runtime.Runtime.get.empty.1', lambda: (np.empty(n,dtype=np.float64)));_nd.invoke('runtime.Runtime.get.copy_out.1', lambda: (self.backend.copy_out(out,p)));_nd.invoke('runtime.Runtime.get.synchronize.2', lambda: (self.backend.synchronize()));_nd.invoke('runtime.Runtime.get.audit.2', lambda: (self.audit()));return out
 @guarded
 def run(self,name,grid,args,block=128):
  _nd.invoke('runtime.Runtime.run.require.1', lambda: (require(name in KERNELS and _nd.invoke('runtime.Runtime.run.type.1', lambda: (type(grid)))is int and 0<grid<2**31 and block==128,'kernel launch schema')))
  _nd.invoke('runtime.Runtime.run.audit.1', lambda: (self.audit()));_nd.invoke('runtime.Runtime.run.launch.1', lambda: (self.backend.launch(name,grid,block,args)));_nd.invoke('runtime.Runtime.run.synchronize.1', lambda: (self.backend.synchronize()));_nd.invoke('runtime.Runtime.run.audit.2', lambda: (self.audit()))
 @guarded
 def release(self,mark):
  _nd.invoke('runtime.Runtime.release.require.1', lambda: (require(_nd.invoke('runtime.Runtime.release.type.1', lambda: (type(mark)))is int and 0<=mark<=_nd.invoke('runtime.Runtime.release.len.1', lambda: (len(self.alloc))),'release mark')));_nd.invoke('runtime.Runtime.release.synchronize.1', lambda: (self.backend.synchronize()))
  while _nd.invoke('runtime.Runtime.release.len.2', lambda: (len(self.alloc)))>mark:
   p,n=self.alloc[-1];_nd.invoke('runtime.Runtime.release.free.1', lambda: (self.backend.free(p)));_nd.invoke('runtime.Runtime.release.pop.1', lambda: (self.alloc.pop()))
  _nd.invoke('runtime.Runtime.release.audit.1', lambda: (self.audit()))
 def close(self):
  if self.closed:return
  try:_nd.invoke('runtime.Runtime.close.close.1', lambda: (self.backend.close()))
  except BaseException as error:
   self.failed=True;_nd.invoke('runtime.Runtime.close.append.1', lambda: (self.cleanup_errors.append(_nd.invoke('runtime.Runtime.close.repr.1', lambda: (repr(error))))));raise
  _nd.invoke('runtime.Runtime.close.clear.1', lambda: (self.alloc.clear()));self.closed=True
 def __enter__(self):return self
 def __exit__(self,kind,error,tb):
  try:_nd.invoke('runtime.Runtime.__exit__.close.1', lambda: (self.close()))
  except BaseException as cleanup:
   if error is None:raise
   _nd.invoke('runtime.Runtime.__exit__.add_note.1', lambda: (error.add_note('Cleanup unresolved: '+_nd.invoke('runtime.Runtime.__exit__.repr.1', lambda: (repr(cleanup))))))
  return False

def run_backend(*args,**kwargs):
 raise _nd.invoke('runtime.run_backend.RuntimeError.1', lambda: (RuntimeError('NOT RELEASED: no backend selected, admitted, runtime-fingerprinted or numerically qualified')))

