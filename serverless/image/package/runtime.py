"""Tenant CUDA runtime lifecycle. No provisioning, credentials or launch entrypoint."""
import ctypes as C
import functools
import numpy as np
LIMIT=3758096384
RESERVE=268435456
KERNELS={'corrfeat','base','polyfeat','scalarfeat'}

def require(ok,message):
 if not ok:raise RuntimeError(message)

def admit(size,tracked,free,total):
 require(type(size)is int and size>0 and 0<=free<=total,'allocation schema')
 if tracked+size>LIMIT-RESERVE or total-free+size+RESERVE>LIMIT or size+RESERVE>free:raise MemoryError('GPU allocation guard')

def guarded(fn):
 @functools.wraps(fn)
 def call(self,*args,**kwargs):
  require(not self.closed and not self.failed,'runtime closed or failed')
  try:return fn(self,*args,**kwargs)
  except BaseException as error:
   self.failed=True
   try:self.close()
   except BaseException as cleanup:error.add_note('Cleanup unresolved: '+repr(cleanup))
   raise
 return call

class Runtime:
 def __init__(self,backend,host_guard):
  self.backend=backend;self.host_guard=host_guard;self.alloc=[];self.failed=False;self.closed=False;self.peak=0;self.peak_device=0;self.cleanup_errors=[]
  try:self.audit()
  except BaseException as error:
   self.failed=True
   try:self.close()
   except BaseException as cleanup:error.add_note('Cleanup unresolved: '+repr(cleanup))
   raise
 @guarded
 def audit(self):
  self.host_guard();free,total=self.backend.memory();tracked=sum(n for p,n in self.alloc)
  require(0<=free<=total and tracked<=LIMIT-RESERVE and total-free<=LIMIT,'GPU memory audit')
  self.peak=max(self.peak,tracked);self.peak_device=max(self.peak_device,total-free)
 @guarded
 def upload(self,values):
  self.audit();v=np.ascontiguousarray(values)
  require(v.dtype.kind in 'fciu' and not v.dtype.hasobject,'upload numeric dtype')
  free,total=self.backend.memory();admit(v.nbytes,sum(n for p,n in self.alloc),free,total)
  p=self.backend.allocate(v.nbytes);self.alloc.append((p,v.nbytes));self.backend.copy_in(p,v);self.backend.synchronize();self.audit();return p
 @guarded
 def get(self,p,n):
  require(type(n)is int and n>0,'download size');address=p.value
  require(any(q.value<=address and address+8*n<=q.value+size for q,size in self.alloc),'download allocation bounds')
  self.audit();self.backend.synchronize();out=np.empty(n,dtype=np.float64);self.backend.copy_out(out,p);self.backend.synchronize();self.audit();return out
 @guarded
 def run(self,name,grid,args,block=128):
  require(name in KERNELS and type(grid)is int and 0<grid<2**31 and block==128,'kernel launch schema')
  self.audit();self.backend.launch(name,grid,block,args);self.backend.synchronize();self.audit()
 @guarded
 def release(self,mark):
  require(type(mark)is int and 0<=mark<=len(self.alloc),'release mark');self.backend.synchronize()
  while len(self.alloc)>mark:
   p,n=self.alloc[-1];self.backend.free(p);self.alloc.pop()
  self.audit()
 def close(self):
  if self.closed:return
  try:self.backend.close()
  except BaseException as error:
   self.failed=True;self.cleanup_errors.append(repr(error));raise
  self.alloc.clear();self.closed=True
 def __enter__(self):return self
 def __exit__(self,kind,error,tb):
  try:self.close()
  except BaseException as cleanup:
   if error is None:raise
   error.add_note('Cleanup unresolved: '+repr(cleanup))
  return False

def run_backend(*args,**kwargs):
 raise RuntimeError('NOT RELEASED: no backend selected, admitted, runtime-fingerprinted or numerically qualified')
