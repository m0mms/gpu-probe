"""Full installed SDK with transport mocked; CPU-only NVRTC compilation."""
import asyncio,contextlib,ctypes as C,importlib.metadata,io,json,os,sys
from pathlib import Path
from unittest.mock import AsyncMock,patch
sys.path.insert(0,'/qualification')

def require(value):
    if not value:raise ValueError('installed_check_failed')

def check():
    import runpod
    import runpod.serverless as serverless
    from runpod.serverless.modules import rp_job
    import bootstrap,handler
    from numpy import arange,float64
    require(importlib.metadata.version('runpod')=='2.2.1')
    require(importlib.metadata.version('numpy')=='2.2.6')
    require(importlib.metadata.version('nvidia-cuda-nvrtc-cu12')=='12.9.86')
    require(arange(-128,129,dtype=float64).size==257)
    with patch.object(sys,'argv',['bootstrap.py']),patch.dict(os.environ,{'RUNPOD_REALTIME_PORT':'0'}),patch.object(serverless.worker,'main') as worker:
        require(bootstrap.main()==0)
    cfg=worker.call_args.args[0]
    require(not cfg['rp_args']['rp_debugger'] and not cfg['rp_args']['rp_serve_api'])
    require(cfg['handler'] is handler.handler)
    receipts=[]
    for fail in [False,True]:
        handler.USED=False
        receipt={'status':'synthetic_native_pass','elements':257,'numeric_exact':True,'negative_compile_control':True,'owned_context_cleanup':True,'provider_cleanup_verified':False,'scientific_operator_qualified':False}
        with patch.object(handler,'execute',side_effect=RuntimeError('synthetic-private-detail') if fail else None,return_value=receipt),patch.object(rp_job,'send_result',new_callable=AsyncMock) as send:
            out=asyncio.run(rp_job.handle_job(None,cfg,{'id':'offline-check','input':handler.REQUEST}))
            send.assert_awaited_once()
        require(out=={'output':({'status':'synthetic_native_fail','reason':'qualification_failed'} if fail else receipt)})
        receipts.append(True)
    import sysconfig
    nvpath=Path(sysconfig.get_paths()['purelib'])/'nvidia/cuda_nvrtc/lib/libnvrtc.so.12'
    nv=C.CDLL(str(nvpath));P=C.c_void_p;I=C.c_int;S=C.c_size_t
    defs={'nvrtcVersion':[C.POINTER(I),C.POINTER(I)],'nvrtcCreateProgram':[C.POINTER(P),C.c_char_p,C.c_char_p,I,C.POINTER(C.c_char_p),C.POINTER(C.c_char_p)],'nvrtcCompileProgram':[P,I,C.POINTER(C.c_char_p)],'nvrtcGetPTXSize':[P,C.POINTER(S)],'nvrtcGetPTX':[P,P],'nvrtcGetProgramLogSize':[P,C.POINTER(S)],'nvrtcGetProgramLog':[P,P],'nvrtcDestroyProgram':[C.POINTER(P)]}
    for name,args in defs.items():f=getattr(nv,name);f.argtypes=args;f.restype=I
    major=I();minor=I();require(nv.nvrtcVersion(C.byref(major),C.byref(minor))==0);require((major.value,minor.value)==(12,9))
    for name,bad in [('probe.cu',False),('invalid.cu',True)]:
        program=P();source=(Path('/qualification/package')/name).read_bytes()
        require(nv.nvrtcCreateProgram(C.byref(program),source,name.encode(),0,None,None)==0)
        try:
            opts=(C.c_char_p*1)(b'--gpu-architecture=compute_89');code=nv.nvrtcCompileProgram(program,1,opts)
            if bad:
                require(code!=0);size=S();require(nv.nvrtcGetProgramLogSize(program,C.byref(size))==0);require(0<size.value<65536)
                log=C.create_string_buffer(size.value);require(nv.nvrtcGetProgramLog(program,log)==0);require(b'intentional_native_qualification_compile_failure' in log.value)
            else:
                require(code==0);size=S();require(nv.nvrtcGetPTXSize(program,C.byref(size))==0);require(0<size.value<1048576)
                ptx=C.create_string_buffer(size.value);require(nv.nvrtcGetPTX(program,ptx)==0);require(b'.entry base' in ptx.value or b'.entry	base' in ptx.value)
        finally:require(nv.nvrtcDestroyProgram(C.byref(program))==0)
    return {'sdk_installed_checks':True,'nvrtc_compile_and_negative_control':True,'gpu_execution':False,'provider_contact':False}
if __name__=='__main__':
    fd=os.dup(1)
    with open(os.devnull,'wb') as sink:os.dup2(sink.fileno(),1);os.dup2(sink.fileno(),2)
    try:result=check();code=0
    except BaseException:result={'passed':False,'stage':'installed_sdk_or_nvrtc','gpu_execution':False};code=1
    os.write(fd,(json.dumps(result)+'\n').encode());os.close(fd);raise SystemExit(code)
