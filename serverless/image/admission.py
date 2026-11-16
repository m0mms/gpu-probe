"""Bounded runtime observation, NOT provider admission or library provenance.

Only the installed, pinned NVRTC wheel and provider-injected driver are read.
No caller-supplied paths, source, commands, environment or secrets are accepted.
"""
import ctypes as C
import hashlib
from pathlib import Path
import sysconfig

DRIVERS = ('/usr/lib/x86_64-linux-gnu/libcuda.so.1',
           '/lib/x86_64-linux-gnu/libcuda.so.1',
           '/usr/local/nvidia/lib64/libcuda.so.1')


def bound_file(path):
    p = Path(path).resolve(strict=True)
    if not p.is_absolute() or not p.is_file():
        raise ValueError('library_file')
    h = hashlib.sha256()
    with p.open('rb') as f:
        for chunk in iter(lambda: f.read(1048576), b''):
            h.update(chunk)
    return {'path': str(p), 'sha256': h.hexdigest()}


def driver_path(paths=DRIVERS):
    resolved = {Path(p).resolve(strict=True) for p in paths if Path(p).exists()}
    if len(resolved) != 1:
        raise ValueError('one_driver_required')
    return resolved.pop()


def observe(guard):
    guard()  # Before loading even the discovery libraries.
    driver = bound_file(driver_path())
    nvrtc = bound_file(Path(sysconfig.get_paths()['purelib']) /
                       'nvidia/cuda_nvrtc/lib/libnvrtc.so.12')
    cu, nv = C.CDLL(driver['path']), C.CDLL(nvrtc['path'])
    IP = C.POINTER(C.c_int)

    def call(lib, name, types, *args):
        f = getattr(lib, name)
        f.argtypes, f.restype = types, C.c_int
        if f(*args) != 0:
            raise ValueError('native_observation_failed')

    call(cu, 'cuInit', [C.c_uint], 0)
    count, device, version, major, minor, vm, vn = (C.c_int() for _ in range(7))
    call(cu, 'cuDeviceGetCount', [IP], C.byref(count))
    if count.value != 1:
        raise ValueError('one_visible_device_required')
    call(cu, 'cuDeviceGet', [IP, C.c_int], C.byref(device), 0)
    call(cu, 'cuDriverGetVersion', [IP], C.byref(version))
    for attribute, target in ((75, major), (76, minor)):
        call(cu, 'cuDeviceGetAttribute', [IP, C.c_int, C.c_int],
             C.byref(target), attribute, device)
    call(nv, 'nvrtcVersion', [IP, IP], C.byref(vm), C.byref(vn))
    # Locked NVRTC 12.9; select only a device covered by the CPU compile check.
    if version.value < 12090 or [vm.value, vn.value] != [12, 9] or [major.value, minor.value] != [8, 9]:
        raise ValueError('unsupported_runtime')
    guard()
    return dict(driver=driver, nvrtc=nvrtc, device=0,
                compute=[major.value, minor.value], driver_version=version.value,
                nvrtc_version=[vm.value, vn.value])
