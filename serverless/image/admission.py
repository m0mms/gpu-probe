"""Bounded runtime observation, NOT provider admission or library provenance.

Only the installed, pinned NVRTC wheel and provider-injected driver are read.
No caller-supplied paths, source, commands, environment or secrets are accepted.
"""
import ctypes as C
import hashlib
from pathlib import Path
import sysconfig
from admission_diagnostics import mark, reset

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
    mark('driver_discovery')
    present = [Path(p).exists() for p in paths]
    mark('driver_discovery', driver_path_mask=sum(1 << i for i, v in enumerate(present) if v))
    resolved = {Path(p).resolve(strict=True) for p, exists in zip(paths, present) if exists}
    mark('driver_discovery', driver_resolved_count=len(resolved))
    if len(resolved) != 1:
        raise ValueError('one_driver_required')
    return resolved.pop()


def observe(guard):
    reset()
    mark('guard_before')
    guard()  # Before loading even the discovery libraries.
    path = driver_path()
    mark('driver_binding')
    driver = bound_file(path)
    mark('nvrtc_binding')
    nvrtc = bound_file(Path(sysconfig.get_paths()['purelib']) /
                       'nvidia/cuda_nvrtc/lib/libnvrtc.so.12')
    mark('driver_load')
    cu = C.CDLL(driver['path'])
    mark('nvrtc_load')
    nv = C.CDLL(nvrtc['path'])
    IP = C.POINTER(C.c_int)

    def call(code, lib, name, types, *args):
        mark(code)
        f = getattr(lib, name)
        f.argtypes, f.restype = types, C.c_int
        result = f(*args)
        mark(code, native_return=result)
        if result != 0:
            raise ValueError('native_observation_failed')

    call('cu_init', cu, 'cuInit', [C.c_uint], 0)
    count, device, version, major, minor, vm, vn = (C.c_int() for _ in range(7))
    call('device_count', cu, 'cuDeviceGetCount', [IP], C.byref(count))
    mark('one_device', device_count=count.value)
    if count.value != 1:
        raise ValueError('one_visible_device_required')
    call('device_select', cu, 'cuDeviceGet', [IP, C.c_int], C.byref(device), 0)
    call('driver_version', cu, 'cuDriverGetVersion', [IP], C.byref(version))
    for attribute, target in ((75, major), (76, minor)):
        call('compute_major' if attribute == 75 else 'compute_minor', cu, 'cuDeviceGetAttribute', [IP, C.c_int, C.c_int],
             C.byref(target), attribute, device)
    call('nvrtc_version', nv, 'nvrtcVersion', [IP, IP], C.byref(vm), C.byref(vn))
    # Locked NVRTC 12.9; select only a device covered by the CPU compile check.
    mark('runtime_compatibility', driver_version=version.value, nvrtc_major=vm.value, nvrtc_minor=vn.value, compute_major=major.value, compute_minor=minor.value)
    if version.value < 12090 or [vm.value, vn.value] != [12, 9] or [major.value, minor.value] != [8, 9]:
        raise ValueError('unsupported_runtime')
    mark('guard_after')
    guard()
    mark('admission_complete')
    return dict(driver=driver, nvrtc=nvrtc, device=0,
                compute=[major.value, minor.value], driver_version=version.value,
                nvrtc_version=[vm.value, vn.value])
