"""Tiny synthetic CUDA qualification callable; no provisioning or launch CLI.

A separately approved supervisor must establish provider/estate admission first.
The injectable native type and guard exist for local simulation, not attestation.
"""
import ctypes as C
import hashlib
import json
from pathlib import Path
import platform

import numpy as np
from host_guard import HostGuard
from native import Native
from runtime import Runtime, require

HERE = Path(__file__).resolve().parent
MARKER = 'intentional_native_qualification_compile_failure'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def verify_package():
    # Integrity check, not an authorization/signature check. Supervisor pins freeze.
    manifest = json.loads((HERE / 'freeze.json').read_text())
    for name, expected in manifest.items():
        require(Path(name).name == name, 'flat package manifest required')
        require(digest(HERE / name) == expected, 'package hash mismatch')


def clean(backend):
    require(backend.ctx is None and backend.mod is None and not backend.alloc
            and not backend.cleanup_errors, 'native cleanup unresolved')


def qualify(config, *, native_type=Native, guard=None):
    """Return local evidence only; caller must not infer provider cleanup/admission.

    config has the existing Native configuration fields except kernel, which is
    always selected from this frozen package. No input arrays or source accepted.
    """
    verify_package()
    require(set(config) == {'driver', 'nvrtc', 'device', 'compute',
                            'driver_version', 'nvrtc_version'}, 'config fields')
    guard = HostGuard() if guard is None else guard
    guard()  # Fail before CUDA library loading on an inadmissible host.

    def bound(name):
        return dict(config, kernel={'path': str(HERE / name),
                                    'sha256': digest(HERE / name)})

    backend = native_type(bound('probe.cu'), guard)
    with Runtime(backend, guard) as runtime:
        values = np.arange(-128, 129, dtype=np.float64)
        input_pointer = runtime.upload(values)
        # NaNs detect missing writes, including the partial final block.
        output_pointer = runtime.upload(np.full(257, np.nan, dtype=np.float64))
        runtime.run('base', 3, [input_pointer, output_pointer, C.c_int(257)])
        result = runtime.get(output_pointer, 257)
        require(np.array_equal(result, 2 * values + 1), 'numeric comparison failed')
        runtime.release(0)
        require(not runtime.alloc and not backend.alloc, 'allocation release failed')
        peak = runtime.peak
        peak_device = runtime.peak_device
    clean(backend)

    # Retain the object to inspect constructor-failure cleanup, not just its error.
    failed = native_type.__new__(native_type)
    try:
        native_type.__init__(failed, bound('invalid.cu'), guard)
    except RuntimeError as error:
        require(str(error).startswith('NVRTC compile failed:') and MARKER in str(error),
                'unexpected negative-control failure')
        require(not getattr(error, '__notes__', []), 'negative-control cleanup note')
        clean(failed)
    else:
        # A compiler accepting the invalid input must still release its context.
        failed.close()
        raise RuntimeError('negative control unexpectedly compiled')

    return {
        'status': 'synthetic_callable_pass',
        'native_execution_claim': native_type is Native,
        'elements': 257, 'grid': 3, 'block': 128,
        'numeric_exact': True, 'compile_failure_control': True,
        'owned_context_cleanup': True,
        'tracked_gpu_peak_bytes': peak, 'sampled_device_peak_bytes': peak_device,
        'python': platform.python_version(), 'numpy': np.__version__,
        'package_freeze_sha256': digest(HERE / 'freeze.json'),
        'native_identity': ({
            'driver_sha256': config['driver']['sha256'],
            'nvrtc_sha256': config['nvrtc']['sha256'],
            'device_ordinal': config['device'], 'compute': config['compute'],
            'driver_version': config['driver_version'],
            'nvrtc_version': config['nvrtc_version'],
            'ptx_sha256': backend.fingerprint['ptx_sha256'],
            'compile_log_sha256': backend.fingerprint['compile_log_sha256'],
        } if native_type is Native else None),
        'provider_admission_verified': False,
        'external_process_cleanup_verified': False,
        'scientific_operator_qualified': False,
    }


if __name__ == '__main__':
    raise SystemExit('No standalone launch: separately reviewed supervisor required')
