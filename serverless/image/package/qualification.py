import native_diagnostics as _nd
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
    return _nd.invoke('qualification.digest.hexdigest.1', lambda: (_nd.invoke('qualification.digest.sha256.1', lambda: (hashlib.sha256(_nd.invoke('qualification.digest.read_bytes.1', lambda: (_nd.invoke('qualification.digest.Path.1', lambda: (Path(path))).read_bytes()))))).hexdigest()))


def verify_package():
    # Integrity check, not an authorization/signature check. Supervisor pins freeze.
    manifest = _nd.invoke('qualification.verify_package.loads.1', lambda: (json.loads(_nd.invoke('qualification.verify_package.read_text.1', lambda: ((HERE / 'freeze.json').read_text())))))
    for name, expected in _nd.invoke('qualification.verify_package.items.1', lambda: (manifest.items())):
        _nd.invoke('qualification.verify_package.require.1', lambda: (require(_nd.invoke('qualification.verify_package.Path.1', lambda: (Path(name))).name == name, 'flat package manifest required')))
        _nd.invoke('qualification.verify_package.require.2', lambda: (require(_nd.invoke('qualification.verify_package.digest.1', lambda: (digest(HERE / name))) == expected, 'package hash mismatch')))


def clean(backend):
    _nd.invoke('qualification.clean.require.1', lambda: (require(backend.ctx is None and backend.mod is None and not backend.alloc
            and not backend.cleanup_errors, 'native cleanup unresolved')))


def qualify(config, *, native_type=Native, guard=None):
    """Return local evidence only; caller must not infer provider cleanup/admission.

    config has the existing Native configuration fields except kernel, which is
    always selected from this frozen package. No input arrays or source accepted.
    """
    _nd.invoke('qualification.qualify.verify_package.1', lambda: (verify_package()))
    _nd.invoke('qualification.qualify.require.1', lambda: (require(_nd.invoke('qualification.qualify.set.1', lambda: (set(config))) == {'driver', 'nvrtc', 'device', 'compute',
                            'driver_version', 'nvrtc_version'}, 'config fields')))
    guard = _nd.invoke('qualification.qualify.HostGuard.1', lambda: (HostGuard())) if guard is None else guard
    _nd.invoke('qualification.qualify.guard.1', lambda: (guard()))  # Fail before CUDA library loading on an inadmissible host.

    def bound(name):
        return _nd.invoke('qualification.qualify.bound.dict.1', lambda: (dict(config, kernel={'path': _nd.invoke('qualification.qualify.bound.str.1', lambda: (str(HERE / name))),
                                    'sha256': _nd.invoke('qualification.qualify.bound.digest.1', lambda: (digest(HERE / name)))})))

    backend = _nd.invoke('qualification.qualify.native_type.1', lambda: (native_type(_nd.invoke('qualification.qualify.bound.1', lambda: (bound('probe.cu'))), guard)))
    with _nd.invoke('qualification.qualify.Runtime.1', lambda: (Runtime(backend, guard))) as runtime:
        values = _nd.invoke('qualification.qualify.arange.1', lambda: (np.arange(-128, 129, dtype=np.float64)))
        input_pointer = _nd.invoke('qualification.qualify.upload.1', lambda: (runtime.upload(values)))
        # NaNs detect missing writes, including the partial final block.
        output_pointer = _nd.invoke('qualification.qualify.upload.2', lambda: (runtime.upload(_nd.invoke('qualification.qualify.full.1', lambda: (np.full(257, np.nan, dtype=np.float64))))))
        _nd.invoke('qualification.qualify.run.1', lambda: (runtime.run('base', 3, [input_pointer, output_pointer, _nd.invoke('qualification.qualify.c_int.1', lambda: (C.c_int(257)))])))
        result = _nd.invoke('qualification.qualify.get.1', lambda: (runtime.get(output_pointer, 257)))
        _nd.invoke('qualification.qualify.require.2', lambda: (require(_nd.invoke('qualification.qualify.array_equal.1', lambda: (np.array_equal(result, 2 * values + 1))), 'numeric comparison failed')))
        _nd.invoke('qualification.qualify.release.1', lambda: (runtime.release(0)))
        _nd.invoke('qualification.qualify.require.3', lambda: (require(not runtime.alloc and not backend.alloc, 'allocation release failed')))
        peak = runtime.peak
        peak_device = runtime.peak_device
    _nd.invoke('qualification.qualify.clean.1', lambda: (clean(backend)))

    # Retain the object to inspect constructor-failure cleanup, not just its error.
    _nd.negative_phase()
    failed = _nd.invoke('qualification.qualify.__new__.1', lambda: (native_type.__new__(native_type)))
    try:
        _nd.invoke('qualification.qualify.__init__.1', lambda: (native_type.__init__(failed, _nd.invoke('qualification.qualify.bound.2', lambda: (bound('invalid.cu'))), guard)))
    except RuntimeError as error:
        _nd.invoke('qualification.qualify.require.4', lambda: (require(_nd.invoke('qualification.qualify.startswith.1', lambda: (_nd.invoke('qualification.qualify.str.1', lambda: (str(error))).startswith('NVRTC compile failed:'))) and MARKER in _nd.invoke('qualification.qualify.str.2', lambda: (str(error))),
                'unexpected negative-control failure')))
        _nd.invoke('qualification.qualify.require.5', lambda: (require(not _nd.invoke('qualification.qualify.getattr.1', lambda: (getattr(error, '__notes__', []))), 'negative-control cleanup note')))
        _nd.invoke('qualification.qualify.clean.2', lambda: (clean(failed)))
    else:
        # A compiler accepting the invalid input must still release its context.
        _nd.invoke('qualification.qualify.close.1', lambda: (failed.close()))
        raise _nd.raising('qualification.qualify.negative_unexpected_success', _nd.invoke('qualification.qualify.RuntimeError.1', lambda: (RuntimeError('negative control unexpectedly compiled'))))

    return {
        'status': 'synthetic_callable_pass',
        'native_execution_claim': native_type is Native,
        'elements': 257, 'grid': 3, 'block': 128,
        'numeric_exact': True, 'compile_failure_control': True,
        'owned_context_cleanup': True,
        'tracked_gpu_peak_bytes': peak, 'sampled_device_peak_bytes': peak_device,
        'python': _nd.invoke('qualification.qualify.python_version.1', lambda: (platform.python_version())), 'numpy': np.__version__,
        'package_freeze_sha256': _nd.invoke('qualification.qualify.digest.1', lambda: (digest(HERE / 'freeze.json'))),
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

