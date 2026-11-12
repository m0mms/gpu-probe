"""Local lifecycle simulation. Never loads CUDA or claims native arithmetic."""
import ctypes as C
import unittest
from unittest.mock import patch

import numpy as np
import qualification as q


class SimulatedNative:
    fault = None
    instances = []

    def __init__(self, config, guard):
        self.ctx = 1
        self.mod = 2
        self.alloc = {}
        self.cleanup_errors = []
        self.next = 4096
        self.calls = []
        self.instances.append(self)
        guard()
        if config['kernel']['path'].endswith('invalid.cu'):
            if self.fault == 'accepted_invalid':
                return
            self.close()
            if self.fault == 'wrong_negative':
                raise RuntimeError('unrelated failure')
            error = RuntimeError('NVRTC compile failed: ' + q.MARKER)
            if self.fault == 'negative_note':
                error.add_note('cleanup unresolved')
            if self.fault == 'negative_leak':
                self.ctx = 1
            raise error

    def memory(self):
        return 8 * 2**30 - sum(v.nbytes for v in self.alloc.values()), 8 * 2**30

    def allocate(self, size):
        pointer = C.c_uint64(self.next)
        self.next += size + 64
        self.alloc[pointer.value] = np.empty(size // 8, dtype=np.float64)
        return pointer

    def copy_in(self, pointer, values):
        if self.fault == 'upload':
            raise RuntimeError('upload failed')
        self.alloc[pointer.value][:] = values

    def copy_out(self, values, pointer):
        if self.fault == 'download':
            raise RuntimeError('download failed')
        values[:] = self.alloc[pointer.value]

    def synchronize(self):
        self.calls.append('sync')

    def launch(self, name, grid, block, args):
        if self.fault == 'launch':
            raise RuntimeError('launch failed')
        if self.fault == 'interrupt':
            raise KeyboardInterrupt()
        if (name, grid, block, args[2].value) != ('base', 3, 128, 257):
            raise RuntimeError('unexpected launch contract')
        source, destination = (self.alloc[p.value] for p in args[:2])
        if self.fault == 'missing_tail':
            destination[:256] = 2 * source[:256] + 1
        else:
            destination[:] = 2 * source + 1
        if self.fault == 'wrong_numeric':
            destination[0] += 1

    def free(self, pointer):
        if self.fault == 'free':
            raise RuntimeError('free failed')
        del self.alloc[pointer.value]

    def close(self):
        self.calls.append('close')
        if self.fault == 'close':
            self.cleanup_errors.append('destroy failed')
            raise RuntimeError('destroy failed')
        self.alloc.clear()
        self.ctx = self.mod = None


class QualificationTests(unittest.TestCase):
    def setUp(self):
        SimulatedNative.fault = None
        SimulatedNative.instances = []
        self.config = dict(driver={}, nvrtc={}, device=0, compute=[8, 9],
                           driver_version=12000, nvrtc_version=[12, 0])

    def run_probe(self):
        return q.qualify(self.config, native_type=SimulatedNative, guard=lambda: None)

    def test_success_and_no_native_claim(self):
        result = self.run_probe()
        self.assertEqual(result['tracked_gpu_peak_bytes'], 2 * 257 * 8)
        self.assertFalse(result['native_execution_claim'])
        self.assertFalse(result['provider_admission_verified'])
        self.assertFalse(result['external_process_cleanup_verified'])
        self.assertFalse(result['scientific_operator_qualified'])
        self.assertEqual(len(SimulatedNative.instances), 2)
        for instance in SimulatedNative.instances:
            q.clean(instance)
            self.assertEqual(instance.calls.count('close'), 1)

    def test_guard_refuses_before_constructor(self):
        def refuse():
            raise MemoryError('host denied')
        with self.assertRaises(MemoryError):
            q.qualify(self.config, native_type=SimulatedNative, guard=refuse)
        self.assertEqual(SimulatedNative.instances, [])

    def test_frozen_file_change_refuses_before_constructor(self):
        with patch.object(q, 'digest', return_value='0' * 64):
            with self.assertRaisesRegex(RuntimeError, 'package hash mismatch'):
                self.run_probe()
        self.assertEqual(SimulatedNative.instances, [])

    def test_external_kernel_override_refused(self):
        self.config['kernel'] = {'path': '/unapproved'}
        with self.assertRaisesRegex(RuntimeError, 'config fields'):
            self.run_probe()
        self.assertEqual(SimulatedNative.instances, [])

    def test_numeric_and_transfer_faults_close_context(self):
        for fault in ['wrong_numeric', 'missing_tail', 'upload', 'download', 'launch', 'free']:
            with self.subTest(fault=fault):
                SimulatedNative.fault = fault
                SimulatedNative.instances = []
                with self.assertRaises(RuntimeError):
                    self.run_probe()
                self.assertEqual(len(SimulatedNative.instances), 1)
                q.clean(SimulatedNative.instances[0])

    def test_interrupt_closes_context(self):
        SimulatedNative.fault = 'interrupt'
        with self.assertRaises(KeyboardInterrupt):
            self.run_probe()
        q.clean(SimulatedNative.instances[0])

    def test_cleanup_failure_not_success(self):
        SimulatedNative.fault = 'close'
        with self.assertRaisesRegex(RuntimeError, 'destroy failed'):
            self.run_probe()
        self.assertEqual(len(SimulatedNative.instances), 1)
        self.assertTrue(SimulatedNative.instances[0].cleanup_errors)

    def test_negative_control_rejects_unrelated_error_note_and_leak(self):
        for fault in ['wrong_negative', 'negative_note', 'negative_leak']:
            with self.subTest(fault=fault):
                SimulatedNative.fault = fault
                with self.assertRaises(RuntimeError):
                    self.run_probe()

    def test_unexpected_compile_success_is_closed_and_rejected(self):
        SimulatedNative.fault = 'accepted_invalid'
        with self.assertRaisesRegex(RuntimeError, 'unexpectedly compiled'):
            self.run_probe()
        q.clean(SimulatedNative.instances[-1])

    def test_receipt_does_not_include_environment(self):
        with patch.dict('os.environ', {'TEST_SECRET': 'DO_NOT_EMIT'}):
            result = self.run_probe()
        self.assertNotIn('DO_NOT_EMIT', str(result))
        self.assertNotIn('TEST_SECRET', str(result))


if __name__ == '__main__':
    unittest.main(verbosity=2)
