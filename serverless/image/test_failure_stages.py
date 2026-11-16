import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import handler
import runner
from failure import STAGES, failed, valid_failure
from receipt import accepted
from test_handler import PASS


class Tests(unittest.TestCase):
    def test_stage_allowlist_and_strict_schema(self):
        for stage in STAGES:
            self.assertTrue(valid_failure(failed(stage)))
            self.assertFalse(accepted({'id':'j','status':'COMPLETED','output':failed(stage)}, 'j'))
        for bad in ('secret text', [], None, {'secret': 'value'}):
            self.assertEqual(failed(bad)['stage'], 'handler_internal')
        self.assertFalse(valid_failure(dict(failed('child_exit'), logs='secret')))

    def test_each_runner_boundary_sets_stage_before_call(self):
        # Fail before GPU work, with fake imports for later boundaries.
        import types
        guard_module = types.ModuleType('attended_guard')
        admission_module = types.ModuleType('admission')
        qualification_module = types.ModuleType('qualification')
        guard_module.AttendedGuard = lambda: object()
        admission_module.observe = lambda g: {}
        qualification_module.qualify = lambda *a, **k: {}
        original_path = list(sys.path)
        try:
            for target, stage in [('bind','package_binding'), ('claim_attempt','attempt_claim'),
                                  ('establish_limits','resource_limits')]:
                with patch.object(runner,'bind',return_value=Path('/not-used')), \
                     patch.object(runner,'claim_attempt'), patch.object(runner,'establish_limits'), \
                     patch.object(runner,target,side_effect=ValueError('SECRET')):
                    with self.assertRaises(ValueError): runner.run()
                    self.assertEqual(runner.STAGE, stage)
            with patch.object(runner,'bind',return_value=Path('/not-used')), \
                 patch.object(runner,'claim_attempt'), patch.object(runner,'establish_limits'), \
                 patch.dict(sys.modules, {'attended_guard':guard_module, 'admission':admission_module,
                                          'qualification':qualification_module}):
                for module, name, stage in [(guard_module,'AttendedGuard','guard_creation'),
                        (admission_module,'observe','runtime_admission'),
                        (qualification_module,'qualify','native_qualification')]:
                    with patch.object(module,name,side_effect=ValueError('SECRET')):
                        with self.assertRaises(ValueError): runner.run()
                        self.assertEqual(runner.STAGE,stage)
                with self.assertRaises(KeyError): runner.run()
                self.assertEqual(runner.STAGE,'result_checks')
        finally:
            sys.path[:] = original_path

    def test_child_channel_suppresses_exception_and_native_text(self):
        # Separate process because runner.main redirects OS descriptors.
        code = """import runner,os
def broken():
 runner.STAGE='runtime_admission'
 print('SECRET_STDOUT',flush=True)
 os.write(2,b'SECRET_STDERR')
 raise ValueError('SECRET_EXCEPTION')
runner.run=broken
raise SystemExit(runner.main())
"""
        result = subprocess.run([sys.executable,'-B','-c',code],
            cwd=Path(__file__).parent,capture_output=True,timeout=10)
        self.assertEqual(result.returncode,1)
        self.assertEqual(json.loads(result.stdout),failed('runtime_admission'))
        self.assertEqual(result.stderr,b'')
        self.assertNotIn(b'SECRET',result.stdout)

    def test_handler_preserves_only_valid_failure_and_consumes_attempt(self):
        for payload in [failed('runtime_admission'), dict(failed('runtime_admission'), env='SECRET'),
                        {'status':'synthetic_native_fail','reason':'SECRET','stage':'SECRET'}]:
            handler.USED=False
            with patch.object(handler.subprocess,'run',return_value=subprocess.CompletedProcess([],1,json.dumps(payload).encode())) as run:
                out=handler.handler({'input':handler.REQUEST})
                self.assertEqual(out, payload if valid_failure(payload) else failed('child_exit'))
                self.assertNotIn('SECRET',json.dumps(out))
                self.assertEqual(handler.handler({'input':handler.REQUEST})['reason'],'attempt_already_used')
                self.assertEqual(run.call_count,1)

    def test_timeout_crash_oversize_and_invalid_success(self):
        with patch.object(handler.subprocess,'run',side_effect=subprocess.TimeoutExpired('SECRET',110)):
            self.assertEqual(handler.execute(),failed('child_timeout'))
        for code, raw, stage in [(-9,b'', 'child_exit'),(0,b'x'*16385,'child_output'),
                                 (0,b'bad json','child_output'),(0,b'{}','child_receipt'),
                                 (1,json.dumps(PASS).encode(),'child_exit')]:
            with patch.object(handler.subprocess,'run',return_value=subprocess.CompletedProcess([],code,raw)):
                self.assertEqual(handler.execute(),failed(stage))

    def test_docker_includes_failure_module(self):
        self.assertIn('runner.py failure.py receipt.py', (Path(__file__).parent/'Dockerfile.candidate').read_text())


if __name__ == '__main__': unittest.main()
