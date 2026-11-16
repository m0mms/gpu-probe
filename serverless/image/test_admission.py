import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import admission
import attended_guard as g
import runner
from receipt import valid_output
from test_handler import PASS


class AdmissionTests(unittest.TestCase):
    def test_guard_refusal_precedes_loading(self):
        with patch.object(admission.C, 'CDLL') as load:
            def refuse(): raise MemoryError('test')
            with self.assertRaises(MemoryError): admission.observe(refuse)
            load.assert_not_called()

    def test_resolved_driver_identity_and_ambiguity(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d).resolve(); (p/'one').write_bytes(b'one'); (p/'alias').symlink_to(p/'one')
            self.assertEqual(admission.driver_path([p/'one',p/'alias']), p/'one')
            (p/'two').write_bytes(b'two')
            with self.assertRaises(ValueError): admission.driver_path([p/'one',p/'two'])
            with self.assertRaises(ValueError): admission.driver_path([])
            self.assertEqual(len(admission.bound_file(p/'one')['sha256']),64)

    def test_visible_memory_mapping(self):
        mount='1 0 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw'
        for limit, passes in [('max',False),(str(65*2**30),False),(str(64*2**30),True)]:
            read=lambda p: limit if p.endswith('memory.max') else '1024'
            if passes:
                self.assertEqual(g.memory_observation('0::/',mount,read)['effective_limit'],64*2**30)
            else:
                with self.assertRaises(MemoryError):g.memory_observation('0::/',mount,read)
        with self.assertRaises(RuntimeError):g.memory_observation('0::/../',mount,lambda p:'0')

    def test_lower_limits_and_rss(self):
        with patch.object(g.resource,'getrlimit',return_value=(2**30,2**30)),patch.object(g.resource,'setrlimit') as limits,patch.object(g.sys,'platform','linux'),patch.dict(g.os.environ):
            g.establish(); limits.assert_called_once_with(g.resource.RLIMIT_AS,(2**30,2**30))
            with self.assertRaises(MemoryError):g.validate_process(7*2**30,1,(2**30,2**30),g.os.environ)

    def test_marker_refuses_repeated_execution(self):
        with tempfile.TemporaryDirectory() as d,patch.object(runner,'HERE',Path(d)):
            (Path(d)/'attempt').mkdir()
            runner.claim_attempt()
            with self.assertRaises(FileExistsError):runner.claim_attempt()

    def test_evidence_rejects_unsafe_types_and_fields(self):
        self.assertTrue(valid_output(PASS))
        for key,value in [('peak_sampled_rss',True),('effective_memory_limit',65*2**30),('provider_admission_verified',True),('secret','x')]:
            v=copy.deepcopy(PASS);v['evidence'][key]=value;self.assertFalse(valid_output(v))
        for key,value in [('driver_sha256','not-a-hash'),('compute',[8.0,9]),('driver_version',12080),('device_ordinal',True)]:
            v=copy.deepcopy(PASS);v['evidence']['native_identity'][key]=value;self.assertFalse(valid_output(v))


if __name__=='__main__':unittest.main()
