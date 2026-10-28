import json
from pathlib import Path
import tempfile
import time
import unittest
from failure_control import accepted
from identity import qualification_reference
from integration_binding import builder_limits
from integration_evidence import validate as evidence
from integration_resources import validate as resources


class IntegrationTests(unittest.TestCase):
    def test_local_mode_cannot_masquerade_as_registry(self):
        config='sha256:'+'a'*64
        self.assertEqual(qualification_reference(config, 'local-build'), config)
        with self.assertRaises(ValueError): qualification_reference(config)
        with self.assertRaises(ValueError): qualification_reference('arbitrary:tag','local-build')
        with self.assertRaises(ValueError): qualification_reference('ghcr.io/m0mms/gpu-probe@'+config,'local-build')

    def test_failure_control_requires_reached_and_clean(self):
        result={'passed':False,'forced_failure_reached':True,'cleanup_passed':True}
        self.assertTrue(accepted(1,result))
        self.assertFalse(accepted(0,result))
        self.assertFalse(accepted(1,dict(result,forced_failure_reached=False)))
        self.assertFalse(accepted(1,dict(result,cleanup_passed=False)))

    def test_builder_limits_checked(self):
        obj={'State':{'Running':True},'HostConfig':{'Memory':4*1024**3,'MemorySwap':4*1024**3,
            'CpuPeriod':100000,'CpuQuota':200000}}
        self.assertEqual(builder_limits(obj)['Memory'],4*1024**3)
        obj['HostConfig']['Memory']=0
        with self.assertRaises(ValueError):builder_limits(obj)

    def test_stale_and_unhealthy_resource_observations_fail(self):
        state={'healthy':True,'samples':3,'sampled_at':time.time(),'complete':True}
        resources(state,complete=True)
        for values in [{'sampled_at':time.time()-20},{'healthy':False},{'complete':False}]:
            with self.assertRaises(ValueError):resources(dict(state,**values),complete=True)

    def test_evidence_excludes_archives(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'suite').mkdir();(root/'suite/result.json').write_text('{}')
            self.assertEqual(evidence(root),2)
            (root/'image.tar').write_bytes(b'not eligible')
            with self.assertRaises(ValueError):evidence(root)




class SaveLimitTests(unittest.TestCase):
    def test_expected_file_limit_not_arbitrary_failure(self):
        from save_limit_control import accepted
        self.assertTrue(accepted(1,b'write: file too large',[65536]))
        self.assertFalse(accepted(1,b'daemon unavailable',[]))
        self.assertFalse(accepted(0,b'file too large',[65536]))
        self.assertFalse(accepted(1,b'file too large',[65537]))

if __name__=='__main__':unittest.main()
