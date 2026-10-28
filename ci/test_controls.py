import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from bounded import run
from check_context import validate
from identity import digest, platform_descriptor, release_context, verify_bytes


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'source.py').write_bytes(b'approved')
        self.expected = {'source.py': hashlib.sha256(b'approved').hexdigest()}

    def test_exact_context(self):
        self.assertEqual(validate(self.root, self.expected), self.expected)

    def test_extra_private_file(self):
        (self.root/'private.key').write_bytes(b'not eligible')
        with self.assertRaises(ValueError): validate(self.root, self.expected)

    def test_changed_source(self):
        (self.root/'source.py').write_bytes(b'changed')
        with self.assertRaises(ValueError): validate(self.root, self.expected)

    def test_symlink(self):
        (self.root/'link').symlink_to(self.root/'source.py')
        with self.assertRaises(ValueError): validate(self.root, self.expected)


class IdentityTests(unittest.TestCase):
    def test_manifest_hash_and_corruption(self):
        raw=b'{"schemaVersion":2}'
        h='sha256:'+hashlib.sha256(raw).hexdigest()
        self.assertEqual(verify_bytes(raw,h)['schemaVersion'],2)
        with self.assertRaises(ValueError): verify_bytes(raw+b' ',h)

    def test_digest_injection(self):
        for value in ['', 'sha256:'+('a'*63), 'sha256:'+('a'*64)+'\n', 'x;id']:
            with self.assertRaises(ValueError): digest(value)

    def test_platform_index_not_config_id(self):
        d={'digest':'sha256:'+'a'*64,'size':123,'platform':{'os':'linux','architecture':'amd64'}}
        att={'digest':'sha256:'+'b'*64,'size':50,'platform':{'os':'unknown','architecture':'unknown'}}
        self.assertEqual(platform_descriptor({'manifests':[d,att]}),d)
        with self.assertRaises(ValueError): platform_descriptor({'manifests':[d,d]})
        with self.assertRaises(ValueError): platform_descriptor({'config':d})

    def test_release_bindings_and_rerun(self):
        env={'EXPECTED_SHA':'a'*40,'GITHUB_SHA':'a'*40,'GITHUB_REPOSITORY':'m0mms/gpu-probe',
             'GITHUB_REPOSITORY_ID':'1430654983','GITHUB_REPOSITORY_OWNER_ID':'474625',
             'GITHUB_REF':'refs/heads/main','GITHUB_EVENT_NAME':'workflow_dispatch',
             'RUNNER_ENVIRONMENT':'github-hosted','GITHUB_RUN_ID':'123','GITHUB_RUN_ATTEMPT':'1'}
        self.assertTrue(release_context(env).endswith('-123-1'))
        for key,value in [('GITHUB_SHA','b'*40),('GITHUB_REF','refs/heads/other'),
                          ('GITHUB_RUN_ATTEMPT','2'),('GITHUB_EVENT_NAME','pull_request')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                release_context(dict(env,**{key:value}))


class ProcessTests(unittest.TestCase):
    def test_output_and_failure_preserved(self):
        code,out,err=run([sys.executable,'-c','import sys;print("evidence");sys.exit(7)'])
        self.assertEqual((code,out,err),(7,b'evidence\n',b''))

    def test_output_limit(self):
        with self.assertRaises(ValueError):
            run([sys.executable,'-c','print("x"*10000)'],cap=128)

    def test_timeout(self):
        with self.assertRaises(TimeoutError):
            run([sys.executable,'-c','import time;time.sleep(5)'],timeout=.1)



class HarnessTests(unittest.TestCase):
    def setUp(self):
        import importlib.util
        from unittest.mock import patch
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        spec=importlib.util.spec_from_file_location('qualification_test_module',Path(__file__).with_name('qualify.py'))
        self.h=importlib.util.module_from_spec(spec)
        with patch.dict('os.environ',{'EVIDENCE_DIR':self.temp.name,'QUALIFY_IMAGE':'ghcr.io/m0mms/gpu-probe@sha256:'+'a'*64}):
            spec.loader.exec_module(self.h)

    def test_baked_identity_path_policy(self):
        for name in ['etc/ssh/ssh_host_ed25519_key','run/gpu-bootstrap-identity/key','etc/gpu-paid-worker/registration.json']:
            self.assertTrue(self.h.forbidden(name))
        self.assertFalse(self.h.forbidden('usr/bin/ssh-keygen'))

    def test_cleanup_failure_not_success(self):
        from unittest.mock import patch
        with patch.object(self.h,'run',return_value=(1,b'',b'daemon unavailable')):
            self.assertFalse(self.h.cleanup())
        self.assertTrue((Path(self.temp.name)/'cleanup-failure.json').exists())

    def test_cleanup_only_owned_inventory(self):
        from unittest.mock import patch
        with patch.object(self.h,'run',return_value=(0,b'',b'')) as command:
            self.assertTrue(self.h.cleanup())
        self.assertEqual(command.call_count,4)
        for call in command.call_args_list:
            self.assertIn('label=gpu-probe.ci='+self.h.NAME,call.args[0])
            self.assertNotIn('prune',call.args[0])


class ResourceTests(unittest.TestCase):
    def test_file_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'bounded.bin'
            code,out,err=run([sys.executable,'-c',"import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b'x'*8192)",str(target)],file_cap=1024)
            self.assertNotEqual(code,0)
            self.assertLessEqual(target.stat().st_size,1024)

    def test_evidence_total(self):
        from check_evidence import validate as check
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);(root/'result.json').write_text('{}')
            self.assertEqual(check(root),2)
            with (root/'oversized.json').open('wb') as stream: stream.truncate(20*1024**2)
            with self.assertRaises(ValueError):check(root)

if __name__=='__main__': unittest.main()
