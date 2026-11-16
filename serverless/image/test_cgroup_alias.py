import os,unittest
from pathlib import PurePosixPath as P
from types import SimpleNamespace
from unittest.mock import patch
import attended_guard as g
import cgroup_alias as a
import admission_diagnostics as d

M='1 0 0:1 / /one rw - cgroup2 cgroup rw\n2 0 0:1 / /two rw - cgroup2 cgroup rw'
class FakeView:
    def __init__(self,limit='max',bad=None):self.limit=limit;self.bad=bad;self.reads=[];self.verified=0
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def file(self,path):
        self.reads.append(path)
        if path==self.bad:raise OSError('missing ancestor')
        if path.endswith('memory.current'):return '1'
        return str(8*g.GIB) if path=='/two/memory.max' else self.limit
    def verify(self):self.verified+=1

class Tests(unittest.TestCase):
    def setUp(self):d.reset()
    def test_all_views_and_ancestors_checked(self):
        view=FakeView();r=g.memory_observation('0::/child',M,None,lambda *args:view)
        self.assertEqual(r['effective_limit'],8*g.GIB)
        self.assertEqual(len(view.reads),8);self.assertEqual(view.verified,1)
        self.assertEqual(d.snapshot()['facts']['cgroup_match_count'],2)
        self.assertEqual(d.snapshot()['facts']['cgroup2_mount_count'],2)
        self.assertFalse(r['hidden_ancestors_verified'])
    def test_missing_and_excess_counts(self):
        for text,count in [('',0),('\n'.join(M.splitlines()[0] for _ in range(17)),17)]:
            with self.assertRaises(RuntimeError):g.memory_observation('0::/',text,None)
            self.assertEqual(d.snapshot()['facts']['cgroup_match_count'],count)
    def test_inaccessible_other_ancestor_refuses(self):
        v=FakeView(bad='/one/memory.current')
        with self.assertRaises(OSError):g.memory_observation('0::/child',M,None,lambda *args:v)
    def test_alias_memory_refusals(self):
        for maximum,current in [('max','1'),(str(65*g.GIB),'1'),('0','1'),('1','2'),('2','-1'),('bad','1')]:
            v=FakeView();v.file=lambda path:maximum if path.endswith('memory.max') else current
            with self.assertRaises((MemoryError,ValueError)):g.memory_observation('0::/',M,None,lambda *args:v)
    def view(self):
        v=a.AliasView([(P('/one'),P('/one')),(P('/two'),P('/two'))],[('1',(0,1)),('2',(0,1))],'CG','MI')
        v.fds={'/one':10,'/two':20}
        v.proc=lambda path:'CG' if path.endswith('cgroup') else 'MI'
        v.file=lambda path:str(os.getpid())+'\n'
        v.verify_fd=lambda fd,record:(1,42)
        return v
    def test_verified_identity_membership_topology(self):
        v=self.view()
        with patch.object(a,'directory',return_value=30),patch.object(a.os,'close'):
            v.verify();self.assertEqual(d.snapshot()['facts']['cgroup_identity_count'],1)
            v.verify_fd=lambda fd,record:(1,int(record[0]))
            with self.assertRaisesRegex(RuntimeError,'distinct'):v.verify()
            self.assertEqual(d.snapshot()['facts']['cgroup_identity_count'],2)
        v=self.view();v.proc=lambda path:'CHANGED'
        with self.assertRaisesRegex(RuntimeError,'topology'):v.verify()
        v=self.view();v.file=lambda path:''
        with patch.object(a,'directory',return_value=30),patch.object(a.os,'close'):
            with self.assertRaisesRegex(RuntimeError,'membership'):v.verify()
    def test_fd_mount_device_and_path_change(self):
        v=self.view();del v.verify_fd
        v.proc=lambda path:'mnt_id:\t1\n'
        with patch.object(a.os,'fstat',return_value=SimpleNamespace(st_dev=os.makedev(0,1),st_ino=42)):
            self.assertEqual(v.verify_fd(10,('1',(0,1))),(os.makedev(0,1),42))
            with self.assertRaisesRegex(RuntimeError,'mount identity'):v.verify_fd(10,('2',(0,1)))
            with self.assertRaisesRegex(RuntimeError,'device identity'):v.verify_fd(10,('1',(0,2)))
        v=self.view();v.verify_fd=lambda fd,record:(1,fd)
        with patch.object(a,'directory',return_value=30),patch.object(a.os,'close'):
            with self.assertRaisesRegex(RuntimeError,'directory changed'):v.verify()
    def test_fd_cleanup_on_entry_failure(self):
        v=self.view();v.fds={};v.verify=lambda:(_ for _ in ()).throw(RuntimeError('bad'))
        with patch.object(a,'directory',side_effect=[10,20]),patch.object(a.os,'close') as close:
            with self.assertRaises(RuntimeError):v.__enter__()
            self.assertEqual(close.call_count,2);self.assertEqual(v.fds,{})
    def test_bounded_reads(self):
        with patch.object(a.os,'read',return_value=b'x'*65536):
            with self.assertRaises(RuntimeError):a.read_fd(1)

    def test_control_file_mount_verified_and_closed(self):
        v=self.view();del v.file
        with patch.object(a.os,'open',return_value=90),patch.object(a.os,'close') as close,patch.object(a,'read_fd',return_value='1') as read:
            v.verify_fd=lambda fd,record:(_ for _ in ()).throw(RuntimeError('overmounted'))
            with self.assertRaisesRegex(RuntimeError,'overmounted'):v.file('/one/memory.max')
            read.assert_not_called();close.assert_called_once_with(90)
        with patch.object(a.os,'open',return_value=90),patch.object(a.os,'close'),patch.object(a,'read_fd',return_value='1'):
            seen=[];v.verify_fd=lambda fd,record:seen.append((fd,record))
            self.assertEqual(v.file('/one/memory.max'),'1')
            self.assertEqual(seen,[(90,('1',(0,1)))])
