"""Read-only verification of multiple cgroup mount views; Linux proc contract."""
import os
from pathlib import PurePosixPath
from admission_diagnostics import mark

LIMIT = 1024 * 1024

def read_fd(fd):
    data = bytearray()
    while len(data) <= LIMIT:
        chunk = os.read(fd, min(65536, LIMIT + 1 - len(data)))
        if not chunk: return data.decode('ascii')
        data.extend(chunk)
    raise RuntimeError('cgroup read bound')


def directory(path):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open('/', flags)
    try:
        for part in PurePosixPath(path).parts[1:]:
            nxt = os.open(part, flags, dir_fd=fd)
            os.close(fd); fd = nxt
        return fd
    except BaseException:
        os.close(fd); raise


class AliasView:
    def __init__(self, matches, records, cgroup_text, mount_text):
        self.matches, self.records = matches, records
        self.initial = (cgroup_text, mount_text)
        self.fds = {}
        self.path_records = {}
        for (leaf, mount), record in zip(matches, records):
            node = leaf
            while True:
                path = str(node)
                if path in self.path_records and self.path_records[path] != record:
                    raise RuntimeError('conflicting cgroup mount records')
                self.path_records[path] = record
                if len(self.path_records)>256:raise RuntimeError('cgroup directory bound')
                if node == mount:break
                node = node.parent

    def file(self, path):
        path = PurePosixPath(path)
        if path.name not in ('memory.max','memory.current','cgroup.procs'):
            raise RuntimeError('cgroup file allowlist')
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=self.fds[str(path.parent)])
        try:
            self.verify_fd(fd, self.path_records[str(path.parent)])
            return read_fd(fd)
        finally: os.close(fd)

    @staticmethod
    def proc(path):
        fd=os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        try:return read_fd(fd)
        finally:os.close(fd)

    def verify_fd(self, fd, record):
        mount_id, device = record
        info=self.proc('/proc/self/fdinfo/'+str(fd))
        ids=[line.split(':',1)[1].strip() for line in info.splitlines() if line.startswith('mnt_id:')]
        if ids != [mount_id]:raise RuntimeError('cgroup mount identity')
        st=os.fstat(fd)
        if (os.major(st.st_dev),os.minor(st.st_dev)) != device:
            raise RuntimeError('cgroup device identity')
        return (st.st_dev, st.st_ino)

    def verify(self):
        if (self.proc('/proc/self/cgroup'), self.proc('/proc/self/mountinfo')) != self.initial:
            raise RuntimeError('cgroup topology changed')
        identities=[]
        for (leaf,mount),record in zip(self.matches,self.records):
            node=leaf
            while True:
                path=str(node)
                current=directory(path)
                try:
                    if self.verify_fd(current,record) != self.verify_fd(self.fds[path],record):
                        raise RuntimeError('cgroup directory changed')
                finally:os.close(current)
                if node==mount:break
                node=node.parent
            identities.append(self.verify_fd(self.fds[str(leaf)],record))
            members=self.file(str(leaf/'cgroup.procs')).splitlines()
            if str(os.getpid()) not in members:raise RuntimeError('cgroup membership not verified')
        mark('cgroup_mapping', cgroup_identity_count=len(set(identities)))
        if len(set(identities)) != 1:raise RuntimeError('distinct cgroup identities')

    def __enter__(self):
        try:
            for leaf,mount in self.matches:
                node=leaf
                while True:
                    if str(node) not in self.fds:self.fds[str(node)]=directory(str(node))
                    if len(self.fds)>256:raise RuntimeError('cgroup directory bound')
                    if node==mount:break
                    node=node.parent
            self.verify()
            return self
        except BaseException:
            self.close();raise

    def close(self):
        for fd in self.fds.values():os.close(fd)
        self.fds.clear()

    def __exit__(self,*args):self.close()
