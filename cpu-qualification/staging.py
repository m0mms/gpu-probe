"""Bounded staging primitives. Writes only to a newly-created private directory.
Caller must supply a verified quota-mounted parent; this module cannot prove it.
"""
import hashlib,os,stat,tarfile
from pathlib import Path,PurePosixPath
from policy import require,LIMITS
from source_stage import source_inventory


def parts(name):
    p=PurePosixPath(name)
    require(type(name) is str and name and not p.is_absolute() and '..' not in p.parts and str(p)==name,'noncanonical destination')
    return p.parts

class Tree:
    def __init__(self,parent,name):
        require(len(parts(name))==1,'single staging directory')
        self.fd=None
        # Walk from / with O_NOFOLLOW, so a symlink ancestor cannot be hidden.
        path=Path(parent).absolute()
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            for part in path.parts[1:]:
                nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
            os.mkdir(name,0o700,dir_fd=fd)  # EEXIST always refuses: no overwrite/resume.
            self.fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
        finally:os.close(fd)
        self.bytes=0;self.files=[];self.failed=False
    def close(self):
        if self.fd is not None:os.close(self.fd);self.fd=None
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
    def directory(self,name):
        fd=os.dup(self.fd)
        try:
            for part in parts(name):
                try:os.mkdir(part,0o700,dir_fd=fd)
                except FileExistsError:pass
                nxt=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);os.close(fd);fd=nxt
            return fd
        except BaseException:os.close(fd);raise
    def write(self,name,stream,size,digest,ceiling,executable=False):
        require(not self.failed,'staging tree failed; reuse refused')
        require(type(size) is int and size>=0,'file size')
        require(type(ceiling) is int and 0<=ceiling<=LIMITS['disk_bytes'],'staging ceiling')
        require(self.bytes+size<=ceiling,'staging expansion budget')
        ps=parts(name);parent=self.directory('/'.join(ps[:-1])) if len(ps)>1 else os.dup(self.fd)
        fd=None
        self.bytes+=size  # reserve even when failure leaves a partial file
        try:
            fd=os.open(ps[-1],os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700 if executable else 0o600,dir_fd=parent)
            count=0;h=hashlib.sha256()
            while count<size:
                b=stream.read(min(1048576,size-count));require(bool(b),'short input');count+=len(b);h.update(b)
                view=memoryview(b)
                while view:view=view[os.write(fd,view):]
            require(stream.read(1)==b'','input exceeds declared size')
            require(h.hexdigest()==digest,'copied input hash mismatch')
            os.fsync(fd);self.files.append({'name':name,'bytes':count,'sha256':digest})
        except BaseException:
            self.failed=True;raise
        finally:
            if fd is not None:os.close(fd)
            os.close(parent)
        # On failure keep partial evidence; never remove arbitrary trees here.
    def symlink(self,name,target):
        ps=parts(name);parent=self.directory('/'.join(ps[:-1])) if len(ps)>1 else os.dup(self.fd)
        try:os.symlink(target,ps[-1],dir_fd=parent)
        finally:os.close(parent)


def copy_manifest(tree,records):
    require(type(records) is list and bool(records),'input records')
    require(len({r['name'] for r in records})==len(records),'duplicate inputs')
    total=sum(r['bytes'] for r in records)
    require(total<=LIMITS['download_bytes'],'input budget')
    for r in records:
        # Destination metadata and hashes must be from the frozen release input set.
        fd=os.open(r['path'],os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as f:
            st=os.fstat(f.fileno());require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_size==r['bytes'],'input identity')
            tree.write(r['name'],f,r['bytes'],r['sha256'],LIMITS['download_bytes'])
            end=os.fstat(f.fileno());require((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns),'input changed')
    return {'files':tree.files,'bytes':tree.bytes}


def extract_source(tree,archive,digest,prefix,patches,ceiling):
    checked=source_inventory(archive,digest,prefix,patches)
    require(checked['regular_source_bytes']+sum(x['bytes'] for x in checked['patches'])<=ceiling,'source expansion budget')
    # Recheck archive identity across inspection and extraction. A future caller
    # stages this immutable archive inside the private quota filesystem first.
    with open(archive,'rb') as raw:
        st=os.fstat(raw.fileno())
        h=hashlib.sha256()
        for b in iter(lambda:raw.read(1048576),b''):h.update(b)
        require(h.hexdigest()==digest,'source changed before extraction');raw.seek(0)
        with tarfile.open(fileobj=raw,mode='r:gz') as t:
            links=[]
            for m in t:
                name=m.name[len(prefix):].lstrip('/')
                if not name:continue
                if m.isdir():
                    d=tree.directory(name);os.close(d)
                elif m.issym():links.append((name,m.linkname))
                elif m.isfile() and name not in patches:
                    # Hash bounded archive member without retaining whole files.
                    h=hashlib.sha256();f=t.extractfile(m)
                    for b in iter(lambda:f.read(1048576),b''):h.update(b)
                    with t.extractfile(m) as f:tree.write(name,f,m.size,h.hexdigest(),ceiling,bool(m.mode&0o111))
            # Overlay files precede all symlinks. Validator forbids link parents.
            for name,r in patches.items():
                fd=os.open(r['candidate_path'],os.O_RDONLY|os.O_NOFOLLOW)
                with os.fdopen(fd,'rb') as f:
                    s=os.fstat(f.fileno());require(stat.S_ISREG(s.st_mode),'overlay regular file')
                    tree.write(name,f,s.st_size,r['candidate_sha256'],ceiling)
            for name,target in links:tree.symlink(name,target)
        end=os.fstat(raw.fileno());require((st.st_dev,st.st_ino,st.st_size,st.st_mtime_ns,st.st_ctime_ns)==(end.st_dev,end.st_ino,end.st_size,end.st_mtime_ns,end.st_ctime_ns),'archive changed during extraction')
    return {'files':len(tree.files),'bytes':tree.bytes,'links':len(links)}
