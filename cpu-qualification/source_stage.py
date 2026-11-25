"""Validate a pinned source tar and overlays before a future staging operation.
This module only reads archives; it does not extract or execute source code.
"""
import hashlib,posixpath,tarfile,os
from pathlib import PurePosixPath
from policy import require

def source_inventory(archive,expected_sha256,prefix,overlays):
    h=hashlib.sha256()
    with open(archive,'rb') as raw:
        before=os.fstat(raw.fileno())
        for b in iter(lambda:raw.read(1024*1024),b''):h.update(b)
        require(h.hexdigest()==expected_sha256,'source archive digest mismatch')
        raw.seek(0)
        with tarfile.open(fileobj=raw,mode='r:gz') as t:
            members={}
            for m in t:
                require(m.name==prefix or m.name.startswith(prefix+'/'),'source prefix')
                name=m.name[len(prefix):].lstrip('/')
                require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,'source path escape')
                if not name:continue
                require(name not in members,'duplicate source member')
                require(m.isdir() or m.isfile() or m.issym(),'unsupported source member')
                members[name]=m
            for name,m in members.items():
                for parent in PurePosixPath(name).parents:
                    if str(parent) in members:require(members[str(parent)].isdir(),'source parent is not directory')
                if m.issym():
                    require(not m.linkname.startswith('/'),'absolute source symlink')
                    # Reject links through links before handling '..': lexical
                    # normalization alone can hide traversal through a symlink pivot.
                    stack=list(PurePosixPath(name).parent.parts)
                    if stack==['.']:stack=[]
                    for part in m.linkname.split('/'):
                        if part in ('','.'):continue
                        if part=='..':
                            require(bool(stack),'escaping source symlink');stack.pop()
                        else:
                            stack.append(part)
                            current='/'.join(stack)
                            require(current not in members or not members[current].issym(),'source symlink chain')
            records=[]
            for name,patch in sorted(overlays.items()):
                require(type(patch) is dict and set(patch)=={'original_sha256','candidate_path','candidate_sha256'},'patch schema')
                require(name not in ('setup.py','MANIFEST.in'),'build entrypoint overlay not permitted')
                require(not PurePosixPath(name).is_absolute() and '..' not in PurePosixPath(name).parts,'patch path')
                for parent in PurePosixPath(name).parents:
                    if str(parent) in members:require(members[str(parent)].isdir(),'overlay parent is not directory')
                if patch['original_sha256'] is None:
                    require(name not in members,'new patch shadows original')
                else:
                    require(name in members and members[name].isfile(),'original patch target not regular')
                    original=t.extractfile(members[name]).read()
                    require(hashlib.sha256(original).hexdigest()==patch['original_sha256'],'original patch mismatch')
                with open(patch['candidate_path'],'rb') as f:candidate=f.read()
                require(hashlib.sha256(candidate).hexdigest()==patch['candidate_sha256'],'candidate patch mismatch')
                records.append({'name':name,'bytes':len(candidate),'sha256':patch['candidate_sha256']})
            # The archive contains top-level build entrypoint links. A future staging
            # adapter must preserve these validated in-tree links, not omit them.
            for name,target in [('setup.py','sky/setup_files/setup.py'),('MANIFEST.in','sky/setup_files/MANIFEST.in')]:
                require(name in members and members[name].issym() and members[name].linkname==target,'build entrypoint link')
                require(target in members and members[target].isfile(),'build entrypoint missing')
            after=os.fstat(raw.fileno())
            require((before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)==(after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns),'archive changed during inspection')
            return {'archive_sha256':expected_sha256,'regular_source_bytes':sum(m.size for m in members.values() if m.isfile()),'patches':records,'members':len(members),'extracted':False,'executed':False}
