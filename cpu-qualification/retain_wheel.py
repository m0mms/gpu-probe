"""Retain exactly one built application wheel; no dependency resolution."""
import hashlib,json,zipfile
from pathlib import Path
MAX_WHEEL=33554432
def inspect_wheel(path):
 p=Path(path)
 if p.is_symlink() or not p.is_file() or not 0<p.stat().st_size<=MAX_WHEEL:raise ValueError('wheel bounds/type')
 with zipfile.ZipFile(p) as z:
  infos=z.infolist()
  if sum(i.file_size for i in infos)>134217728:raise ValueError('wheel expansion bound')
  metadata=[i for i in infos if i.filename.endswith('.dist-info/METADATA')]
  if len(metadata)!=1 or metadata[0].file_size>1048576:raise ValueError('wheel metadata')
  if b'\nName: skypilot\n' not in b'\n'+z.read(metadata[0]):raise ValueError('wrong application wheel')
 return {'name':p.name,'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
def retain(root):
 root=Path(root);files=list(root.iterdir())
 if len(files)!=1 or not files[0].name.startswith('skypilot-') or files[0].suffix!='.whl':raise ValueError('exactly one application wheel required')
 record=inspect_wheel(files[0]);(root/'wheel.json').write_text(json.dumps(record,sort_keys=True)+'\n');return record
if __name__=='__main__':retain('/tmp/wheel')
