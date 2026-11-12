"""Local exact-context verification; no Docker or network."""
import hashlib,json
from pathlib import Path
from runner import FREEZE
ROOT=Path(__file__).resolve().parent
def require(condition):
    if not condition:raise ValueError("context_check_failed")

def check():
    p=ROOT/'package';raw=(p/'freeze.json').read_bytes()
    require(hashlib.sha256(raw).hexdigest()==FREEZE)
    m=json.loads(raw); names=set(m)|{'freeze.json'}
    require(not p.is_symlink() and {x.name for x in p.iterdir()}==names)
    for n in names:
        f=p/n
        require(f.is_file() and not f.is_symlink())
        if n in m:require(hashlib.sha256(f.read_bytes()).hexdigest()==m[n])
    files=['requirements.lock','bootstrap.py','handler.py','runner.py']
    for n in files:require((ROOT/n).is_file() and not (ROOT/n).is_symlink())
    expected=['**']+['!'+x for x in files]+['!package/','package/**']+['!package/'+n for n in sorted(names)]
    require((ROOT/'.dockerignore').read_text().splitlines()==expected)
    return True
if __name__=='__main__':
    if not check():raise SystemExit(1)
    print('Exact context checked; no build performed.')
