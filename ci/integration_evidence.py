"""No image archives, keys, logs or unbounded files may become public artifacts."""
import os
from pathlib import Path


def validate(root):
    if not root.is_dir() or root.is_symlink():
        raise ValueError('missing evidence root')
    total = 0
    count = 0
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('linked evidence')
        if path.is_dir():
            continue
        if not path.is_file() or path.suffix != '.json':
            raise ValueError('unexpected evidence member')
        total += path.stat().st_size
        count += 1
    if not count or total > 20*1024**2:
        raise ValueError('empty or oversized aggregate evidence')
    return total


if __name__ == '__main__':
    print('Aggregate JSON evidence bytes:', validate(Path(os.environ['EVIDENCE_DIR'])))
