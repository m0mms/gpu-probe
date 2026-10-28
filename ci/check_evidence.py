"""Bound retained evidence before upload; oversized evidence is a visible failure."""
import os
from pathlib import Path


def validate(root):
    total = 0
    files = list(root.iterdir())
    for path in files:
        if path.is_symlink() or not path.is_file() or path.suffix != '.json':
            raise ValueError('unexpected evidence member')
        total += path.stat().st_size
    if total > 20*1024**2:
        raise ValueError('evidence exceeds 20 MiB; upload refused, no silent truncation')
    return total


if __name__ == '__main__':
    print('Retained evidence bytes:', validate(Path(os.environ['EVIDENCE_DIR'])))
