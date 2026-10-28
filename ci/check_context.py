"""Validate the deliberately small build context; never execute its contents."""
import hashlib
import json
from pathlib import Path


def validate(root, expected):
    found = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise ValueError('symlink in context')
        if path.is_dir():
            continue
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            raise ValueError('invalid context member')
        found[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if found != expected:
        raise ValueError('context differs from reviewed allowlist')
    return found


if __name__ == '__main__':
    base = Path(__file__).resolve().parent
    validate(base.parent / 'image', json.loads((base / 'context-lock.json').read_text()))
    print('Build context matches reviewed allowlist')
