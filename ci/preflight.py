"""Fail closed on context, release identity and provisional infrastructure budget."""
import json
import os
from pathlib import Path
import shutil
from check_context import validate
from identity import release_context


if __name__ == '__main__':
    base = Path(__file__).resolve().parent
    tag = release_context(os.environ)
    validate(base.parent/'image', json.loads((base/'context-lock.json').read_text()))
    # Availability check only; not a guarantee against other job consumers.
    if shutil.disk_usage(os.environ['RUNNER_TEMP']).free < 12 * 1024**3:
        raise ValueError('less than 12 GiB runner free disk')
    memory = Path('/proc/meminfo').read_text().splitlines()
    available = next(int(x.split()[1])*1024 for x in memory if x.startswith('MemAvailable:'))
    if available < 4 * 1024**3:
        raise ValueError('less than 4 GiB available memory')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        stream.write('tag='+tag+'\n')
    print(json.dumps({'source_sha': os.environ['GITHUB_SHA'], 'candidate': tag,
                      'available_memory': available, 'capacity_is_snapshot_only': True}))
