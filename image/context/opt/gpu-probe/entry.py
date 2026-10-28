"""Fixed forced-command entry; installed in immutable root-owned image path."""
import os
import sys

if (sys.argv[1:] != ['--stdio-v1'] or
    os.environ.get('SSH_ORIGINAL_COMMAND') != '/usr/local/libexec/gpu-paid-worker --stdio-v1' or
    os.geteuid() == 0):
    raise SystemExit(2)
os.environ.clear()
os.environ.update({'PATH':'/usr/bin:/bin','LANG':'C','HOME':'/nonexistent'})
sys.path.insert(0,'/opt/gpu-probe')
from paid_probe.capability_worker import main
raise SystemExit(main(['--stdio-v1']))
