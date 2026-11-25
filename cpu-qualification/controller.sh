set -eu
python -B /control/resource_guard.py
mkdir -p /tmp/qualification-home
python -B - <<'PY'
import json,sys
sys.path.insert(0,'/control')
from staging import Tree,extract_source
with Tree('/tmp','patched') as tree:
    extract_source(tree,'/inputs/source.tar.gz','c58c0a73cad7670d61bd628380bf100b1edbf2ec5565bc9fd8f3383a607e0e4b','skypilot-315df3afb4f66d7b3f4d2f6104717a81c2eb4af7',json.load(open('/control/patches.json')),120000000)
PY
python -m venv /tmp/controller
/tmp/controller/bin/python -m pip install --no-index --no-cache-dir --only-binary=:all: --require-hashes --find-links=/inputs -r /control/requirements.lock
PIP_NO_INDEX=1 /tmp/controller/bin/python -m pip wheel --no-deps --no-build-isolation --no-cache-dir --wheel-dir /tmp/wheel /tmp/patched
/tmp/controller/bin/python -m pip install --no-index --no-deps --no-cache-dir /tmp/wheel/skypilot-*.whl
/tmp/controller/bin/python -m pip check
cd /tmp
/tmp/controller/bin/python -c 'import sky; import runpod; import sky.utils.host_auth; print("CPU_CONTROLLER_IMPORT_PASSED")'
