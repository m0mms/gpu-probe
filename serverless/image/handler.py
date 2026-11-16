"""Synthetic-only queue adapter. Local preparation, not an approved release."""
import json
import subprocess
import sys
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
LOCK = threading.Lock()
USED = False
REQUEST = {"test": "frozen-cuda-257-v1"}


def execute():
    # The child suppresses native logs; never return subprocess diagnostics.
    result = subprocess.run(
        [sys.executable, "-I", str(HERE / "runner.py")],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=110,
        check=False,
    )
    if result.returncode != 0 or len(result.stdout) > 16384:
        raise RuntimeError("qualification_failed")
    receipt = json.loads(result.stdout)
    from receipt import valid_output
    if not valid_output(receipt):
        raise RuntimeError("qualification_failed")
    return receipt  # Exact schema, bounded numeric/hash fields; no raw logs.



def handler(job):
    global USED
    # No arbitrary source, shell command, library path or scientific input.
    if not isinstance(job, dict) or job.get("input") != REQUEST:
        return {"status": "synthetic_native_fail", "reason": "invalid_request"}
    with LOCK:
        if USED:
            return {"status": "synthetic_native_fail", "reason": "attempt_already_used"}
        USED = True
    try:
        return execute()
    except BaseException:
        return {"status": "synthetic_native_fail", "reason": "qualification_failed"}


if __name__ == "__main__":
    import runpod
    runpod.serverless.start({"handler": handler})
