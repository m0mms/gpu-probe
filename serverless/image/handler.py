"""Synthetic-only queue adapter. Local preparation, not an approved release."""
import json
import subprocess
import sys
import threading
from pathlib import Path

from failure import failed, valid_failure

HERE = Path(__file__).resolve().parent
LOCK = threading.Lock()
USED = False
REQUEST = {"test": "frozen-cuda-257-v1"}


def execute():
    # The child suppresses native logs; never return subprocess diagnostics.
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-B", str(HERE / "runner.py")],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=110,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return failed('child_timeout')
    except Exception:
        return failed('child_start')
    if len(result.stdout) > 16384:
        return failed('child_output')
    try:
        receipt = json.loads(result.stdout)
    except (ValueError, TypeError):
        return failed('child_exit' if result.returncode else 'child_output')
    if result.returncode != 0:
        return receipt if valid_failure(receipt) else failed('child_exit')
    from receipt import valid_output
    if not valid_output(receipt):
        return receipt if valid_failure(receipt) else failed('child_receipt')
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
        return failed('handler_internal')


if __name__ == "__main__":
    import runpod
    runpod.serverless.start({"handler": handler})
