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
    expected = {"status": "synthetic_native_pass", "elements": 257,
                "numeric_exact": True, "negative_compile_control": True,
                "owned_context_cleanup": True,
                "provider_cleanup_verified": False,
                "scientific_operator_qualified": False}
    if (receipt != expected or not isinstance(receipt, dict)
            or any(type(receipt[key]) is not type(value) for key, value in expected.items())):
        raise RuntimeError("qualification_failed")
    return expected  # Reconstruct output; no arbitrary strings or extra fields.


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
