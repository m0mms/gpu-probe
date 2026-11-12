"""Fixed queue-worker startup; no CLI/debugger/realtime overrides."""
import importlib.metadata
import os
import sys

def main():
    # Check before importing SDK (which may initialize logging and environment).
    if len(sys.argv) != 1 or os.environ.get("RUNPOD_REALTIME_PORT", "0") != "0":
        return 64
    try:
        if importlib.metadata.version("runpod") != "2.2.1":
            return 65
    except importlib.metadata.PackageNotFoundError:
        return 65
    from handler import handler
    import runpod
    runpod.serverless.start({"handler": handler, "refresh_worker": False})
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
