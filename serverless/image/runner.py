"""One attended interpreter: unchanged synthetic test and separate approved guard."""
import hashlib
import json
import os
from pathlib import Path
import resource
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
FREEZE = "3d17a4dfeea755d4e1c6193d8c9b842161962847a9b771f6ca8b59e7b15bbdd5"


def bind():
    package = HERE / "package"
    if package.is_symlink() or (package / "freeze.json").is_symlink():
        raise ValueError("package_members")
    frozen = (package / "freeze.json").read_bytes()
    if hashlib.sha256(frozen).hexdigest() != FREEZE:
        raise ValueError("package_binding")
    manifest = json.loads(frozen)
    if {p.name for p in package.iterdir()} != set(manifest) | {"freeze.json"}:
        raise ValueError("package_members")
    for name, digest in manifest.items():
        file = package / name
        if (Path(name).name != name or file.is_symlink() or not file.is_file()
                or hashlib.sha256(file.read_bytes()).hexdigest() != digest):
            raise ValueError("package_integrity")
    return package


def claim_attempt():
    # Local persistent marker survives handler/process restart on this filesystem,
    # but NOT worker replacement. It is explicitly not global exactly-once control.
    fd = os.open(HERE / "attempt" / ".attempt-started", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(HERE / "attempt", os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def establish_limits():
    from attended_guard import establish
    establish()


def run():
    package = bind()
    claim_attempt()
    establish_limits()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(package))
    from attended_guard import AttendedGuard
    from admission import observe
    guard = AttendedGuard()
    config = observe(guard)
    import qualification
    result = qualification.qualify(config, guard=guard)
    for name in ("native_execution_claim", "numeric_exact", "compile_failure_control", "owned_context_cleanup"):
        if result[name] is not True:
            raise ValueError("test_failed")
    return {"status": "synthetic_native_pass", "elements": 257,
            "numeric_exact": True, "negative_compile_control": True,
            "owned_context_cleanup": True, "provider_cleanup_verified": False,
            "scientific_operator_qualified": False,
            "evidence": {"package_freeze": FREEZE,
                         "native_identity": result["native_identity"],
                         "peak_sampled_rss": guard.peak_rss,
                         "effective_memory_limit": guard.last["effective_limit"],
                         "hidden_ancestors_verified": False,
                         "provider_admission_verified": False}}


def main():
    # Keep both Python/native output suppressed through interpreter teardown.
    output = os.dup(1)
    with open(os.devnull, "wb") as sink:
        os.dup2(sink.fileno(), 1)
        os.dup2(sink.fileno(), 2)
    try:
        receipt = run()
        raw = (json.dumps(receipt) + "\n").encode()
        while raw:
            written = os.write(output, raw)
            if written <= 0:
                return 1
            raw = raw[written:]
        return 0
    except BaseException:
        return 1
    finally:
        os.close(output)


if __name__ == "__main__":
    raise SystemExit(main())
