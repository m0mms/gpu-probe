"""Fresh interpreter boundary; immutable test, original guard, local config only."""
import hashlib
import json
import os
from pathlib import Path
import resource
import sys

HERE = Path(__file__).resolve().parent
FREEZE = "3d17a4dfeea755d4e1c6193d8c9b842161962847a9b771f6ca8b59e7b15bbdd5"


def bind():
    # This file is deliberately absent from the image recipe. Its reviewed
    # delivery, provider bindings and retry contract remain release prerequisites.
    raw = (HERE / "admission.json").read_bytes()
    if len(raw) > 65536:
        raise ValueError("admission_size")
    expected = os.environ.get("QUALIFICATION_ADMISSION_SHA256", "")
    if len(expected) != 64 or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("admission_binding")
    config = json.loads(raw)
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
    return package, config


def claim_attempt():
    # Local persistent marker survives handler/process restart on this filesystem,
    # but NOT worker replacement. It is explicitly not global exactly-once control.
    fd = os.open(HERE / ".attempt-started", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(HERE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def establish_limits():
    _, hard = resource.getrlimit(resource.RLIMIT_AS)
    limit = min(hard, 48 * 2**30) if hard != resource.RLIM_INFINITY else 48 * 2**30
    resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    for name in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS", "VECLIB_MAXIMUM_THREADS"):
        os.environ[name] = "3"


def run():
    package, config = bind()
    claim_attempt()
    establish_limits()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(package))
    import qualification
    result = qualification.qualify(config)
    for name in ("native_execution_claim", "numeric_exact", "compile_failure_control", "owned_context_cleanup"):
        if result[name] is not True:
            raise ValueError("test_failed")
    return {"status": "synthetic_native_pass", "elements": 257,
            "numeric_exact": True, "negative_compile_control": True,
            "owned_context_cleanup": True, "provider_cleanup_verified": False,
            "scientific_operator_qualified": False}


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
