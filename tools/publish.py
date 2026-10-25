#!/usr/bin/env python3
"""One exact release, on a reviewed GitHub-hosted runner. Never rebuild or retry."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

REPO = "m0mms/gpu-probe"
ROOT = "baa2ea26e8841b68741f8d14984692b97cd0c2f3"
TAG = "qualification-20261022"
ARCHIVE = "worker.oci.tar"
ARCHIVE_SIZE = 47472640
ARCHIVE_SHA = "e314c9f954e099310aa31332f98fa9fb8e7ebbe64ff5f097772211fd04157fbd"
MANIFEST = "f40fb0c91f94d4aee25747c5880bad7236df56c3d856f24630cb5f19cac0a00c"
SKOPEO = "quay.io/skopeo/stable@sha256:309ce24d7a87ca4eb35fc6dd9d91af7c4750d7f24578f633c6effd75c81f315d"
DEST = "docker://ghcr.io/m0mms/gpu-probe:" + TAG


def require(condition):
    if not condition:
        raise RuntimeError("gate_failed")


def command(args, *, data=None, check=True):
    # Do not print commands, tokens, API error bodies or external stderr.
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if check:
        require(result.returncode == 0)
    return result


def api(path):
    return json.loads(command(["gh", "api", path]).stdout)


def check_context(env, repository, runs):
    require(env.get("GITHUB_REPOSITORY") == REPO)
    require(env.get("GITHUB_REPOSITORY_ID") == "1430654983")
    require(env.get("GITHUB_REPOSITORY_OWNER_ID") == "474625")
    require(env.get("GITHUB_ACTOR") == "m0mms")
    require(env.get("GITHUB_EVENT_NAME") == "workflow_dispatch")
    require(env.get("GITHUB_REF") == "refs/heads/main")
    require(env.get("GITHUB_RUN_ATTEMPT") == "1")
    require(env.get("RUNNER_ENVIRONMENT") == "github-hosted")
    require(re.fullmatch(r"[0-9a-f]{40}", env.get("APPROVED_SHA", "")) is not None)
    require(env["APPROVED_SHA"] == env.get("GITHUB_SHA"))
    require(repository["id"] == 1430654983 and repository["owner"]["id"] == 474625)
    require(repository["full_name"] == REPO and repository["visibility"] == "public")
    require(repository["default_branch"] == "main")
    # Deliberately reject any previous run, even one which failed preflight.
    # This is a tripwire, not a provider-side idempotency guarantee: do not delete run history.
    require(runs["total_count"] == 1 and len(runs["workflow_runs"]) == 1)
    run = runs["workflow_runs"][0]
    require(str(run["id"]) == env.get("GITHUB_RUN_ID"))
    require(run["head_sha"] == env["APPROVED_SHA"])


def check_release(release, tag_ref):
    require(not release["draft"] and not release["prerelease"])
    require(release["tag_name"] == TAG)
    require(tag_ref["object"] == {"sha": ROOT, "type": "commit",
            "url": "https://api.github.com/repos/" + REPO + "/git/commits/" + ROOT})
    matches = [a for a in release["assets"] if a["name"] == ARCHIVE]
    require(len(matches) == 1)
    require(matches[0]["size"] == ARCHIVE_SIZE)
    require(matches[0]["state"] == "uploaded")
    require(matches[0].get("digest") == "sha256:" + ARCHIVE_SHA)


def require_absent(probe):
    # Deliberately narrow logrus diagnostic grammar, not substring matching.
    # An unqualified GHCR variant stops for review rather than broadening this gate.
    require(probe.returncode == 1 and probe.stdout == b"")
    text = probe.stderr.decode("utf-8", errors="strict")
    match = re.fullmatch(r'time="[0-9T:.+Z-]+" level=fatal msg=("[^\n]+")\n?', text)
    require(match is not None)
    message = json.loads(match.group(1))
    require(message == f'Error parsing image name "{DEST}": reading manifest {TAG} '
                       'in ghcr.io/m0mms/gpu-probe: manifest unknown')


def main():
    # Execute only after local activation review has verified all source companions.
    require(os.environ.get("SOURCES_VERIFIED_MANIFEST") == os.environ.get("EXPECTED_SOURCES_MANIFEST"))
    require(re.fullmatch(r"[0-9a-f]{64}", os.environ.get("EXPECTED_SOURCES_MANIFEST", "")) is not None)
    repo = api("repos/" + REPO)
    runs = api("repos/" + REPO + "/actions/workflows/publish-qualification.yml/runs?per_page=100")
    check_context(os.environ, repo, runs)
    check_release(api("repos/" + REPO + "/releases/tags/" + TAG),
                  api("repos/" + REPO + "/git/ref/tags/" + TAG))
    require(shutil.disk_usage(os.environ["RUNNER_TEMP"]).free >= 2 * 1024**3)
    # Credentials exist only on the ephemeral runner in verified shared-memory tmpfs.
    require(command(["findmnt", "-n", "-o", "FSTYPE", "-T", "/dev/shm"]).stdout.strip() == b"tmpfs")
    token = os.environ.pop("GH_TOKEN")
    name = "gpu-probe-publish-" + os.environ["GITHUB_RUN_ID"]
    require(re.fullmatch(r"gpu-probe-publish-[0-9]+", name) is not None)
    with tempfile.TemporaryDirectory(prefix="gpu-probe-", dir=os.environ["RUNNER_TEMP"]) as work, \
            tempfile.TemporaryDirectory(prefix="gpu-probe-auth-", dir="/dev/shm") as secret:
        work = Path(work)
        secret = Path(secret)
        # gh needs its token for this single download, then it is removed from environment.
        os.environ["GH_TOKEN"] = token
        try:
            command(["gh", "release", "download", TAG, "--repo", REPO,
                     "--pattern", ARCHIVE, "--dir", str(work)])
        finally:
            os.environ.pop("GH_TOKEN", None)
        archive = work / ARCHIVE
        require(archive.stat().st_size == ARCHIVE_SIZE)
        require(hashlib.file_digest(archive.open("rb"), "sha256").hexdigest() == ARCHIVE_SHA)
        command(["docker", "pull", SKOPEO])
        base = ["docker", "run", "--rm", "--name", name, "--pull=never", "--read-only",
                "--cap-drop=ALL", "--security-opt=no-new-privileges", "--memory=512m",
                "--memory-swap=512m", "--cpus=1", "--pids-limit=32", "--log-driver=none",
                "--tmpfs", "/var/tmp:rw,noexec,nosuid,nodev,size=134217728,mode=1777"]
        try:
            command(base + ["-i", "--mount", f"type=bind,src={secret},dst=/auth",
                            SKOPEO, "login", "--authfile", "/auth/config.json",
                            "--username", "m0mms", "--password-stdin", "ghcr.io"],
                    data=token.encode())
            token = ""
            auth = ["--mount", f"type=bind,src={secret},dst=/auth,readonly"]
            src = ["--mount", f"type=bind,src={archive},dst=/input/image.tar,readonly"]
            raw = command(base + ["--network=none"] + src + [SKOPEO, "inspect", "--raw",
                          "oci-archive:/input/image.tar"]).stdout
            require(hashlib.sha256(raw).hexdigest() == MANIFEST)
            probe = command(base + auth + [SKOPEO, "inspect", "--authfile", "/auth/config.json",
                            "--raw", DEST], check=False)
            # An existing tag, a permission error or uncertain response stops the operation.
            require_absent(probe)
            print("publication_intent: one copy; any interruption requires read-only reconciliation", flush=True)
            command(base + auth + src + [SKOPEO, "copy", "--preserve-digests", "--retry-times", "0",
                    "--authfile", "/auth/config.json", "oci-archive:/input/image.tar", DEST])
            remote = command(base + auth + [SKOPEO, "inspect", "--authfile", "/auth/config.json",
                             "--raw", DEST]).stdout
            require(hashlib.sha256(remote).hexdigest() == MANIFEST)
            print(json.dumps({"status": "exact_manifest_verified", "manifest": "sha256:" + MANIFEST,
                              "public_visibility": "not_changed_or_verified", "gpu_qualification": False}))
        finally:
            # Target only this run's name. No global prune or credential/logout operation.
            exists = command(["docker", "ps", "-aq", "--filter", "name=^/" + name + "$"], check=False)
            require(exists.returncode == 0)
            if exists.stdout.strip():
                command(["docker", "rm", "-f", name])
            # Container-created auth file is root owned; remove using local runner sudo.
            if (secret / "config.json").exists():
                command(["sudo", "-n", "rm", "--", str(secret / "config.json")])


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Publication stopped; outcome may be partial. Reconcile before any new attempt.")
        raise SystemExit(1) from None
