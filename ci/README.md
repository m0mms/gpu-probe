# Synthetic worker CI

Prepared implementation; publication is disabled unless the separately reviewed release is enabled. No result from these workflows authorizes provider spending or general computation.

The image context is `image/`, checked against `ci/context-lock.json`. Workflow code and test material are never included in that build context. The only image changes from the reference recipe are inclusion of owned-source licence notices during the build. Source files retain their individual declared licence scope.

`worker-ci.yml` performs read-only checks. `worker-release.yml` builds one candidate from an exact main commit, pushes to a unique candidate tag, attests the returned digest, and tests the registry-delivered platform image on a fresh runner. A passing job is evidence for review, not automatic release acceptance. Candidate tags do not promise registry-enforced immutability.

Activation prerequisites: independent executable review, public-disclosure approval (including unsuccessful candidates), actual repository/environment protection verification, current dependency/source/security assessment and bounded Linux integration qualification. The environment `worker-publication` must already be configured with the intended reviewers; merely naming it in YAML does not enforce review. `GPU_PROBE_CI_ENABLED` is an off-switch, not proof of authority.

Build Actions are pinned to commits. The standard setup action acquires its maintained Buildx/BuildKit dependencies; their versions are recorded, not claimed bit-reproducible. BuildKit container resource options are 4 GiB RAM/no extra swap and 2 CPUs. The shared Docker daemon remains outside those container limits. Actual option enforcement and runner disk behaviour must be observed before activation. No persistent release cache is configured.

Anonymous runtime retrieval is separate from authenticated attestation verification. Signature verification binds repository, workflow, source commit, signer commit, main ref and GitHub-hosted builder. BuildKit SBOM/provenance and GitHub signed provenance serve different purposes. The index digest and runtime platform manifest digest are recorded separately.

Tests preserve the seven synthetic SSH cases, independent forwarding listener control, isolated nonroot import, source hashes/modes, host-key binding, effective SSH policy, second-start refusal, fresh known-identity-path layer scan, and owned-resource cleanup. The layer scan is not a universal secret detector. No real account values or user SSH keys are used.

On failed or interrupted publication, retain the run and reconcile the recorded digest before any new authorized dispatch. A new build, even from the same commit, is a new candidate. Never delete run history to pass a gate. No `latest` tag or automated release promotion is configured. Qualification evidence is retained as a bounded Actions artifact for 30 days and must be collected into the release record before expiry.

Resource limits are deliberately scoped: descriptor checks bound compressed input; the Docker daemon may expand layers before the later content scan. There is no claimed hard daemon disk quota. A disposable runner contains that failure, and activation requires measuring peak disk usage for this reviewed image. The Docker-save client has a 1 GiB RLIMIT_FSIZE; its real enforcement must be checked on Linux. Attestation output is bounded while read, and the complete JSON evidence set is checked against 20 MiB before upload. An oversized set fails visibly rather than uploading truncated evidence.
