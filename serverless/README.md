# Serverless synthetic qualification

Two manual workflows have different authority and outcomes:

- `serverless-validation.yml` retains the general zero-findings gate and never publishes images.
- `attended-synthetic.yml` is the dated one-campaign exception: one Linux/amd64 CPU build, installed SDK/compiler checks, full scan, then publication to `ghcr.io/m0mms/gpu-probe` under a source-specific tag. It requires the exact reviewed commit activation, refuses reruns and expires before 2026-11-23. It accepts unresolved OS LOW/MEDIUM/HIGH/UNKNOWN findings only for this synthetic image publication; CRITICAL, Python or suppressed findings refuse. This is not a reusable security clearance or permission to create GPU resources.

Both retain raw scan/inventory evidence. General scan failure remains recorded; it is not relabeled as a clean image. Fresh evidence and independent review are still required before the separate attended GPU attempt.

The worker accepts only the fixed synthetic request. It binds the unchanged package, claims one filesystem-local attempt marker, observes and hashes the installed NVRTC/provider driver, and checks device 0 (one visible GPU, compute 8.9), NVRTC 12.9 and driver >=12.9 before calling the frozen test. These hashes establish observed identity, not trusted provenance. The wrapper guard permits a finite visible cgroup ceiling <=64GiB, sampled RSS <=6GiB, address space <=48GiB and 3 threads. It does not claim hidden-ancestor verification or hard RSS containment. No user credentials or research inputs are included.

Returned `synthetic_native_fail` is failure even when the provider reports `COMPLETED`. Consumers must bind the saved job ID and validate the typed receipt and bounded evidence using `image/receipt.py`. Provider-injected credentials, SDK pre-handler processing and worker replacement/replay remain residual risks. The local marker is not global exactly-once protection.

Neither workflow creates provider resources. EU placement, live price, exact endpoint configuration, attendance and external cleanup are separate prerequisites. Public source and image publication require the owner's applicable authority. CI timeout/cancellation can interrupt evidence capture; container limits are not a hard daemon/disk quota.

Custom source is MIT under LICENSE-SCOPE.json. Referenced dependencies retain their licenses. No third-party binaries or SDK snapshot are included in this source; the built image contains the locked dependencies.
