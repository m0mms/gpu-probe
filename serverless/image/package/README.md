# Synthetic CUDA qualification test

This package tests one small double-precision CUDA kernel and deliberate compiler failure. It accepts no external kernel source or application datasets. It does not establish scientific correctness, provider security, termination or billing cessation.

The positive check uploads 257 float64 integers from -128 to 128 and NaN output sentinels, computes 2*x+1, checks every output exactly, and releases owned allocations and context. The negative check must reject the intentionally invalid kernel with its specific marker and release owned resources. No automatic retry is performed.

Host guards require sampled RSS no greater than 6 GiB, a finite cgroup memory limit no greater than 8 GiB, address-space limit no greater than 48 GiB and at most three threads. These guards are not proof that a provider worker satisfies those conditions. GPU allocation accounting does not include all compiler or driver overhead.

Direct execution refuses. A separately reviewed supervisor must provide the exact library identities, device and compiler/driver versions, and establish applicable resource and execution authority. A hash establishes integrity, not permission. Results never establish provider cleanup or billing cessation.

Local simulation tests use a fake backend and do not qualify native CUDA. The CPU-only CI compiler test does not load a GPU driver or execute a kernel. Real GPU execution requires a separate approved test.
