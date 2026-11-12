# Serverless synthetic validation candidate

This is an unbuilt candidate for one no-push Linux/amd64 CI validation. No successful installed-SDK, compiler or GPU result is claimed by the source package.

The manual workflow builds locally, tests installed Runpod SDK behaviour with transport mocked, loads NVRTC and compiles positive/negative synthetic kernels without a GPU, scans OS and Python packages, and retains JSON evidence. It does not publish an image or create provider resources. It requires a reviewed exact commit SHA and separate execution approval.

Returned `synthetic_native_fail` is a test failure even if provider delivery is `COMPLETED`. A consumer must use the saved job ID and the exact typed success receipt (`image/receipt.py`). SDK failures outside the handler may include diagnostics; this is not universal log containment.

The worker image contains no admission file or credentials. Resource admission, driver compatibility, provider retries, actual GPU execution and external cleanup remain separate gates. Dependencies are pinned, not declared vulnerability-free; any reported finding blocks this validation's security gate pending review.

The workflow runs for at most 30 minutes. Build and test container limits do not impose a hard quota on the Docker daemon or disk. Timeout or cancellation can interrupt final evidence collection. Repository publication and Actions use require the owner's applicable authority.

Custom source is licensed under MIT, as scoped in LICENSE-SCOPE.json. Referenced dependencies and container components retain their own licenses. No third-party library binaries or SDK source snapshot are distributed here.
