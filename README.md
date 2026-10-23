# GPU probe worker

A minimal container worker for synthetic registration and capability probes. It does not admit compute jobs (`compute_admitted` is false). Reported cgroup measurements are observations, not hardware attestation. This release does not establish suitability for arbitrary GPU workloads.

## Contents and licensing

The ten custom worker files under `context/` are covered by the scoped MIT license in `LICENSE` and `LICENSE-SCOPE.json`. Debian, Python, OpenSSH and other bundled components retain their own licenses and copyright notices. The container as a whole is not MIT licensed. Bundled package notices remain in the image.

`SOURCES.json` maps the 123 binary package versions to 84 source-package versions and lists 267 corresponding source files, with sizes, SHA-256 hashes and release locations. `SHA256SUMS.sources` checks those unmodified release assets. Upstream snapshot links provide provenance; the release assets provide the distributor-hosted source copy.

## Image and build reference

`IMAGE.json` identifies the expected Linux amd64 image manifest and release tag. `Dockerfile.reference` documents the functional build recipe before a separate offline notice layer was added. It is not a promise of bit-for-bit reconstruction of the final image. The notice layer preserved all original compressed layers and runtime configuration. The original worker image passed synthetic qualification; the final notice-bearing image has not been runtime-retested. No live GPU qualification is claimed.

These files are a staged release preview. The repository, image and source URLs are proposed destinations until publication is independently verified.
