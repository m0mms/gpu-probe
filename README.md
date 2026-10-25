# GPU probe worker

A minimal container worker for synthetic registration and capability probes. It does not admit compute jobs (`compute_admitted` is false). Reported cgroup measurements are observations, not hardware attestation. This release does not establish suitability for arbitrary GPU workloads.

## Contents and licensing

The ten custom worker files under `context/` are covered by the scoped MIT license in `LICENSE` and `LICENSE-SCOPE.json`. Debian, Python, OpenSSH and other bundled components retain their own licenses and copyright notices. The container as a whole is not MIT licensed. Bundled package notices remain in the image.

`SOURCES.json` maps the 123 binary package versions to 84 source-package versions and lists 267 corresponding source files, with sizes, SHA-256 hashes and release locations. 259 files are flat release assets; eight filenames containing `~` are preserved inside `source-filenames-qualification-20261022.tar`. `SOURCES.json` supplies the archive hash and member mapping. Download the archive and the 259 flat files into one source directory. Verify the archive with:

```sh
printf '%s  %s\n' f0eeefb758c0c27f5b076b7b6e8c4d00bd22b4ced7d3b49511071e91bfa821b2 source-filenames-qualification-20261022.tar | sha256sum -c -
tar -xf source-filenames-qualification-20261022.tar
sha256sum -c SHA256SUMS.sources
```

The last command checks all 267 unmodified source files under their original names. The normalized `debianutils_5.7-0.5.deb12u1.debian.tar.xz` duplicate is retained as historical transport evidence and is not part of the canonical inventory. The original Git tag remains unchanged and predates this retrieval correction; the release description links the corrected inventory by immutable commit. Upstream snapshot links provide provenance; the release assets provide the distributor-hosted source copy.

## Image and build reference

`IMAGE.json` identifies the expected Linux amd64 image manifest and release tag. `Dockerfile.reference` documents the functional build recipe before a separate offline notice layer was added. It is not a promise of bit-for-bit reconstruction of the final image. The notice layer preserved all original compressed layers and runtime configuration. The original worker image passed synthetic qualification; the final notice-bearing image has not been runtime-retested. No live GPU qualification is claimed.

These files are a staged release preview. The repository, image and source URLs are proposed destinations until publication is independently verified.
