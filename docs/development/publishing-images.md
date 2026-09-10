# Publishing container images

> This is a maintainer/CI reference. If you only want to **run** the published
> images, see [container images](../container-images.md). For the release
> process that triggers the versioned image builds, see
> [cutting a release](releasing.md).

The [`Container images`](../../.github/workflows/container-images.yml) workflow
builds the two runtime images and publishes multi-arch manifests to the GitHub
Container Registry (GHCR).

| Variant | Dockerfile | Base image | Tag suffix |
| --- | --- | --- | --- |
| CentOS Stream | [`Dockerfile`](../../Dockerfile) | `quay.io/centos/centos` | *(none)* |
| Alpine | [`Dockerfile.alpine`](../../Dockerfile.alpine) | `alpine` | `-alpine` |

Both variants are built for `linux/amd64` and `linux/arm64` and published as a
single multi-arch manifest per variant, as `ghcr.io/voxpupuli/openvox-ca`.

## When images are built

| Trigger | What happens |
| --- | --- |
| **Push to `main`** | Builds both variants on both architectures and pushes the rolling `edge` (and `main`) tags, plus their `-alpine` counterparts. `edge` always points at the latest default-branch build. |
| **Release tag** (`git push` of a `v*` tag) | Builds both variants on both architectures and pushes the semver tags (`1.2.3`, `1.2`, and — for v1+ only — `1`), `latest`, and their `-alpine` counterparts. The major-only tag is suppressed for `v0.*` because a `0.x` major carries no compatibility promise. |
| **Manual** (Actions → *Container images* → *Run workflow*) | Builds everything. Pushes only if you tick the **push** input; otherwise it builds and smoke-tests without publishing. |
| **Pull request** | Always builds both variants on both architectures as a validation check. Same-repo PRs also push a throwaway `pr-<n>` tag; fork PRs build only and discard the result (their token cannot write packages). |

Architecture builds run on native GitHub-hosted runners — `ubuntu-latest`
(amd64) and `ubuntu-24.04-arm` (arm64) — and the per-architecture digests are
merged into the final manifest. No QEMU emulation is involved, so arm64 builds
run at native speed.

## Provenance, SBOMs and signatures

Every push — release tags, `edge`/`main`, and same-repo PR tags alike — is
signed. Fork PRs push nothing and so sign nothing; their token could not mint a
certificate in any case. Everything is keyed off the same `setup.outputs.push`
output as the build itself, so "was it published" and "was it signed" cannot
diverge.

| Where | What is attached | Attached to |
| --- | --- | --- |
| `build` (×4) | SLSA v1.0 provenance; SBOMs in SPDX-JSON and CycloneDX-JSON | The per-architecture digest |
| `merge` (×2) | SLSA v1.0 provenance; a `cosign sign` signature, `--recursive` | The index digest — and, via `--recursive`, each child manifest |

The per-architecture images are the ones worth cataloguing: each has its own
binary and its own base package set, so the SBOM records whichever CentOS
Stream or Alpine packages that variant installs, as well as the Go modules.
The packages are deliberately not enumerated here: each image's `dnf install` or
`apk add` line is the authority, and naming a subset in prose guarantees this
sentence is wrong the next time one of them changes.
Syft reads the image back out of the registry by digest rather than scanning a
local rebuild, so the document describes what was actually pushed. The merged
index carries provenance only; an SBOM of an index would just be the union of
documents already attached to its children.

Attestations are pushed to the registry (`push-to-registry: true`), so they are
discoverable through the OCI 1.1 referrers API and readable with `cosign` as
well as `gh attestation verify`. `cosign sign` runs in addition to the
attestations because an admission policy that asserts "this image is signed"
wants a signature, not a predicate — `cosign verify` and
`cosign verify-attestation` are different checks.

**BuildKit's own attestations remain disabled** (`provenance: false`). They are
unsigned, so they do not establish authenticity on their own, and the extra
manifests they create are what breaks the push-by-digest + `imagetools create`
merge in the first place. The attestations above replace them rather than
supplement them.

### Nothing re-resolves a tag

A tag is mutable, so re-reading one between publishing and signing would open a
window in which the thing signed is not the thing published. The workflow avoids
that end to end:

- Per-architecture images are pushed with `push-by-digest=true` and never receive
  a tag at all; `docker/build-push-action` reports the digest it pushed, and that
  digest is what crosses the job boundary.
- `imagetools create --metadata-file` reports the digest of the index it just
  pushed. The obvious alternative — `imagetools inspect <tag>` — is a fresh tag
  resolution and is exactly the race being avoided.
- `actions/attest` is given `subject-digest`; `cosign sign` is given
  `${IMAGE}@${digest}`. `cosign sign` will accept a tag, which is why this is
  worth stating: signing one would be the mistake.
- After signing, the job asserts that every tag it published still resolves to
  the digest that was signed, and fails if not. That does not prevent a race — it
  converts one from a silently unsigned tag into a red build.

See [verifying a release](releasing.md#verifying-a-release) for the verification
commands and what each of them proves.

## One-time repository setup (for the repository owner)

These steps must be performed once by someone with admin access to the upstream
repository. Until then, release/manual builds will fail at the push step and PR
validation builds will still work (they don't push).

1. **Allow Actions to publish packages.**
   Settings → Actions → General → *Workflow permissions*. The build and merge
   jobs already request `packages: write` (the grant is per-job, not
   workflow-wide), but if an organization policy overrides this, select
   **Read and write permissions** (or explicitly allow the `GITHUB_TOKEN` to
   write packages for this repository).

2. **Publish a release to create the package, then set its visibility.**
   The GHCR package is created on the first successful push and is **private**
   by default. To make the images publicly pullable: your profile/org →
   *Packages* → `openvox-ca` → *Package settings* → *Change visibility* →
   **Public**. The package is automatically linked to this repository via the
   `org.opencontainers.image.source` label.

3. **Set the Helm chart package's visibility too.**
   The chart is published by [`helm-chart.yml`](../../.github/workflows/helm-chart.yml)
   into a *second*, separate GHCR package —
   `openvox-ca-charts/openvox-ca` — because one package cannot hold both
   container images and a chart. It is created private on its first push and
   needs the same *Change visibility* → **Public** treatment. Unlike the image
   package it carries no `image.source` label, so link it to this repository by
   hand from its package settings page.

4. **arm64 runners.**
   The `ubuntu-24.04-arm` runner used for arm64 is free for **public**
   repositories. For a private repository you must provision arm64 runners
   (GitHub-hosted larger runners or self-hosted) or the arm64 build jobs will
   queue indefinitely.

5. **Fork pull-request approval (the build "gate").**
   GitHub holds workflow runs on PRs from first-time contributors until a
   maintainer approves them (Settings → Actions → General → *Fork pull request
   workflows from outside collaborators*). Fork PRs still build once approved,
   but their `GITHUB_TOKEN` is read-only, so the build result is discarded
   rather than pushed.
