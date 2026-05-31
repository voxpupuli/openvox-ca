# Container images

The [`Container images`](../.github/workflows/container-images.yml) workflow
builds the two runtime images and publishes multi-arch manifests to the GitHub
Container Registry (GHCR).

| Variant       | Dockerfile                              | Base image              | Tag suffix |
| ------------- | --------------------------------------- | ----------------------- | ---------- |
| CentOS Stream | [`Dockerfile`](../Dockerfile)           | `quay.io/centos/centos` | *(none)*   |
| Alpine        | [`Dockerfile.alpine`](../Dockerfile.alpine) | `alpine`            | `-alpine`  |

Both variants are built for `linux/amd64` and `linux/arm64` and published as a
single multi-arch manifest per variant. The image name follows the repository:
`ghcr.io/<owner>/golang-puppet-ca`.

```console
$ docker pull ghcr.io/<owner>/golang-puppet-ca:latest          # CentOS Stream
$ docker pull ghcr.io/<owner>/golang-puppet-ca:latest-alpine   # Alpine
```

## When images are built

| Trigger | What happens |
| --- | --- |
| **Push to `main`** | Builds both variants on both architectures and pushes the rolling `edge` (and `main`) tags, plus their `-alpine` counterparts. `edge` always points at the latest default-branch build. |
| **Release tag** (`git push` of a `v*` tag) | Builds both variants on both architectures and pushes the semver tags (`1.2.3`, `1.2`, `1`), `latest`, and their `-alpine` counterparts. |
| **Manual** (Actions → *Container images* → *Run workflow*) | Builds everything. Pushes only if you tick the **push** input; otherwise it builds and smoke-tests without publishing. |
| **Pull request** | Builds nothing by default. Apply the **`build-images`** label to a PR to build both variants on both architectures as a validation check. Same-repo PRs also push a throwaway `pr-<n>` tag; fork PRs build only (their token cannot write packages). |

Architecture builds run on native GitHub-hosted runners — `ubuntu-latest`
(amd64) and `ubuntu-24.04-arm` (arm64) — and the per-architecture digests are
merged into the final manifest. No QEMU emulation is involved, so arm64 builds
run at native speed.

## One-time repository setup (for the repository owner)

These steps must be performed once by someone with admin access to the upstream
repository. Until then, release/manual builds will fail at the push step and PR
validation builds will still work (they don't push).

1. **Allow Actions to publish packages.**
   Settings → Actions → General → *Workflow permissions*. The workflow already
   requests `packages: write`, but if an organization policy overrides this,
   select **Read and write permissions** (or explicitly allow the
   `GITHUB_TOKEN` to write packages for this repository).

2. **Publish a release to create the package, then set its visibility.**
   The GHCR package is created on the first successful push and is **private**
   by default. To make the images publicly pullable: your profile/org →
   *Packages* → `golang-puppet-ca` → *Package settings* → *Change visibility* →
   **Public**. The package is automatically linked to this repository via the
   `org.opencontainers.image.source` label.

3. **Create the `build-images` label.**
   Issues → *Labels* → *New label*, name it exactly `build-images`. Maintainers
   apply this label to a PR to opt it into a container build. Because applying a
   label requires triage/write access, contributors cannot self-trigger builds.

4. **arm64 runners.**
   The `ubuntu-24.04-arm` runner used for arm64 is free for **public**
   repositories. For a private repository you must provision arm64 runners
   (GitHub-hosted larger runners or self-hosted) or the arm64 build jobs will
   queue indefinitely.

5. **Fork pull-request approval (the build "gate").**
   GitHub holds workflow runs on PRs from first-time contributors until a
   maintainer approves them (Settings → Actions → General → *Fork pull request
   workflows from outside collaborators*). Combined with the `build-images`
   label, this means fork PRs only build after a maintainer both approves the
   run and applies the label — and even then they never push.
