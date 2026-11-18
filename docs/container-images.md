# Container images

Prebuilt, multi-arch container images are published to the GitHub Container
Registry (GHCR) for every release and every push to `main`. Three variants are
built, differing in base image and in the user they run as:

| Variant | Base image | Tag suffix | Runs as |
| --- | --- | --- | --- |
| CentOS Stream | `quay.io/centos/centos` | *(none)* | `1000:1000` |
| Alpine | `alpine` | `-alpine` | `1000:1000` |
| Distroless | `gcr.io/distroless/static-debian13:nonroot` | `-distroless` | `65532:65532` |

Every variant is built for `linux/amd64` and `linux/arm64` and published as a
single multi-arch manifest per variant, so `docker`/`podman` pulls the right
architecture automatically. The images are published as
`ghcr.io/voxpupuli/openvox-ca`.

The distroless variant holds the two binaries, a CA trust store and little
else: no shell, no package manager, no `curl` or `kill`. It has the least in it
to patch or to exploit, and what that costs is listed under [the distroless
variant](#the-distroless-variant). It runs as a **different uid** from the
other two, so switching an existing deployment to or from it means re-owning
its data; see [runtime user](#runtime-user).

## Pulling

```console
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest              # CentOS Stream
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest-alpine       # Alpine
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest-distroless   # distroless
```

## Available tags

| Tag | Points at |
| --- | --- |
| `latest` / `latest-alpine` / `latest-distroless` | The most recent release |
| `1.2.3`, `1.2`, `1` (+ `-alpine`, `-distroless`) | A specific release and its semver aliases; the major-only tag (`1`) is published for v1+ releases only, so `0.x` releases have no `0` tag |
| `edge` / `edge-alpine` / `edge-distroless` | The latest build from the default branch (`main`) |
| `main` / `main-alpine` / `main-distroless` | Same as `edge`; the head of `main` |

Pin to a specific semver tag (e.g. `1.2.3`) for reproducible deployments;
`edge` tracks unreleased changes and can break at any time.

## Verifying an image

Every published image is signed and carries SLSA v1.0 build provenance, through
Sigstore — there is no long-lived signing key involved. Pin the identity to the
release shape rather than accepting anything this repository signed, because
pull-request builds are signed too:

```console
$ cosign verify ghcr.io/voxpupuli/openvox-ca:1.2.3 \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github\.com/voxpupuli/openvox-ca/\.github/workflows/container-images\.yml@refs/tags/v'
```

Each per-architecture image also carries an SBOM in both SPDX-JSON and
CycloneDX-JSON, catalogued from the image itself so the base-layer packages are
included as well as the Go modules. Those are attached to the architecture
digests, not to the multi-arch index a tag resolves to; see [verifying what you
downloaded](../README.md#verifying-what-you-downloaded) for the two-step form,
and [verifying a release](development/releasing.md#verifying-a-release) for what
each check does and does not prove.

## Running

The image's entrypoint is `openvox-ca`; any arguments you pass are appended to
it, exactly like running the binary. Mount a volume for the CA directory so the
CA survives container restarts, and publish port 8140:

```console
$ docker run -d --name openvox-ca \
    -p 8140:8140 \
    -v openvox-ca-data:/data \
    ghcr.io/voxpupuli/openvox-ca:latest \
    --cadir=/data --hostname=puppet.example.com \
    --tls-cert=/data/ca_crt.pem --tls-key=/data/ca_key.pem
```

On first run this bootstraps a new CA under `/data` and serves HTTPS on port
8140, using the CA's own certificate as the TLS server certificate. (The
server refuses plain HTTP on a non-loopback address unless `--no-tls-required`
is set — only do that behind a trusted TLS-terminating proxy or in test
environments.)

That last part makes the command self-contained, and nothing else: the CA
certificate's `keyUsage` is `certSign, cRLSign` and it has no
`subjectAltName`, so no agent will accept the connection. The server warns
about this at startup; see [serving
certificate](configuration.md#serving-certificate). Before any agent talks to
this CA, either let the CA issue its own with
[`serving_cert`](configuration.md#the-cas-own-serving-certificate) — which
removes this bootstrap entirely and renews the certificate unattended, which
nothing else does once the CA key is held at a provider — or issue one with `openvox-ca-ctl generate` and
point `--tls-cert`/`--tls-key` at that. The same goes for the rest of a
production deployment — mTLS, an alternative storage backend, autosigning: pass the
relevant flags, or mount a config file and set `--config`. See [configuring the
server](configuration.md) for the full reference, and the [HTTP API
reference](api.md) for the endpoints agents use.

### Memory limits

If you set a memory limit — `--memory`, podman's `-m`, or a compose `mem_limit`
— the launcher reads it from the container's **cgroup v2** ceiling and divides
it across the three processes it runs (a supervisor, an isolated signer and the
frontend), rather than letting each apply the whole of it. On a cgroup v1 host
nothing is derived; set `GOMEMLIMIT` on the container instead. `GOMEMLIMIT` set
on the container likewise names the budget for the whole tree, not for one
process. See [memory budget](configuration.md#memory-budget).

### Runtime user

The CentOS Stream and Alpine variants run as the non-root user `puppet`,
uid/gid **1000**. The distroless variant runs as uid/gid **65532**, the base
image's own `nonroot` user. Each declares its user numerically, so that a host
which cannot read the image's `/etc/passwd` can still tell who the process runs
as. Under Kubernetes, a container whose image only names its user fails to
start when the pod sets `runAsNonRoot` without also setting `runAsUser` — the
kubelet cannot verify that a name is non-root, and the container stops at
`CreateContainerConfigError`.

A named volume like the one above is created with the right ownership
automatically. A bind mount is not, so `chown` the host directory to the
variant's uid and gid (`1000:1000`, or `65532:65532` for distroless) before
starting the container, or the CA cannot write its state. Under rootless Podman
the container's uid maps to a subordinate uid on the host, so a plain `chown`
leaves the directory unwritable — use `podman unshare chown <uid>:<gid> <dir>`,
or mount with the `:U` suffix. Under Kubernetes, `fsGroup` on the pod covers
PersistentVolumeClaims and `emptyDir`, but the kubelet does not apply it to a
`hostPath`, which needs the same treatment as a bind mount.

**Switching between distroless and either other variant changes the uid**, and
the CA's state does not follow by itself. The private keys are written `0600`,
readable by their owner alone, so the new variant cannot read a key the old one
wrote, and openvox-ca never changes the owner or mode of an existing file.
Re-own the volume or bind mount to the new uid and gid before starting the new
variant. Under Kubernetes, set the pod's `runAsUser`, `runAsGroup` and
`fsGroup` to match the variant: `fsGroup` re-groups the volume, but it leaves
each file's owner as it was.

### The distroless variant

With no shell in the image, anything that runs one inside the container does
not work, and needs another route:

- **Running `openvox-ca-ctl`.** Exec the binary directly, which needs no shell:
  `docker exec <container> openvox-ca-ctl …`, or `kubectl exec <pod> --
  openvox-ca-ctl …`. `sh -c '…'` fails.
- **Reloading on `SIGHUP`.** There is no `kill` to exec. Send the signal from
  outside instead: `docker kill --signal=HUP <container>`, or `podman kill
  --signal=HUP`. Under Kubernetes, `kubectl rollout restart` works for every
  variant. To signal without a restart, run `kill` from an ephemeral container
  that joins the server's process namespace: `kubectl debug -it <pod>
  --profile=restricted --image=docker.io/library/busybox:1.37@sha256:<digest>
  --target=openvox-ca -- kill -HUP 1`. It must run as the server's uid, which a
  pod-level `runAsUser` gives it, and `--profile=restricted` lets a namespace
  that enforces the `restricted` Pod Security standard admit it. That container
  can read the CA's private keys through the server's `/proc/1/root`, so pin the
  image by digest and give it the trust you give the CA image itself.
- **Healthchecks.** A Docker or Compose healthcheck that runs `curl` or `wget`,
  such as the one in this repository's
  [`compose.yml`](https://github.com/voxpupuli/openvox-ca/blob/main/compose.yml),
  cannot run here. Kubernetes `httpGet` probes are unaffected, because the
  kubelet makes the request from outside the container.
- **A policy-based autosign executable** written as a script needs its
  interpreter, which the image does not have. Use a statically linked
  executable, or another variant.

### Compose

The [`compose.yml`](https://github.com/voxpupuli/openvox-ca/blob/main/compose.yml) at the repository root is the equivalent
Docker/Podman Compose deployment: edit `--hostname`, then `docker compose up
-d` (or `podman-compose up -d`). Its healthcheck runs `curl` or `wget` inside
the container, so it does not work with the distroless variant. The
`test/compose*.yml` files, by contrast,
are the integration-test topologies — they build throwaway images from the
working tree and are not deployment examples.

> **Autosigning is off by default.** Only set `--autosign-config=true` in
> dev/test environments: it lets any CSR submitter obtain a signed certificate
> without operator review.

## Publishing

How these images are built and published (the GitHub Actions workflow, the tag
matrix, and the one-time repository setup a maintainer performs) is documented
in [publishing container images](development/publishing-images.md).
