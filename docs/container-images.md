# Container images

Prebuilt, multi-arch container images are published to the GitHub Container
Registry (GHCR) for every release and every push to `main`. Two variants are
built, differing only in base image:

| Variant | Base image | Tag suffix |
| --- | --- | --- |
| CentOS Stream | `quay.io/centos/centos` | *(none)* |
| Alpine | `alpine` | `-alpine` |

Both variants are built for `linux/amd64` and `linux/arm64` and published as a
single multi-arch manifest per variant, so `docker`/`podman` pulls the right
architecture automatically. The images are published as
`ghcr.io/voxpupuli/openvox-ca`.

## Pulling

```console
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest          # CentOS Stream
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest-alpine   # Alpine
```

## Available tags

| Tag | Points at |
| --- | --- |
| `latest` / `latest-alpine` | The most recent release |
| `1.2.3`, `1.2`, `1` (+ `-alpine`) | A specific release and its semver aliases |
| `edge` / `edge-alpine` | The latest build from the default branch (`main`) |
| `main` / `main-alpine` | Same as `edge`; the head of `main` |

Pin to a specific semver tag (e.g. `1.2.3`) for reproducible deployments;
`edge` tracks unreleased changes and can break at any time.

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
    --tls-cert=/data/ca_crt.pem --tls-key=/data/private/ca_key.pem
```

On first run this bootstraps a new CA under `/data` and serves HTTPS on port
8140, using the CA's own certificate as the TLS server certificate. (The
server refuses plain HTTP on a non-loopback address unless `--no-tls-required`
is set — only do that behind a trusted TLS-terminating proxy or in test
environments.) For a production deployment — a TLS certificate matching the
server's DNS name, mTLS, an alternative storage backend, autosigning — pass
the relevant flags (or mount a config file and set `--config`). See
[configuring the server](configuration.md) for the full reference, and the
[HTTP API reference](api.md) for the endpoints agents use.

### Compose

The [`compose.yml`](../compose.yml) at the repository root is the equivalent
Docker/Podman Compose deployment: edit `--hostname`, then `docker compose up
-d` (or `podman-compose up -d`). The `test/compose*.yml` files, by contrast,
are the integration-test topologies — they build throwaway images from the
working tree and are not deployment examples.

> **Autosigning is off by default.** Only set `--autosign-config=true` in
> dev/test environments: it lets any CSR submitter obtain a signed certificate
> without operator review.

## Publishing

How these images are built and published (the GitHub Actions workflow, the tag
matrix, and the one-time repository setup a maintainer performs) is documented
in [publishing container images](development/publishing-images.md).
