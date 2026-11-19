# Container images

Prebuilt, multi-arch container images are published to the GitHub Container
Registry (GHCR) for every release and every push to `main`. Two variants are
built, differing in base image:

| Variant | Base image | Tag suffix | Runs as |
| --- | --- | --- | --- |
| Distroless (the default) | `gcr.io/distroless/static-debian13:nonroot` | *(none)*, or `-distroless` | `65532:65532` |
| Alpine | `alpine` | `-alpine` | `65532:65532` |

Every variant is built for `linux/amd64` and `linux/arm64` and published as a
single multi-arch manifest per variant, so `docker`/`podman` pulls the right
architecture automatically. The images are published as
`ghcr.io/voxpupuli/openvox-ca`.

The distroless variant holds the two binaries, a CA trust store and little
else: no shell, no package manager, no `curl` or `kill`. It has the least in it
to patch or to exploit, and what that costs is listed under [the distroless
variant](#the-distroless-variant). Its tags carry no suffix, and each is
published again with `-distroless` appended, for anyone who wants to name the
variant. The Alpine variant adds a shell and busybox. Both run as the same uid,
so either can take over data the other wrote.

## Pulling

```console
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest          # distroless
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest-alpine   # Alpine
```

`latest` names the most recent final release, so it first appears with 1.0.0.
Until then, pull `edge`. The pre-releases so far predate the configuration
the examples below rely on, so their own documentation applies to them.

## Available tags

| Tag | Points at |
| --- | --- |
| `latest` / `latest-distroless` / `latest-alpine` | The most recent final release; pre-releases never move it, so it does not exist before 1.0.0 |
| `1.2.3`, `1.2`, `1` (+ `-distroless`, `-alpine`) | A specific release and its semver aliases; the major-only tag (`1`) is published for v1+ releases only, so `0.x` releases have no `0` tag |
| `edge` / `edge-distroless` / `edge-alpine` | The latest build from the default branch (`main`) |
| `main` / `main-distroless` / `main-alpine` | Same as `edge`; the head of `main` |

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

The image's entrypoint is `openvox-ca`, and its default command is
`--cadir=/etc/puppetlabs/puppet/ssl/ca --verbosity=1`. Any arguments you pass
are appended to the entrypoint, exactly like running the binary, and replace
that command entirely, so restate `--cadir` in them. While the default command
runs, its `--cadir` also outranks a `cadir` set in a configuration file.

Mount a volume at `/etc/puppetlabs/puppet/ssl` so the CA survives container
restarts, and publish port 8140:

```console
$ docker run -d --name openvox-ca \
    -p 8140:8140 \
    -v openvox-ca-ssl:/etc/puppetlabs/puppet/ssl \
    ghcr.io/voxpupuli/openvox-ca:latest
```

On first run this bootstraps a new CA under `/etc/puppetlabs/puppet/ssl/ca`, and
the CA issues its own serving certificate, for the names `puppet` and
`localhost`, into `/etc/puppetlabs/puppet/ssl` beside it. Its certname, the
inventory slot it occupies, is `openvox-ca` rather than `puppet`, so on a CA
carried over from Puppet it does not displace an existing `puppet` certificate. The volume keeps both,
and the CA renews the certificate before it expires. A volume mounted somewhere
else, with `--cadir` pointed into it, keeps the CA but not the certificate,
which the baked configuration always writes to `/etc/puppetlabs/puppet/ssl`:
the CA issues a new one whenever the container is recreated. Give such a
deployment its own configuration, with the `store` paths on that volume. An
agent left at its default server name, `puppet`, verifies that certificate as it stands, and the CA's
private key stays in the signer process rather than on the listener (see
[process isolation](ca-key-security.md#process-isolation)).

That comes from the configuration baked into the image at
`/etc/openvox-ca/config.yaml`
([its source](https://github.com/voxpupuli/openvox-ca/blob/main/packaging/container/config.yaml)),
which sets [`serving_cert`](configuration.md#the-cas-own-serving-certificate)
and nothing else. To serve another name, or to configure anything else (mTLS,
a storage backend, autosigning), mount your own file over it, or set
`OPENVOX_CA_CONFIG` to where you mounted it. The [health check](#health-check)
reads the same file. Yours replaces the baked one entirely, so keep a
`serving_cert` block in it unless you supply the certificate yourself:

```yaml
serving_cert:
  certname: ca.example.com
  names: [ca.example.com, puppet]
  ttl: 2160h
  renew_before: 720h
  usages: [serverAuth]   # as the baked file; leaving it out adds clientAuth
  store:
    files:
      cert: /etc/puppetlabs/puppet/ssl/serving_crt.pem
      key: /etc/puppetlabs/puppet/ssl/serving_key.pem
```

Give it a certname nothing else enrols under, as the baked file does: issuing
under the certname of an existing certificate displaces it from its inventory
slot.

**`--tls-cert` and `--tls-key` do not combine with the baked configuration.**
`serving_cert` and `tls_cert`/`tls_key` are two answers to which certificate
the listener presents, and the server refuses to start with both. To supply
your own certificate, put `tls_cert` and `tls_key` in the file you mount, or
run the server with no configuration file at all and pass the flags, restating
`--cadir` with them:

```console
$ docker run -d --name openvox-ca -p 8140:8140 \
    -v openvox-ca-ssl:/etc/puppetlabs/puppet/ssl \
    -e OPENVOX_CA_CONFIG=/dev/null \
    ghcr.io/voxpupuli/openvox-ca:latest \
    --cadir=/etc/puppetlabs/puppet/ssl/ca \
    --tls-cert=/etc/puppetlabs/puppet/ssl/tls.crt \
    --tls-key=/etc/puppetlabs/puppet/ssl/tls.key
```

**Behind a TLS-terminating proxy**, the same applies to `--no-tls-required`:
the baked configuration always serves TLS, so the flag has no effect while it is
in place, and the server says so at startup. Run with
`-e OPENVOX_CA_CONFIG=/dev/null`, `--cadir=/etc/puppetlabs/puppet/ssl/ca` and
`--no-tls-required`, or mount a configuration without `serving_cert` that sets
`no_tls_required: true`. Only do this behind a trusted proxy, or in a test
environment. Without TLS the server installs no authorisation at all, so every
endpoint, the administrative ones included, answers anything that can reach
port 8140 (see [the HTTP API reference](api.md)). Publish the port to the proxy
alone, on a private network or bound to loopback with
`-p 127.0.0.1:8140:8140`, never with the `-p 8140:8140` the examples above use.
See [configuring the
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

Both variants run as uid/gid **65532**: the distroless base image's own
`nonroot` user, and a `puppet` user created with that uid in the Alpine image.
Each declares its user numerically, so that a host
which cannot read the image's `/etc/passwd` can still tell who the process runs
as. Under Kubernetes, a container whose image only names its user fails to
start when the pod sets `runAsNonRoot` without also setting `runAsUser` — the
kubelet cannot verify that a name is non-root, and the container stops at
`CreateContainerConfigError`.

A named volume like the one above is created with the right ownership
automatically. A bind mount is not, so `chown` the host directory to
`65532:65532` before starting the container, or the CA cannot write its state. Under rootless Podman
the container's uid maps to a subordinate uid on the host, so a plain `chown`
leaves the directory unwritable — use `podman unshare chown <uid>:<gid> <dir>`,
or mount with the `:U` suffix. Under Kubernetes, `fsGroup` on the pod covers
PersistentVolumeClaims and `emptyDir`, but the kubelet does not apply it to a
`hostPath`, which needs the same treatment as a bind mount.

**Data written by a container that ran as another uid** does not follow by
itself. The private keys are written `0600`, readable by their owner alone, and
openvox-ca never changes the owner or mode of an existing file. Re-own a Docker
or Podman volume or bind mount to `65532:65532` before starting the container,
and do it for every volume the CA reads, not only its `--cadir`: a
`crl_chain_file` kept on another volume and left unreadable fails every chain
refresh. Under Kubernetes the Helm chart runs the pod as `65532:65532` through
`podSecurityContext`. Where the kubelet applies `fsGroup` to the volume, as it
does to most PersistentVolumeClaims and to `emptyDir`, it re-groups data another
uid wrote and adds group read and write, so the pod can take it over; a
`hostPath`, or a driver without `fsGroup` support, needs re-owning like a bind
mount. See [choosing an image](helm-chart.md#choosing-an-image).

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
- **Healthchecks.** A Docker or Compose healthcheck that runs `curl` or `wget`
  cannot run here. The image's own [health check](#health-check), `openvox-ca
  healthcheck`, needs neither, and Kubernetes `httpGet` probes are unaffected,
  because the kubelet makes the request from outside the container.
- **A policy-based autosign executable** written as a script needs its
  interpreter, which the image does not have. Use a statically linked
  executable, or another variant.

### Health check

Every image declares a `HEALTHCHECK` that runs `openvox-ca healthcheck`, so
`docker ps` and `podman ps` report the container's health without any
configuration. It requests `/healthz/ready` every 30 seconds and marks the
container unhealthy after three failures in a row. The first two minutes are a
grace period, because the first start generates the CA key; the first check
that passes ends it.

The check is its own process. It sees the container's environment and the
server's config file, but not the arguments the server was started with:

- **Port.** It reads `port` from the config file that `OPENVOX_CA_CONFIG`
  names, or else `/etc/openvox-ca/config.yaml`, and from `OPENVOX_CA_PORT`, as
  the server does, and defaults to 8140. A file passed to the server with
  `--config` is invisible to it. To move the port, set `OPENVOX_CA_PORT` on the
  container rather than passing `--port`, so the server and the check agree. A
  server listening on every address is checked over loopback; one bound with
  `host` to a specific address is checked there.
- **Scheme.** It tries HTTPS first and falls back to plain HTTP only when the
  server answers in plain HTTP, so TLS enabled anywhere the check cannot see,
  such as `--tls-cert` on the command line under `OPENVOX_CA_CONFIG=/dev/null`,
  needs nothing repeated.
- **Certificate.** It does not verify the server's certificate. It sends no
  credentials and reads nothing but the status code, and it has no way to know
  which name or CA a deployment's certificate should verify against: a CA
  serving its own certificate, which cannot be verified at all, is still
  reported healthy.

It exits 0 when the endpoint answers 200, and 1 otherwise with a one-line
reason, which `docker inspect --format '{{json .State.Health}}' openvox-ca`
shows. To change what it checks, override it with the exec form, which works in
an image without a shell:

```yaml
    healthcheck:
      test: ["CMD", "/usr/local/bin/openvox-ca", "healthcheck", "--port", "8141"]
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--probe` | `ready` | `live`, `ready` or `startup`: which `/healthz/` endpoint to request |
| `--port` | from configuration | Port to check |
| `--host` | from configuration | Address to check |
| `--config` | `OPENVOX_CA_CONFIG`, else `/etc/openvox-ca/config.yaml` | The server's config file |
| `--timeout` | `3s` | Give up and report unhealthy after this long |

Kubernetes ignores an image's `HEALTHCHECK`. The [Helm chart](helm-chart.md)
uses the kubelet's own HTTP probes on the same three endpoints instead, which
cost the pod nothing between checks.

### Compose

The [`compose.yml`](https://github.com/voxpupuli/openvox-ca/blob/main/compose.yml) at the repository root is the equivalent
Docker/Podman Compose deployment: `docker compose up -d` (or `podman-compose
up -d`). It declares no healthcheck of its own, so the
service has the image's [health check](#health-check). The
`test/compose*.yml` files, by contrast,
are the integration-test topologies — they build throwaway images from the
working tree and are not deployment examples.

> **Autosigning is off by default.** Only enable it in dev/test environments,
> with `autosign_config: "true"` in a configuration you mount or
> `OPENVOX_CA_AUTOSIGN_CONFIG=true` under the service's `environment:`: it lets
> any CSR submitter obtain a signed certificate without operator review.

## Publishing

How these images are built and published (the GitHub Actions workflow, the tag
matrix, and the one-time repository setup a maintainer performs) is documented
in [publishing container images](development/publishing-images.md).
