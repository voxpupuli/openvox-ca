# openvox-ca

---

> 🤖 LLM/AI WARNING 🤖
>
> This project was largely written by [Claude](https://claude.ai/)
> It has been reviewed and tested, but use in production at your own discretion.
>
> 🤖 LLM/AI WARNING 🤖

---

**openvox-ca** is a drop-in replacement for the certificate authority built into
[OpenVox Server](https://voxpupuli.org/openvox/) (and its upstream, Puppet
Server), written in Go. It speaks the same HTTP API that OpenVox and Puppet
agents — and the `puppetserver ca` / `puppet ssl` tooling — already use, and
reads and writes a certificate store compatible with the existing Puppet CA
directory layout. Existing agents keep working without reconfiguration.

Run it instead of OpenVox Server's built-in (Clojure) CA when you want a small,
self-contained CA process that scales out across replicas, keeps its key in
OpenBao, exports to Kubernetes, or exposes Prometheus metrics — while remaining
wire-compatible with your existing Puppet/OpenVox fleet.

> **Migrating from OpenVox Server or Puppet Server?** See the
> [migration guide](docs/migrating-from-puppet-server.md) for step-by-step
> instructions, directory layout mapping, and CLI command translation, and
> [authorisation behaviour worth knowing](#authorisation-behaviour-worth-knowing)
> for the two rules that differ from a relaxed `auth.conf`.

## Features

- **Full Puppet CA API compatibility:** all 13 endpoints used by agents and OpenVox Server. See the [HTTP API reference](docs/api.md)
- **Pluggable storage:** filesystem (default; drop-in compatible with the OpenVox/Puppet Server CA layout), SQLite (single database file), or PostgreSQL / MySQL (MariaDB) / etcd / Redis (Valkey) for HA clusters; CA cert/key can be pinned to local files independently. See the [storage backends guide](docs/storage-backends.md)
- **Pluggable CA key custody:** keep the CA private key as a local file (default) or delegate it entirely to an OpenBao Transit secrets engine key, which never leaves OpenBao — works identically on a VM (AppRole/token) or in Kubernetes (native ServiceAccount auth, no sidecar). See [OpenBao Transit-engine CA key](docs/openbao-transit.md)
- **Autosigning:** `true`, glob-pattern file, or executable plugin modes
- **mTLS support:** optional HTTPS with per-endpoint tier-based client certificate authorization
- **CA import:** replace a bootstrapped CA with an external cert/key pair offline
- **Intermediate CA:** run under an external root, with `openvox-ca csr` emitting a signing request for a parent CA and `openvox-ca import-ca-cert` installing the signed chain. No key material is ever supplied on the command line, so it works identically for every `ca_key_provider` including an OpenBao Transit key that never leaves the vault. See the [operator CLI reference](docs/operator-cli.md)
- **Server-side key generation:** issue cert+key pairs without a node-submitted CSR; configurable RSA (2048/3072/4096) or ECDSA (P-256/P-384/P-521)
- **Configurable key algorithms:** CA and leaf certificates can use RSA or ECDSA; ECDSA support for both bootstrapped CAs and generated leaf certs
- **Random serial numbers:** every issued leaf certificate gets a cryptographically random 128-bit serial (CA/Browser Forum guidance)
- **CRL Distribution Points:** optionally embed a CRL URL in every issued certificate (`--crl-url`) so verifiers can automatically fetch the CRL
- **Configurable CRL validity:** control how long each published CRL is valid (`crl_validity_days`)
- **Automatic CRL refresh:** a background job re-signs this CA's own CRL before its validity lapses, so a low-churn CA never serves an expired CRL; safe across replicas (serialised on the shared CRL lock) and tunable or disablable. Operators can also force a refresh on demand via `openvox-ca-ctl reissue-crl`. Imported ancestor CRLs are preserved but cannot be re-signed here, so keeping them current is `crl_chain_file`'s job (below) or, failing that, a re-import before they expire
- **Revocation that propagates:** on the HA backends every replica reloads the stored CRL on a short timer (`crl_sync_interval_sec`, 60s by default), so a certificate revoked on one replica stops being accepted by the others within that window rather than whenever they next happen to re-sign. Renewal re-reads the CRL from storage, so a revoked certificate cannot renew itself into a fresh one on a replica that has yet to catch up. See [Revocation across replicas](docs/configuration.md#revocation-across-replicas)
- **Upstream CRL chain (opt-in):** point `crl_chain_file` at a PEM bundle of *ancestor* CRLs and openvox-ca re-reads it on a timer and republishes it alongside its own, so a sub-CA's ancestors stay current without anyone remembering to re-import before each `nextUpdate`. An ancestor's CRL can never move backwards. On every storage backend except `filesystem`, and under `encrypt_ca_key` or `ca_key_provider: openbao`, this is the only mechanism that does not require stopping the CA. See [configuration](docs/configuration.md#publishing-an-upstream-crl-chain)
- **Expired-certificate cleanup (opt-in):** a background job removes certificates that expired more than a configurable grace period ago from the inventory and the CRL (and deletes their stored signed certificate), keeping both from growing without bound as nodes are decommissioned; safe across replicas (serialised on the shared CRL lock)
- **OCSP responder:** built-in RFC 6960 OCSP responder; AIA extension embedded in issued certs when `--ocsp-url` is set; in-memory cache with nonce bypass
- **Health probes:** `/healthz/live`, `/healthz/ready`, and `/healthz/startup` endpoints for Kubernetes-style liveness/readiness checks
- **Prometheus exporter:** optional `/metrics` listener (`--metrics-listen`) exposing Go runtime/process and HTTP metrics plus CA certificate, CRL, and per–leaf-certificate expiry and issuance-status series; ships with a [Jsonnet alerting mixin](mixin/). See [metrics & monitoring](docs/metrics.md)
- **Kubernetes export (opt-in):** publish the CA certificate and/or CRL into any number of Kubernetes Secrets and ConfigMaps via in-cluster server-side apply, with configurable names, namespaces, data keys, labels, annotations, Secret `type`, and how much of the chain to publish (`cert_scope`/`crl_scope`, which default to this CA's own block alone — set them to `chain` on a target that was publishing a full bundle before); CRL-bearing objects are refreshed whenever the CRL changes. See [Kubernetes export](docs/kubernetes-export.md)
- **Helm chart:** an OCI-published chart, versioned in lockstep with the server, covering dual-stack Services, TLS-passthrough Ingress and Gateway API routes, an opt-in ServiceMonitor and network policies; the server's own settings pass straight through to its config file, so the whole configuration reference is reachable. See [deploying with Helm](docs/helm-chart.md)
- **Graceful shutdown:** `SIGTERM`/`SIGINT` drains in-flight requests with a configurable window (25s default) before exiting; deferred storage and signer cleanup always runs
- **Configuration reload:** `SIGHUP` (or `systemctl reload`) re-reads the TLS keypair and the admin allow list without dropping connections, so renewing the CA's server certificate or decommissioning a compile server needs no restart. See [reloading configuration](docs/configuration.md#reloading-configuration)
- **systemd integration:** `Type=notify` readiness (`systemctl start` returns once the listener is actually accepting), a live status line covering the listener, CA expiry and CRL freshness, watchdog keep-alives, and `systemctl reload` for TLS certificate renewal and admin allow-list changes; ships a hardened [unit file](packaging/systemd/openvox-ca.service). See [running under systemd](docs/systemd.md)
- **FIPS-compatible:** the core CA uses the standard library only (`crypto/x509`, `net/http`); no CGO by default; FIPS build available via `GOEXPERIMENT=boringcrypto` (the optional Kubernetes export adds the `client-go` dependency)
- **`openvox-ca-ctl`:** operator CLI matching `puppetserver ca` subcommands. See the [operator CLI reference](docs/operator-cli.md)

## Installation

### Container images (recommended)

Prebuilt, multi-arch images are published to the GitHub Container Registry for
every release:

```console
$ docker pull ghcr.io/voxpupuli/openvox-ca:latest
```

See [container images](docs/container-images.md) for the available tags and a
`docker run` example, or use the [compose.yml](compose.yml) at the repository
root for a Docker/Podman Compose deployment.

### Release tarballs

Each release publishes four tarballs — `linux_amd64` and `linux_arm64`, each in a standard and a
FIPS (`_fips`) build — plus `checksums.txt`. Every archive contains both binaries (`openvox-ca`,
`openvox-ca-ctl`) and the systemd unit `openvox-ca.service`. Asset names carry the release version,
so set `VERSION` to the release you want (the newest is on the
[releases page](https://github.com/voxpupuli/openvox-ca/releases/latest)) and download by tag:

```console
$ VERSION=0.9.0
$ curl -fLO https://github.com/voxpupuli/openvox-ca/releases/download/v${VERSION}/openvox-ca_${VERSION}_linux_amd64.tar.gz
$ curl -fLO https://github.com/voxpupuli/openvox-ca/releases/download/v${VERSION}/checksums.txt
$ sha256sum --ignore-missing -c checksums.txt
$ tar xzf openvox-ca_${VERSION}_linux_amd64.tar.gz
```

See [running under systemd](docs/systemd.md) for the rest of a VM install.

### Kubernetes (Helm)

A chart is published as an OCI artefact for every release, versioned in lockstep
with the server:

```console
$ helm install openvox-ca \
    oci://ghcr.io/voxpupuli/openvox-ca-charts/openvox-ca \
    --namespace puppet --create-namespace \
    --set tls.existingSecret=openvox-ca-server-tls
```

See [deploying with Helm](docs/helm-chart.md) for the guide and the
[chart README](charts/openvox-ca/README.md) for the values reference.

### Building from source

Requires Go 1.25+ and [Mage](https://magefile.org/):

```bash
git clone https://github.com/voxpupuli/openvox-ca.git
cd openvox-ca
mage build:all      # → bin/openvox-ca and bin/openvox-ca-ctl
```

Full build instructions (including the FIPS build) are in
[`CONTRIBUTING.md`](CONTRIBUTING.md#building).

## Quick start

### Local demo: plain HTTP on loopback, auto-bootstrap CA

```bash
./bin/openvox-ca --cadir /etc/puppetlabs/puppet/ssl/ca --host 127.0.0.1 --hostname puppet.example.com
```

On first run the server bootstraps a new CA under `--cadir` and begins serving
plain HTTP on port 8140. The server refuses plain HTTP on a non-loopback
address unless `--no-tls-required` is set — only do that behind a trusted
TLS-terminating proxy or in test environments. For anything reachable from the
network, serve HTTPS as below.

### HTTPS with mTLS

```bash
./bin/openvox-ca \
  --cadir /etc/puppetlabs/puppet/ssl/ca \
  --tls-cert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
  --tls-key  /etc/puppetlabs/puppet/ssl/ca/private/ca_key.pem \
  --puppet-server puppet.example.com
```

When `--tls-cert` and `--tls-key` are both set, the server:

1. Presents those certs to connecting clients
2. Requests (but does not require) a client certificate from every connection,
   and does not verify it at the TLS layer
3. Enforces endpoint-level authorization, which is where a presented
   certificate is verified against this CA and checked against the CRL (see
   [Authorization tiers](docs/api.md#authorization-tiers))

The complete flag, environment-variable, and config-file reference is in
[configuring the server](docs/configuration.md).

## Documentation

| Guide | What it covers |
| --- | --- |
| [Configuring the server](docs/configuration.md) | Every flag, environment variable, config-file key; autosigning; directory layout; graceful shutdown; reloading configuration |
| [HTTP API reference](docs/api.md) | All endpoints, authorization tiers, and admin credential resolution |
| [Operator CLI (`openvox-ca-ctl`)](docs/operator-cli.md) | The `openvox-ca-ctl` command reference, and the offline `openvox-ca` subcommands (`csr`, `import-ca-cert`) that run against the server's own configuration |
| [Storage backends](docs/storage-backends.md) | filesystem, SQLite, PostgreSQL, MySQL, etcd, Redis/Valkey; migrating between them |
| [CA key security](docs/ca-key-security.md) | Process isolation and the signer handshake, key encryption at rest, key-custody options, PKCS#11 plans, destructive-op monitoring |
| [OpenBao Transit-engine CA key](docs/openbao-transit.md) | Delegating CA key custody to OpenBao |
| [Deploying with Helm](docs/helm-chart.md) | The `openvox-ca` chart: installation, TLS passthrough, ingress and Gateway API, monitoring |
| [Kubernetes export](docs/kubernetes-export.md) | Publishing the CA cert/CRL into Secrets and ConfigMaps |
| [Metrics & monitoring](docs/metrics.md) | The Prometheus exporter and the alerting [mixin](mixin/) |
| [Running under systemd](docs/systemd.md) | The `Type=notify` unit, status text, `systemctl reload`, watchdog, and hardening |
| [Container images](docs/container-images.md) | Pulling and running the published images |
| [Migration guide](docs/migrating-from-puppet-server.md) | Replacing an OpenVox/Puppet Server built-in CA |

## Authorisation behaviour worth knowing

Two rules catch operators out, neither of which changes a stock deployment.

`GET /certificate_status/{subject}` is admin-only. That matches OpenVox/Puppet
Server's shipped `auth.conf`, so only a configuration that had been relaxed to
let ordinary agent certificates read statuses loses that access. It can be
granted back two ways, both of which confer the whole admin tier — signing and
revocation included — plus an escape hatch that makes the route public rather
than authenticated. Denials are logged, with the string to grep for, in
[authorisation parity](docs/migrating-from-puppet-server.md#authorisation-parity).

`POST /certificate_renewal` accepts only certificates this CA issued and has not
revoked. In the default single-issuer topology nothing reaches that check that
the authorisation middleware had not already refused with `403 access denied`
(TLS requests but does not verify a client certificate — see [HTTPS with
mTLS](#https-with-mtls)). The gate becomes load-bearing once a second issuer can
be trusted for client authentication. There is no opt-out: an agent holding a
certificate from a replaced CA must re-enrol. See [renewal
eligibility](docs/migrating-from-puppet-server.md#renewal-eligibility).

## Contributing

Contributions are welcome. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to
build, test, and submit changes, [`AGENTS.md`](AGENTS.md) for the repository
conventions, and the [development documentation](docs/development/) for internal
design notes and the test suites.

## License

See [LICENSE](LICENSE).
