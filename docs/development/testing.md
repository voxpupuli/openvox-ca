# Testing

This describes the test suites and the container/compose topologies they run in.
For build/lint conventions and the full `mage` target list, see
[`AGENTS.md`](../../AGENTS.md); for a contributor overview, see
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Common targets

```bash
# Run all unit tests (with coverage, under -race; needs cgo and a C compiler)
mage test:unit

# Run the magefile's own suite (build-tagged; not covered by `go test ./...`)
mage test:magefile

# Format, vet, tidy modules, lint, and check the workflows for drift (the CI gate)
mage dev:check

# Run integration tests using the compose stack
mage test:integCompose

# Run the full OpenVox stack (CA TLS + WEBrick master + OpenVoxDB + agent)
mage test:puppet

# The same stack against a FIPS build (GOEXPERIMENT=boringcrypto)
mage test:puppetFIPS

# Run k6 load tests (correctness + throughput + saturation) via compose
mage test:bench
```

`test:unit` runs under `-race`. Several specs exist only to prove concurrency
guarantees — the storage lock serialising CA bootstrap and key creation, the CRL
cache, the API's in-flight bookkeeping, the systemd notification path — and
without the race detector they can
pass over a genuine data race. The race detector needs cgo, so the target sets
`CGO_ENABLED=1` and a C compiler has to be installed — see
[Prerequisites](../../CONTRIBUTING.md#prerequisites). It costs roughly 40% more
wall clock than the same run without it.

## Container / Compose topologies

A test runtime image (`test/Dockerfile.run`) and `test/compose.yml` are provided for development and integration testing.

```bash
# Build images and run the full integration test suite
mage test:integCompose

# integCompose + concurrency/correctness tests (DO_LOAD=true)
mage test:loadCompose

# k6 load test suite: correctness, throughput benchmarks, saturation ramp
mage test:bench

# Full OpenVox stack: CA (TLS) + WEBrick master + OpenVoxDB + agent
mage test:puppet
```

`test:integCompose` and `test:loadCompose` use `test/compose.yml`, the canonical integration test suite. It runs two containers on an isolated network (openvox-ca + test-runner) and exercises the full API in TAP format across 21 test groups:

| Group | Coverage |
| --- | --- |
| 1 | Endpoint smoke tests (health probes, CA cert, CRL, 404s, expirations) |
| 2 | Full CSR lifecycle: submit → sign → verify → revoke → re-register; issue #8 assertions (no Netscape Comment OID, random serial ≥16 hex digits, CRL Distribution Point present, `authorization_extensions` field, CSR deleted after signing) |
| 3 | `openvox-ca-ctl sign --all` (bulk signing) |
| 4 | `POST /generate` (server-side key+cert generation) |
| 5 | `GET /certificate_statuses?state=` filter; `openvox-ca-ctl list / list --all` |
| 6 | `cert_ttl` custom validity via `PUT /certificate_status` |
| 7 | `subject_alt_names` field in status responses |
| 8 | CSR CN mismatch rejection (400) |
| 9 | Error cases: invalid subjects, bad JSON, conflict (409), `BasicConstraints CA:TRUE` rejection |
| 10 | `PUT /clean` bulk revoke+delete: success, not-found, and error buckets |
| 11 | Protocol features: bare paths, `/puppet-ca/v1/` prefixed paths |
| 12 | `openvox-ca-ctl` offline subcommands: `setup` (bootstrap new CA) and `import` (external CA cert/key/CRL) |
| 13 | `POST /sign` and `POST /sign/all` bulk HTTP signing API |
| 14 | Concurrency / load tests (opt-in via `DO_LOAD=true` / `mage test:loadCompose`) |
| 15 | OCSP: good/revoked status, nonce handling, cache invalidation on revoke, malformed request (400) |
| 16 | Autosign modes: `true`, glob-pattern file, executable plugin |
| 17 | Config drivers: env vars, config file |
| 18 | `pp_cli_auth` mTLS: Phase 1 bootstraps certs (loopback HTTP); Phase 2 asserts pp_cli_auth cert reaches admin endpoints while plain cert is denied |
| 19 | `openvox-ca-ctl` error paths: revoke/clean/sign/generate against non-existent or duplicate subjects; arg validation; `--dns` SAN delivery; full mTLS via `--ca-cert`/`--client-cert`/`--client-key`; unreachable server |
| 20 | Migration from an OpenVox/Puppet Server CA: import CA cert/key/CRL via `openvox-ca-ctl import`, copy pre-existing signed certs, verify fetch/sign/revoke/list all work on the migrated CA |
| 21 | `POST /certificate_renewal` over mTLS: agent renews its own certificate; CN-mismatch renewal rejected |

`test:bench` uses `test/compose-bench.yml` (autosign=true, k6 load runner).

`test:puppet` uses `test/compose-puppet.yml`, a five-service stack that validates end-to-end catalog compilation, PuppetDB reporting, exported resources, and CRL revocation using a real OpenVox 8 agent and WEBrick puppet master. The CA runs with genuine TLS (a cert with CN=openvox-ca signed by the CA itself); all inter-service traffic verifies it.

`test:migration` uses `test/compose-migration.yml`, which starts a real OpenVox Server (`voxpupuli/puppetserver:latest`) to create a genuine Puppet CA, then imports its CA material into openvox-ca using `openvox-ca-ctl import` and verifies the full migration path: old certs are fetchable, new certs can be signed, migrated certs can be revoked and cleaned.

The k6 script (`test/load.js`) runs two concurrent scenarios:

- **reads** — hammers GET /certificate/ca, CRL, and expirations; ramps to 200 VUs
- **workflow** — POST /generate → GET status → GET cert → DELETE; ramps to 50 VUs (CPU-bound on RSA key generation)

Thresholds that fail the run: error rate ≥ 1%, read p95 ≥ 500 ms, workflow p95 ≥ 5 s.

## Storage-backend integration suites

The pluggable storage backends each have their own integration suite, gated
behind a Go build tag and driven by a `mage` target:

| Command | What it does |
| --- | --- |
| `mage test:backendsPostgres` | SQL backend integration suite against PostgreSQL |
| `mage test:backendsMySQL` | SQL backend integration suite against MySQL |
| `mage test:backendsEtcd` | etcd backend integration suite (embedded etcd) |
| `mage test:backendsRedis` | Redis backend full-stack bash TAP suite (Puppet topology) |
| `mage test:backendsRedisGo` | Redis backend Go integration suite (build tag `redis_integration`) |
| `mage test:backendsOpenBao` | OpenBao Transit signer integration suite (build tag `openbao_integration`) |

See [storage backends](../storage-backends.md) and
[`AGENTS.md`](../../AGENTS.md) for the build tags and per-backend detail.

## Container identity guards

Every image asserts at build time who it runs as, and the two published images
additionally assert that the directories the CA writes are owned by that
account. Both guards exist because `USER` is numeric and cannot reference the
account it is supposed to name — the uid in `useradd` and the uid in `USER` are
separate literals, and nothing else stops them drifting apart.

CI only ever exercises the passing branch of these guards, so **whenever you
edit one, re-verify by hand that it still fails.** A guard that has stopped
failing is indistinguishable from one that passes. Each Dockerfile carrying a
guard points back at this section.

Every mutation below should abort the build naming the drift. Apply each to a
copy, never to the tracked file, and check the message rather than just the
non-zero exit — a mutation that breaks the build for the wrong reason looks
identical to one that worked.

```bash
# 1. Pinned uid. Works on Dockerfile, Dockerfile.alpine and test/Dockerfile.run
#    (context `.`) -- expect "puppet is 1001:1000, not 1000:1000".
sed 's/-u 1000/-u 1001/' Dockerfile > /tmp/mut && docker build -f /tmp/mut .

# 2. The same, for docker/puppet/Dockerfile.client. Note the build context, and
#    that this image's account is puppet-agent, so the message differs:
#    -- expect "puppet-agent is 1001:1000, not 1000:1000".
sed 's/-u 1000/-u 1001/' docker/puppet/Dockerfile.client > /tmp/mut && \
    docker build -f /tmp/mut docker/puppet

# 3. Ownership of the directories the CA writes (Dockerfile, Dockerfile.alpine).
#    Drop either argument of the chown; the loop asserts both, so either is
#    caught. The first is the image's default --cadir, the second is what
#    compose.yml and the docs mount.
#    -- expect "/etc/puppetlabs/puppet/ssl/ca is owned by 0:0, not 1000:1000"
sed 's|chown -R puppet:puppet /etc/puppetlabs/puppet /data|chown -R puppet:puppet /data|' \
    Dockerfile > /tmp/mut && docker build -f /tmp/mut .
#    -- expect "/data is owned by 0:0, not 1000:1000"
sed 's|chown -R puppet:puppet /etc/puppetlabs/puppet /data|chown -R puppet:puppet /etc/puppetlabs/puppet|' \
    Dockerfile > /tmp/mut && docker build -f /tmp/mut .

# 4. Package-assigned identity (docker/puppet/Dockerfile). This one is inherited
#    rather than chosen, so mutate the image, not the expectation: flipping
#    `expected` only proves the comparison runs, not that `id` observes anything.
#    -- expect "is 53:53:53, not 52:52:52", then "is 52:52:52 10, not 52:52:52".
sed 's|^RUN expected=|RUN usermod -u 53 puppet \&\& groupmod -g 53 puppet \&\& expected=|' \
    docker/puppet/Dockerfile > /tmp/mut && docker build -f /tmp/mut docker/puppet
sed 's|^RUN expected=|RUN usermod -aG wheel puppet \&\& expected=|' \
    docker/puppet/Dockerfile > /tmp/mut && docker build -f /tmp/mut docker/puppet
```

These are deliberately not a CI job: each mutation is a full image build, and
the failure they guard against is introduced by editing the assertion itself —
which is exactly when this procedure is required.

## Diagnosing a failed compose suite

When `test:puppet`, `test:puppetFIPS` or `test:backendsRedis` fails, the
harness replays the tail of each stack service's container log to stderr
before tearing the stack down: the CA (both replicas for the Redis
topology), the puppet master, OpenVoxDB, PostgreSQL, and Redis for the
backend suite. `puppet-client` is the one exception, and there is nothing to
miss: the agent runs through `compose exec`, so its output is captured by the
harness and that container's own log stays empty. A
failing CI job is therefore self-sufficient — the TAP `not ok` line is
followed by the containers' own account of what went wrong, which teardown
would otherwise destroy.

To keep the stack for interactive inspection instead, run the script
directly with `--up --keep` and use `compose logs`. The teardown dump is
deliberately skipped in that mode: nothing is being destroyed, so the logs
are still there to be read. A readiness timeout still prints the timed-out
service's log either way, since that is the one thing worth reading
immediately.
