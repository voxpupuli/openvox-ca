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
That image is the *fixture* image, separate from the two published ones: it carries the packages the suites
invoke rather than the ones `openvox-ca` needs to run. Its command contract is described under
[Fixture image command contract](#fixture-image-command-contract).

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
| 18 | `pp_cli_auth` mTLS: the admin credential is minted offline with `openvox-ca generate --pp-cli-auth` before any server starts; Phase 1 bootstraps the remaining certs (loopback HTTP); Phase 2 asserts the pp_cli_auth cert reaches admin endpoints while a plain cert is denied |
| 19 | `openvox-ca-ctl` error paths: revoke/clean/sign/generate against non-existent or duplicate subjects; arg validation; `--dns` SAN delivery; full mTLS via `--ca-cert`/`--client-cert`/`--client-key`; unreachable server |
| 20 | Migration from an OpenVox/Puppet Server CA: import CA cert/key/CRL via `openvox-ca-ctl import`, copy pre-existing signed certs, verify fetch/sign/revoke/list all work on the migrated CA |
| 21 | `POST /certificate_renewal` over mTLS: agent renews its own certificate; CN-mismatch renewal rejected |

`test:bench` uses `test/compose-bench.yml` (autosign=true, k6 load runner).

`test:puppet` uses `test/compose-puppet.yml`, a five-service stack that validates end-to-end catalog compilation, PuppetDB reporting, exported resources, and CRL revocation using a real OpenVox 8 agent and WEBrick puppet master. The CA runs with genuine TLS (a cert with CN=openvox-ca signed by the CA itself); all inter-service traffic verifies it.

`test:migration` uses `test/compose-migration.yml`, which starts a real OpenVox Server (`voxpupuli/puppetserver:latest`) to create a genuine Puppet CA, then imports its CA material into openvox-ca using `openvox-ca-ctl import` and verifies the full migration path: old certs are fetchable, new certs can be signed, migrated certs can be revoked and cleaned.

Every assertion in that suite reports why it failed, and every HTTP request
goes through `test/migration/http-helpers.sh` so that curl's exit status, the
HTTP status code, the byte count and curl's own error text survive into the TAP
diagnostic. That is not decoration: the suite runs unattended against
containers that are destroyed the moment it finishes, so an assertion that
prints only `not ok` has destroyed the evidence for its own failure. `mage
test:migrationHelpers` is the regression suite for those helpers and for the
retry bound below; it needs bash, curl and python3, runs on the host in
seconds, and CI runs it immediately before `test:migration`.

Pre-flight fetches against the old Puppet Server retry, up to
`HTTP_RETRY_ATTEMPTS` times, `HTTP_RETRY_DELAY` seconds apart, because that
server is fixture rather than the behaviour under test — and because a
response from it that arrived unusable once failed a run that a re-run of the
same commit passed. Truncation is the likeliest explanation, not a confirmed
one: the assertion discarded the evidence that would have settled it, which is
what the rest of this change is about. Assertions from Phase 5 onwards are about openvox-ca's own conduct and
deliberately do not retry: retrying there would convert exactly the
intermittent fault worth reporting into a green run. Phase 4 is the one
deliberate exception on that side of the line, and it is not an assertion
about conduct: it polls `/healthz/ready` until the server has started, which
is waiting for a precondition rather than re-rolling a verdict. The CSR submission in
Phase 2 does not retry either, for a different reason — a CSR `PUT` is not
idempotent, so a second attempt would be rejected rather than retried.

The k6 script (`test/load.js`) runs two concurrent scenarios:

- **reads** — hammers GET /certificate/ca, CRL, and expirations; ramps to 200 VUs
- **workflow** — POST /generate → GET status → GET cert → DELETE; ramps to 50 VUs (CPU-bound on RSA key generation)

Thresholds that fail the run: error rate ≥ 1%, read p95 ≥ 500 ms, workflow p95 ≥ 5 s.

## Storage-backend integration suites

The pluggable storage backends each have their own integration suite, gated
behind a Go build tag and driven by a `mage` target:

| Command | What it does |
| --- | --- |
| `mage test:backendsPostgres` | SQL backend integration suite against PostgreSQL — under `-race`; needs cgo and a C compiler |
| `mage test:backendsMySQL` | SQL backend integration suite against MySQL — under `-race`; needs cgo and a C compiler |
| `mage test:backendsEtcd` | etcd backend integration suite (embedded etcd) — under `-race`; needs cgo and a C compiler |
| `mage test:backendsRedis` | Redis backend full-stack bash TAP suite (Puppet topology) |
| `mage test:backendsRedisGo` | Redis backend Go integration suite (build tag `redis_integration`), under `-race` — needs cgo and a C compiler |
| `mage test:backendsOpenBao` | OpenBao Transit signer integration suite (build tag `openbao_integration`) |

See [storage backends](../storage-backends.md) and
[`AGENTS.md`](../../AGENTS.md) for the build tags and per-backend detail.

### Which suites run under `-race`

Every `go test` a `mage` target invokes, and whether it is raced. The table is
exhaustive on purpose: a prose list has to restate its own scope each time it is
edited, and twice now a claim about a *subset* has been generalised to the whole
set. If you add a target that runs `go test`, add a row.

The pre-push hook (`.lefthook.yml`) is the one caller outside this table: it runs
`go test -race ./...` and `go test -tags mage .` directly rather than through a
target. Both match their rows here — raced and unraced respectively.

| Target | `go test` | `-race` | Why not |
| --- | --- | --- | --- |
| `mage test:unit` | yes | **yes** | — |
| `mage test:backendsEtcd` | yes | **yes** | — |
| `mage test:backendsPostgres` | yes | **yes** | — |
| `mage test:backendsMySQL` | yes | **yes** | — |
| `mage test:backendsRedisGo` | yes | **yes** | — |
| `mage test:backendsOpenBao` | yes | no | exercises `internal/signer/openbao`, not storage locking |
| `mage test:magefile` | yes | no | exercises the magefile's own build logic; no concurrency to watch |
| `mage test:backendsRedis` | **no** | n/a | bash TAP suite; there is no `go test` to add the flag to |

The raced ones are raced for the reason `test:unit` is: what they assert about
concurrency is a coarse outcome — a row count after two backends contend on
`AppendLine`, an advisory lock excluding a second holder — and a coarse outcome
cannot observe an unsynchronised write sitting behind it. MySQL has the most to
gain, because its InnoDB deadlock retry means an append spec can pass by
*retrying over* a race rather than by excluding it.

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

## Fixture image command contract

`test/Dockerfile.run` builds the image the integration suites run *inside*. It is
not either published image, and its package list exists for the suites rather
than for `openvox-ca` — which needs none of it, being statically linked.

The contract is split across two files on purpose, and they have to move
together:

- **`test/Dockerfile.run`** declares the **packages**, each annotated with the
  commands it provides.
- **`test/fixture-commands.sh`** declares the **commands** those packages must
  deliver, and asserts them. `require_fixture_commands` runs before either
  in-container suite does any work; `command_not_found_handle` catches a command
  nobody wrote down, on a path nobody enumerated; `fixture_missing_assert` turns
  what it caught into one TAP assertion at the end of the run.

**Adding a command to an in-container script means adding it to both files.**
Declaring a package without adding its commands leaves the check blind; adding a
command without its package fails the preflight. Six scripts run in the image —
`test/integration-compose.sh`, `test/migration/migration-test.sh`, the
`test/migration/http-helpers.sh` it sources, the two
`docker/puppet/ca-entrypoint*.sh`, and `test/fixture-commands.sh` itself — and two
more, `test/puppet/puppet-stack.sh` and `test/backends/redis-stack.sh`, reach into
it from the host with `compose exec`.

A `Bail out!` naming an absent command means one of two things: the package was
never declared, or the base image dropped it. The second is not hypothetical —
on 2026-09-10 the rolling `stream10` tag dropped `diffutils`, and because
nothing had ever declared the suite's one `diff` call, both Compose legs failed
while *asserting a certificate-content mismatch on byte-identical files*. The
base cannot be pinned against a repeat: quay does not retain superseded CentOS
Stream digests, which `renovate.json` records as its reason for declining.

`mage test:fixtureCommands` exercises the guard logic on the host. CI never takes
its failing branches, so the mutations below check the parts that only a real
image can show. Apply each to a copy, never to the tracked file, and read the
message rather than just the non-zero exit.

```bash
# 1. A declared package the base no longer provides. Drop diffutils from the
#    install line, rebuild, and run a compose leg.
#    -- expect "Bail out! ... # absent from PATH: diff", before test 1 runs.
sed 's/ diffutils findutils/ findutils/' test/Dockerfile.run > /tmp/mut && \
    docker build -f /tmp/mut -t openvox-ca-integ:latest . && \
    docker compose -f test/compose.yml up --exit-code-from test-runner

# 2. The contract's size check. Delete any entry from FIXTURE_COMMANDS without
#    adjusting FIXTURE_COMMANDS_EXPECTED.
#    -- expect "Bail out! fixture command contract lists 27 commands, expected 28".
sed '/^    diff$/d' test/fixture-commands.sh > /tmp/mut && \
    bash -c 'set -uo pipefail; . /tmp/mut; require_fixture_commands'

# 3. The recorder. Point FIXTURE_MISSING_LOG somewhere unwritable; without this
#    check a dead recorder reports "nothing was missing".
#    -- expect "Bail out! cannot write the supplied FIXTURE_MISSING_LOG at /proc/x".
bash -c 'set -uo pipefail; FIXTURE_MISSING_LOG=/proc/x; . test/fixture-commands.sh; \
    require_fixture_commands'
```

## Diagnosing a failed compose suite

When `test:puppet`, `test:puppetFIPS` or `test:backendsRedis` fails, the
harness replays each stack service's container log to stderr
before tearing the stack down: the CA (both replicas for the Redis
topology), the puppet master, OpenVoxDB, PostgreSQL, and Redis for the
backend suite. `puppet-client` is the one exception, and there is nothing to
miss: the agent runs through `compose exec`, so its output is captured by the
harness and that container's own log stays empty. A
failing CI job is therefore self-sufficient — the TAP `not ok` line is
followed by the containers' own account of what went wrong, which teardown
would otherwise destroy.

Each service is replayed in two views, and which one you want depends on how
it failed. First its **first start attempt**, headed with what you are
looking at:

```
# ---- first 4 of 244 log lines from openvox-ca (start attempt 1 of 81) ----
```

Then a tail of the newest lines beneath it. A service under
`restart: on-failure` — the two CA replicas in
`test/compose-backends-redis.yml` are the only ones under `test/` carrying it
— has a log that is several concatenated start attempts, and it is the first
that holds the reason it never came up; everything behind it is the futile
retries. A tail cannot reach that first attempt, and a deeper tail moves it
further away rather than closer, so the depth is not the knob to reach for
(#281). The tail is kept because it remains the right view for the other
shape of failure, a service that failed once, late, without restarting, and
it is suppressed when the log is short enough that it would only reprint the
head.

The attempt boundary comes from the log's own content, because compose
concatenates restarts with no separator of its own: a restart re-runs the
entrypoint from the top and replays the log's opening line, which makes that
line both the banner and the attempt counter. When it never recurs the count
is one — the right answer for every service without a `restart:` policy.

Read the attempt count before you read the attempt. Under `restart:
on-failure` a first attempt that aborted is not by itself the failure: a CA
replica that loses the bootstrap race is *expected* to abort and recover on
its next attempt, which is why that policy is there. What the first attempt
gives you is the reason the process gave, which a tail had destroyed; it does
not tell you the run failed because of it.

To keep the stack for interactive inspection instead, run the script
directly with `--up --keep` and use `compose logs`. The teardown dump is
deliberately skipped in that mode: nothing is being destroyed, so the logs
are still there to be read. A readiness timeout still prints the timed-out
service's log either way, since that is the one thing worth reading
immediately.

Both harnesses dump through one shared helper, `test/failure-log.sh`, which
takes the compose command as an argument rather than reading either one's
`_COMPOSE` array. `mage test:failureLogHelpers` is its regression suite: it
needs bash and no container runtime, runs on the host in under a second, and
CI runs it in the unit job rather than inside any one compose suite. It runs
*alongside* those suites, not ahead of them: it does not gate them, because a
broken dump cannot change whether a compose suite passes — only what that
suite prints when it fails.

`test:migration` dumps on failure too, but what it dumps is not a container
log. Its old Puppet Server is a compose service whose output already reaches
CI by stream interleaving; the openvox-ca *under test* is a background process
inside the test-runner container, so nothing streams it. Its stdout and stderr
go to a file, and the suite replays the tail to stderr from its `EXIT` trap
whenever the run exits non-zero or any assertion failed — including the early
exit taken when the server never becomes ready, which is the case that most
needs it.

A tail is the whole story there, and deliberately so: that process is started
exactly once, `test/compose-migration.yml` declares no `restart:` policy, and
so there is one attempt for a tail to reach. The distinction that matters when
reading any of these dumps is whether the service restart-loops, not whether
the code that dumps it happens to call `tail`.
