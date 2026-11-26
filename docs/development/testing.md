# Testing

This describes the test suites and the container/compose topologies they run in.
For build/lint conventions and the common `mage` targets, see
[`AGENTS.md`](../../AGENTS.md) (`mage -l` lists every target); for a contributor
overview, see [`CONTRIBUTING.md`](../../CONTRIBUTING.md).

## Common targets

```bash
# Run all unit tests (with coverage, under -race; needs cgo and a C compiler)
mage test:unit

# Run the magefile's own suite (build-tagged; not covered by `go test ./...`)
mage test:magefile

# Format, vet, tidy modules, lint, and check the workflows for drift (the CI gate)
mage dev:check

# Scan for known vulnerabilities the code can reach (needs network; CI runs it too)
mage dev:vulncheck

# Run integration tests using the compose stack
mage test:integCompose

# Run the full OpenVox stack (CA TLS + WEBrick master + OpenVoxDB + agent)
mage test:puppet

# The same stack against a FIPS build (GOEXPERIMENT=boringcrypto)
mage test:puppetFIPS

# Run k6 load tests (correctness + throughput + saturation) via compose
mage test:bench
```

`dev:vulncheck` reads the advisory database live, so its CI job can go red on a
tree nobody changed. It exits 3 when a scan finds a vulnerability the code can
reach: a newly published advisory, listed under `=== Symbol Results ===` in the
job log. Any other failure, such as vuln.go.dev being unreachable, exits 1, and
rerunning the job is the first step. For an advisory, the fix is to bump the
affected module, or the Go toolchain for a standard-library advisory (Renovate's
"Go toolchain" group). When no fixed release exists yet, the maintainers decide
between making the vulnerable symbol unreachable and overriding the required
check, since govulncheck has no per-advisory allowlist.

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
That image is the *fixture* image, separate from the published ones: it carries the packages the suites
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
| 2 | Full CSR lifecycle: submit → sign → verify → revoke → re-register refused (400) → clean → re-register; issue #8 assertions (no Netscape Comment OID, random serial ≥16 hex digits, CRL Distribution Point present, `authorization_extensions` field, CSR deleted after signing) |
| 3 | `openvox-ca-ctl sign --all` (bulk signing) |
| 4 | `POST /generate` (server-side key+cert generation) |
| 5 | `GET /certificate_statuses?state=` filter; `openvox-ca-ctl list / list --all` |
| 6 | `cert_ttl` custom validity via `PUT /certificate_status` |
| 7 | `subject_alt_names` field in status responses |
| 8 | CSR CN mismatch rejection (400) |
| 9 | Error cases: invalid subjects, bad JSON, duplicate CSR for a signed certificate (400 with OpenVox Server's body), `BasicConstraints CA:TRUE` rejection (409) |
| 10 | `PUT /clean` bulk revoke+delete: success, not-found, and error buckets |
| 11 | Protocol features: bare paths, `/puppet-ca/v1/` prefixed paths |
| 12 | `openvox-ca-ctl` offline subcommands: `setup` (bootstrap new CA) and `import` (external CA cert/key/CRL) |
| 13 | `POST /sign` and `POST /sign/all` bulk HTTP signing API |
| 14 | Concurrency / load tests (opt-in via `DO_LOAD=true` / `mage test:loadCompose`) |
| 15 | OCSP: good/revoked status, nonce handling, cache invalidation on revoke, malformed request (400) |
| 16 | Autosign modes: `true`, glob-pattern file, executable plugin |
| 17 | Config drivers: env vars, config file |
| 18 | `pp_cli_auth` mTLS: the admin credential is minted offline with `openvox-ca generate --pp-cli-auth` before any server starts; Phase 1 bootstraps the remaining certs (loopback HTTP); Phase 2 asserts the pp_cli_auth cert reaches admin endpoints while a plain cert is denied |
| 19 | `openvox-ca-ctl` error paths: revoke/clean/sign/generate against non-existent or duplicate subjects; arg validation; `--dns` SAN delivery in both the comma-separated and repeated forms; full mTLS via `--ca-cert`/`--client-cert`/`--client-key`; unreachable server |
| 20 | Migration from an OpenVox/Puppet Server CA: import CA cert/key/CRL via `openvox-ca-ctl import`, copy pre-existing signed certs, verify fetch/sign/revoke/list all work on the migrated CA |
| 21 | `POST /certificate_renewal` over mTLS: agent renews its own certificate; CN-mismatch renewal rejected |

`test:bench` uses `test/compose-bench.yml` (autosign=true, k6 load runner).

`test:puppet` uses `test/compose-puppet.yml`, a five-service stack that validates end-to-end catalog compilation, PuppetDB reporting, exported resources, CRL revocation, and an agent waiting through a duplicate-request refusal (`400`) until its subject is free, using a real OpenVox 8 agent and WEBrick puppet master. The CA runs with genuine TLS (a cert with CN=openvox-ca signed by the CA itself); all inter-service traffic verifies it.

`test:migration` uses `test/compose-migration.yml`, which starts a real OpenVox Server (the pinned `ghcr.io/openvoxproject/openvoxserver` image the compose file names) to create a genuine Puppet CA, then imports its CA material into openvox-ca using `openvox-ca-ctl import` and verifies the full migration path: old certs are fetchable, new certs can be signed, migrated certs can be revoked and cleaned.

It then runs a second suite, `test/roundtrip/roundtrip.sh` on `test/compose-roundtrip.yml`, even when the first fails, and reports both. That one hands a single cadir between OpenVox Server's CA and openvox-ca four times, from the host: OpenVox Server creates the CA, openvox-ca starts on it with no import, OpenVox Server starts on what openvox-ca left, and openvox-ca returns after `rebuild-inventory-hmac --yes-re-bless`, which it must refuse to start without. Each phase issues certificates and revokes and cleans by name ones the other issued, and checks that `inventory.txt` only grew, in OpenVox Server's format. openvox-ca runs as OpenVox Server's uid, as [sharing the cadir](../storage-backends.md#sharing-the-cadir-with-openvox-server) requires. Each phase's inventory snapshot is kept under `.test-output/roundtrip/`.

Every assertion in the import-path suite (`test/migration/migration-test.sh`)
reports why it failed, and every HTTP request
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

Every image asserts at build time who it runs as, and the published images
additionally assert that the directories the CA writes are owned by that
account. Both guards exist because `USER` is numeric and cannot reference the
account it is supposed to name — the uid in `useradd` and the uid in `USER` are
separate literals, and nothing else stops them drifting apart.

`Dockerfile.distroless` is built differently, because its runtime stage has no
shell to run an assertion in. Its uid is one build argument, `CA_UID`, which
both `USER` and the `chown` take, so those two cannot drift. The ownership
assertion runs in the builder stage instead, against the tree the runtime stage
copies. That leaves a gap: `COPY` can change an owner on the way in. A
per-directory `COPY` gives the directory it creates root ownership, even though
the builder assertion has passed. So container-images.yml's *Check the image's
user and writable directories* step reads every published image after it is
built, whichever Dockerfile it comes from. `USER` must be a numeric, non-root
`uid:gid`, and the default `--cadir` and `/data` must be owned by exactly that.
The default `--cadir` is read out of the image's `CMD`, not repeated in the
step, so moving it there without moving the directory fails too. The version
label must end with the variant's tag suffix, and on the variant without one
must not end with another variant's, so the label says which variant an image
is. The step then runs `openvox-ca --version`, because a cgo build
fails only when a base without libc tries to start it, and has
`openvox-ca-ctl setup` initialise a CA in each of those directories as the
image's user, because an owner in a listing is not a write. Last, it runs the
image with no arguments, so the default `CMD` and the configuration baked in at
`/etc/openvox-ca/config.yaml` must start a CA that answers `/healthz/ready`, and
the listener's certificate must verify as `puppet` against that CA's: a baked
configuration the server cannot read, or one that serves the CA's own
certificate, fails there.

CI only ever exercises the passing branch of these guards, so **whenever you
edit one, re-verify by hand that it still fails.** A guard that has stopped
failing is indistinguishable from one that passes. Each Dockerfile carrying a
guard points back at this section.

Every mutation below should abort the build naming the drift. Apply each to a
copy, never to the tracked file, and check the message rather than just the
non-zero exit — a mutation that breaks the build for the wrong reason looks
identical to one that worked.

```bash
# 1. Pinned uid (context `.`). On Dockerfile.alpine and test/Dockerfile.run
#    -- expect "puppet is 65533:65532, not 65532:65532".
sed 's/-u 65532/-u 65533/' Dockerfile.alpine > /tmp/mut && docker build -f /tmp/mut .

# 2. The same, for docker/puppet/Dockerfile.client. Note the build context, and
#    that this image's account is puppet-agent, so the message differs:
#    -- expect "puppet-agent is 1001:1000, not 1000:1000".
sed 's/-u 1000/-u 1001/' docker/puppet/Dockerfile.client > /tmp/mut && \
    docker build -f /tmp/mut docker/puppet

# 3. Ownership of the directories the CA writes (Dockerfile.alpine).
#    Drop either argument of the chown; the loop asserts both, so either is
#    caught. The first is the image's default --cadir, whose parent compose.yml
#    and the docs mount; the second is a mount point for --cadir=/data.
#    -- expect "/etc/puppetlabs/puppet/ssl/ca is owned by 0:0, not 65532:65532"
sed 's|chown -R puppet:puppet /etc/puppetlabs/puppet /data|chown -R puppet:puppet /data|' \
    Dockerfile.alpine > /tmp/mut && docker build -f /tmp/mut .
#    -- expect "/data is owned by 0:0, not 65532:65532"
sed 's|chown -R puppet:puppet /etc/puppetlabs/puppet /data|chown -R puppet:puppet /etc/puppetlabs/puppet|' \
    Dockerfile.alpine > /tmp/mut && docker build -f /tmp/mut .

# 4. Package-assigned identity (docker/puppet/Dockerfile). This one is inherited
#    rather than chosen, so mutate the image, not the expectation: flipping
#    `expected` only proves the comparison runs, not that `id` observes anything.
#    -- expect "is 53:53:53, not 52:52:52", then "is 52:52:52 10, not 52:52:52".
sed 's|^RUN expected=|RUN usermod -u 53 puppet \&\& groupmod -g 53 puppet \&\& expected=|' \
    docker/puppet/Dockerfile > /tmp/mut && docker build -f /tmp/mut docker/puppet
sed 's|^RUN expected=|RUN usermod -aG wheel puppet \&\& expected=|' \
    docker/puppet/Dockerfile > /tmp/mut && docker build -f /tmp/mut docker/puppet
```

For `Dockerfile.distroless`, mutations 5 and 6 abort its build. Mutations 7 to
19 build a bad image, and the image check must then reject it. To run that check
by hand, take its `run:` script out of the workflow as the first command below
does. Run it on Linux, because the parsing expects GNU tar's listing format:

```bash
yq -r ".jobs.build.steps[] | select(.name == \"Check the image's user and writable directories\") | .run" \
    .github/workflows/container-images.yml > /tmp/check.sh

# 5, 6. Ownership in the builder stage. Drop either argument of the chown.
#    -- expect "/etc/puppetlabs/puppet/ssl/ca is owned by 0:0, not 65532:65532"
sed 's|chown -R "${CA_UID}:${CA_UID}" /rootfs/etc/puppetlabs/puppet /rootfs/data|chown -R "${CA_UID}:${CA_UID}" /rootfs/data|' \
    Dockerfile.distroless > /tmp/mut && docker build -f /tmp/mut .
#    -- expect "/data is owned by 0:0, not 65532:65532"
sed 's|chown -R "${CA_UID}:${CA_UID}" /rootfs/etc/puppetlabs/puppet /rootfs/data|chown -R "${CA_UID}:${CA_UID}" /rootfs/etc/puppetlabs/puppet|' \
    Dockerfile.distroless > /tmp/mut && docker build -f /tmp/mut .

# 7-19. The image check. Build the mutant with the label CI gives it, then run
#    the check against it. Distroless is the unsuffixed variant, so its label
#    is the plain tag and its SUFFIX is empty:
#    docker build --label org.opencontainers.image.version=edge \
#        -f /tmp/mut -t mut . && PUSH=false LOADED=mut SUFFIX= \
#        SUFFIXES=-alpine bash /tmp/check.sh
# 7. Copy per directory, which the builder-stage guard cannot see.
#    -- expect "/data is owned by 0:0, but the image runs as 65532:65532"
sed 's|^COPY --from=builder /rootfs/ /$|COPY --from=builder /rootfs/etc/puppetlabs /etc/puppetlabs\nCOPY --from=builder /rootfs/data /data|' \
    Dockerfile.distroless > /tmp/mut
# 8. Run as root.  -- expect "USER is '0:0'; the image must not run as root"
sed 's|^USER ${CA_UID}:${CA_UID}$|USER 0:0|' Dockerfile.distroless > /tmp/mut
# 9. Run as a name. -- expect "USER is 'nonroot'; it must be a numeric uid:gid"
sed 's|^USER ${CA_UID}:${CA_UID}$|USER nonroot|' Dockerfile.distroless > /tmp/mut
# 10. Copy nothing. -- expect "/etc/puppetlabs/puppet/ssl/ca is not in the image"
sed '/^COPY --from=builder \/rootfs\/ \/$/d' Dockerfile.distroless > /tmp/mut
# 11. Link against libc, which distroless does not have.
#    -- expect "openvox-ca does not run in this image", after docker's
#    "exec /usr/local/bin/openvox-ca: no such file or directory"
sed 's/^ENV CGO_ENABLED=0 GOOS=linux$/ENV CGO_ENABLED=1 GOOS=linux/' Dockerfile.distroless > /tmp/mut
# 12. Own a directory without being able to write it.
#    -- expect "openvox-ca-ctl setup could not initialise a CA in /data as 65532:65532"
sed 's|^    chown -R "${CA_UID}:${CA_UID}" /rootfs/etc/puppetlabs/puppet /rootfs/data \&\& \\$|    chown -R "${CA_UID}:${CA_UID}" /rootfs/etc/puppetlabs/puppet /rootfs/data \&\& chmod 0555 /rootfs/data \&\& \\|' \
    Dockerfile.distroless > /tmp/mut
# 13. Move the default cadir in CMD and nowhere else.
#    -- expect "/srv/ca is not in the image"
sed 's|^CMD \["--cadir=/etc/puppetlabs/puppet/ssl/ca", \\$|CMD ["--cadir=/srv/ca", \\|' \
    Dockerfile.distroless > /tmp/mut
# 14. Drop the default cadir from CMD.
#    -- expect "CMD is ["--verbosity=1"]; it must name the default cadir once, as --cadir=<absolute path>"
sed 's|^CMD \["--cadir=/etc/puppetlabs/puppet/ssl/ca", \\$|CMD [\\|' Dockerfile.distroless > /tmp/mut
# 15. Label a suffixed variant without its suffix: build Dockerfile.alpine with
#    --label org.opencontainers.image.version=edge and run the check with
#    SUFFIX=-alpine.
#    -- expect "the version label is 'edge'; it must end with this variant's tag suffix '-alpine'"
# 16. An entrypoint that does not serve.
#    -- expect "the server did not answer /healthz/ready: it exited, or 60 seconds
#    passed", followed by the server's own "unknown flag: --cadir"
sed 's|^ENTRYPOINT \["/usr/local/bin/openvox-ca"\]$|ENTRYPOINT ["/usr/local/bin/openvox-ca-ctl"]|' \
    Dockerfile.distroless > /tmp/mut
# 17. Label the unsuffixed variant as another: build the unmodified
#    Dockerfile.distroless with --label org.opencontainers.image.version=edge-alpine.
#    -- expect "the version label is 'edge-alpine', another variant's; this variant's tags carry no suffix"
# 18. Bake the default configuration in with COPY --chmod, which leaves
#    /etc/openvox-ca untraversable, so the server never reads it.
#    -- expect "the server did not answer /healthz/ready: it exited, or 60 seconds
#    passed", followed by the server's own "refusing to start: plain HTTP"
sed 's|^COPY --from=builder /container-config/ /etc/openvox-ca/$|COPY --chmod=0644 packaging/container/config.yaml /etc/openvox-ca/config.yaml|' \
    Dockerfile.distroless > /tmp/mut
# 19. A default configuration that serves the CA's own certificate.
#    -- expect "the default configuration's serving certificate does not verify as puppet against the CA"
sed "s|^RUN install -D -m 0644 packaging/container/config.yaml /container-config/config.yaml\$|RUN mkdir /container-config \&\& printf 'tls_cert: %s\\\\ntls_key: %s\\\\n' /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem /etc/puppetlabs/puppet/ssl/ca/ca_key.pem > /container-config/config.yaml|" \
    Dockerfile.distroless > /tmp/mut
```

These are deliberately not a CI job: each mutation is a full image build, and
the failure they guard against is introduced by editing the assertion itself —
which is exactly when this procedure is required.

The workflow's variant list, in its setup job, is guarded the same way: it
must hold unique names, exactly one unsuffixed variant, every other suffix
`-<name>`, and an alias `-<name>` on the unsuffixed variant and on no other.
CI only ever takes the passing branch, so check each refusal by running the
step's script with a mutated list. Every mutation below should print the
step's `::error::` line and exit 1:

```bash
yq -r '.jobs.setup.steps[] | select(.name == "Define the image variants") | .run' \
    .github/workflows/container-images.yml > /tmp/variants.sh
mut() { sed "$1" /tmp/variants.sh > /tmp/mut.sh && GITHUB_OUTPUT=/dev/null bash /tmp/mut.sh; }
mut 's/, "alias": "-distroless"//'                                   # no alias
mut 's/"alias": "-distroless"/"alias": "-dl"/'                       # not "-<name>"
mut 's/"suffix": "-alpine"}/"suffix": "-alpine", "alias": "-alpine"}/' # on a suffixed variant
mut 's/"suffix": "-alpine"/"suffix": ""/'                            # two unsuffixed
```

The merge job's check that every tag got its alias copy is the same: CI never
fails it. Run the tag-list part of its *Create multi-arch manifest* step with
each mutation below. The first writes the alias copies over the file instead
of appending them, and should print `::error::expected 6 tags with the
-distroless alias copies, but the list holds 3`. The second names the copies
wrongly, keeping their count, and should print `::error::r/i:1.0.0 has no alias
copy named r/i:1.0.0-distroless in the list`. Both exit 1:

```bash
yq -r '.jobs.merge.steps[] | select(.name == "Create multi-arch manifest") | .run' \
    .github/workflows/container-images.yml | sed -n '1,/publishing:/p' > /tmp/tags.sh
mut() { sed "$1" /tmp/tags.sh > /tmp/tags-mut.sh &&
    DOCKER_METADATA_OUTPUT_JSON='{"tags":["r/i:1.0.0","r/i:1.0","r/i:latest"]}' \
    ALIAS=-distroless bash /tmp/tags-mut.sh; }
mut '/+ \$alias/s/>> \/tmp\/tags.txt/> \/tmp\/tags.txt/'   # copies overwrite
mut "s/'.tags\[\] + \$alias'/'.tags[] + \"-\" + \$alias'/"    # copies misnamed
```

## Image build context check

CI's *Image build context* job builds the builder stages of `Dockerfile.alpine`
and `Dockerfile.distroless` from the checkout and reads the build settings back
out of both binaries in each with `go version -m`. It fails unless each carries `vcs.revision` equal to the
checked-out commit, `vcs.modified=false` and `-trimpath=true`. The first two
hold only while [`.dockerignore`](../../.dockerignore) excludes nothing git
tracks and keeps `.git`; the third pins the `-trimpath` the Dockerfiles share
with the release tarballs.

Like the guards above, CI only takes its passing branch. To re-verify a failing
one, apply the mutation in a fresh `git clone` of the tree and **commit it
there**. An uncommitted edit is itself a modified tracked file, so it fails on
`vcs.modified` whatever it changed. A worktree will not do either: its `.git`
is a file pointing outside the build context. Then run the job's two steps in
the clone, or build the stage and read the settings by hand:

```bash
docker build --target builder -f Dockerfile.alpine -t openvox-ca-builder-alpine .
docker build --target builder -f Dockerfile.distroless -t openvox-ca-builder-distroless .
docker run --rm openvox-ca-builder-alpine go version -m /openvox-ca | grep -E 'vcs\.|trimpath'

# 1. Exclude a tracked path: append `docs/` to .dockerignore and commit.
#    -- expect "is not stamped vcs.modified=false; .dockerignore excludes a tracked file"
# 2. Exclude the repository: append `.git` to .dockerignore and commit.
#    -- expect "is not stamped with vcs.revision=<sha>; is .git excluded from the build context?"
# 3a. Drop -trimpath from both go build lines in Dockerfile.alpine and commit.
#    -- expect "Dockerfile.alpine: /openvox-ca is not built with -trimpath"
# 3b. The same in Dockerfile.distroless, which proves the loop reaches it.
#    -- expect "Dockerfile.distroless: /openvox-ca is not built with -trimpath"
```

## Fixture image command contract

`test/Dockerfile.run` builds the image the integration suites run *inside*. It is
not one of the published images, and its package list exists for the suites rather
than for `openvox-ca` — which needs none of it, being statically linked.

The contract is split across two files on purpose, and they have to move
together — three declarations in all:

- **`test/Dockerfile.run`** declares the **packages**, each annotated with the
  commands it provides.
- **`test/fixture-commands.sh`** declares the **commands** those packages must
  deliver and **how many** there should be (`FIXTURE_COMMANDS_EXPECTED`), and
  asserts both. `require_fixture_commands` runs before either
  in-container suite does any work; `command_not_found_handle` catches a command
  nobody wrote down, on a path nobody enumerated; `fixture_missing_assert` turns
  what it caught into one TAP assertion at the end of the run.

**Adding a command to an in-container script means three edits: the providing
package in `test/Dockerfile.run`, the entry in `FIXTURE_COMMANDS`, and the
`FIXTURE_COMMANDS_EXPECTED` count beside it.** Declaring a package without adding
its commands leaves the check blind; adding a command without its package fails
the preflight; adding one without bumping the count fails the size check. Six scripts run in the image —
`test/integration-compose.sh`, `test/migration/migration-test.sh`, the
`test/migration/http-helpers.sh` it sources, the two
`docker/puppet/ca-entrypoint*.sh`, and `test/fixture-commands.sh` itself — and three
more, `test/puppet/puppet-stack.sh`, `test/backends/redis-stack.sh` and
`test/roundtrip/roundtrip.sh`, reach into it from the host with `compose exec`.

A `Bail out!` naming an absent command means one of two things: the package was
never declared, or the base image dropped it. The second is not hypothetical —
on 2026-09-10 the rolling `stream10` tag dropped `diffutils`, and because
nothing had ever declared the suite's one `diff` call, both Compose legs failed
while *asserting a certificate-content mismatch on byte-identical files*. The
image is now built on Debian, pinned by digest, but each Renovate bump of that
pin can drop a package the same way.

`mage test:fixtureCommands` exercises the guard logic on the host. CI never takes
its failing branches, so the mutations below check the parts that only a real
image can show. Apply each to a copy, never to the tracked file, and read the
message rather than just the non-zero exit.

```bash
# 1. A declared package the base does not provide. Drop python3 from the
#    install line, rebuild, and run a compose leg. Most of the declared
#    packages are Essential in Debian and come with the base, so dropping one
#    of those changes nothing. Of the three the base lacks, curl is the
#    services' healthcheck and would stall the leg before the preflight runs.
#    -- expect "Bail out! ... # absent from PATH: python3", before test 1 runs.
sed 's/ openssl python3 sed/ openssl sed/' test/Dockerfile.run > /tmp/mut && \
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

## Package install-and-verify legs

CI's *Packages* legs (`.github/workflows/packages.yml`, which "CI success"
needs) build the deb and rpm as the release does and install each into a
container booted with systemd as PID 1: `debian:trixie` for the deb and UBI 10
(`ubi10/ubi-init`) for the rpm, each on an amd64 and an arm64 runner. They judge
the packages from the installed state. The CA must answer TLS verified through
the `certs/ca.pem` the package linked, a CA placed before install must come
through byte-identical, and each format's lifecycle (takeover, upgrade,
remove, purge, the environment file) must behave as
[docs/systemd.md](../systemd.md#installing-from-a-package) describes.
`test/packages/install-verify.sh` holds every assertion and says why each one
is there.

To reproduce a failed leg locally, with Docker able to run `--privileged`
containers (Docker Desktop can) and a `timeout` command on the `PATH` (older
macOS releases lack one; Homebrew's coreutils provides it, and the harness
also finds it as `gtimeout`):

```console
$ mage build:distVariant linux_amd64
$ mage build:distVariant linux_arm64
$ mage build:packages
$ test/packages/build-upgrade.sh dist/upgrade
$ test/packages/install-verify.sh deb dist   # or rpm
```

It installs the package for the Docker engine's own architecture.
`build-upgrade.sh` builds the newer packages the upgrade cases install, from
`HEAD` in a temporary worktree, so commit packaging changes before running it.
The output is TAP. A scenario with a failure prints the journal of both units
before its container is removed, and a container whose systemd never boots
prints its own log.

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
`_COMPOSE` array. `test/roundtrip/roundtrip.sh` uses it too, for its `ovs` and
`ovca` services. That suite stops and starts both on purpose, once per phase,
so there "start attempt" counts phases rather than failed retries: the first
attempt is a healthy phase-1 or phase-2 boot, and the failure is in the tail. `mage test:failureLogHelpers` is its regression suite: it
needs bash and no container runtime, runs on the host in under a second, and
CI runs it in the unit job rather than inside any one compose suite. It runs
*alongside* those suites, not ahead of them: it does not gate them, because a
broken dump cannot change whether a compose suite passes — only what that
suite prints when it fails.

`test:migration`'s import-path suite dumps on failure too, but what it dumps is
not a container log. Its old Puppet Server is a compose service whose output already reaches
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

## The Puppet CA API contract

`internal/api/contract_test.go` checks openvox-ca's `/puppet-ca/v1` responses
against responses recorded from a real OpenVox Server, kept under
`internal/api/testdata/contract/`. It runs in `mage test:unit` and reads only
committed files: it never starts OpenVox Server itself (only re-recording does).
The rule it enforces, and the differences it knows about, are in [the API
reference](../api.md#differences-from-openvox-server).

Each fixture under `fixtures/` is one route and outcome: the request, the
response OpenVox Server gave (headers included, for reference), the image and
OpenVox Server source it came from, and how much of the response is binding:

- `exact`: the status, media type, and every value upstream sent;
- `types`: the status, media type, and every field's presence and JSON type;
- `none`: the status and media type;
- `status`: the status alone, for a request no route serves, whose body is
  the HTTP server's rather than the CA's.

`cadir/` is the store that server held when it answered, its CA bundle, key,
CRL chain, certificates and CSRs, and each spec loads it into a fresh
openvox-ca, so values derived from a certificate can be compared exactly.
Each spec can start from that one snapshot because every recorded answer is
to the snapshot state, which holds for two reasons: the recorder records every
read before any mutation, and no subject is touched by two mutations that
change the store. Most mutations OpenVox Server refuses change nothing, so they
may share a subject; keep such a request refused. A refused autosigned CSR
submission does change the store: OpenVox Server saves the CSR before it checks
whether it may sign it, so that case keeps its subject to itself. The one
exception to the snapshot rule is `/sign/all`, which signs every pending CSR,
including the ones earlier fixtures submitted: it is recorded last and bound
by type only, because its answer is to a later state than the snapshot. The
CA key is a throwaway, generated inside a disposable container for the
recording and committed so the specs can sign with it; nothing should trust
it.

The recording autosigns exactly one subject, named in the `autosign.conf` the
recorder writes beside the fixtures, and the replay reads that file as its own
autosign policy. Every other subject's CSR waits for manual signing on both
sides.

An exception names a difference that openvox-ca still has, exactly as the
checker reports it, and why: an issue, or a ruling to keep its own behaviour.
A difference without one fails the spec, and so does an exception that no
longer matches anything, so fixing a difference fails until its exception is
removed. Each exception has a counterpart in
[the API reference](../api.md#differences-from-openvox-server); add or remove
both in the same commit.

Never hand-edit anything under `testdata/contract/`. A fixture is a record of
what OpenVox Server said, and an edited one is a claim about OpenVox Server
that nobody observed; the next re-record discards it anyway. Change the
recorder instead. The recorder's own suite (`test/contract/record`, run by
`mage test:unit`) fails when the fixtures stop matching its `cases()`: an
edited compare mode or request, a case that was never recorded, or a fixture
no case produces.

### Re-recording

```shell
go run ./test/contract/record
```

It needs Docker and network access. It starts the OpenVox Server image that
`test/compose-migration.yml` pins, signs the corner-case certificates with the
CA that server bootstraps, records every fixture, and replaces
`testdata/contract/` only once the whole recording has succeeded; an
interrupted run removes its container and its partial recording. It replaces
its `-out` directory wholesale, so it refuses one that exists and holds no
contract. The CA is new on every run, so every fixture and certificate
changes. Review the diff for changed shapes rather than values, and expect
exceptions to need their `$[name=…]` paths revisited only when a fixture is
added or renamed.

Nothing ever forces a re-record. The contract is what OpenVox Server answered
on the date and image each fixture names, and the suite keeps checking against
that: a fixture records the image it came from as provenance only, so a
Renovate bump, digest or tag, never fails the suite on its own, and the passing
of time does not either (see below). Re-record when a maintainer chooses to
follow a change upstream. The fixtures
cite the upstream source lines behind each response, checked against one
release, `citedTag` in the recorder, which refuses an image built from any
other. Moving to a new release therefore means rechecking each line range in
`cases()` against its tag, then moving `citedTag`, then re-recording.

The recording's CA and certificates expire, and openvox-ca refuses to issue
from a CA past its expiry. So each spec pins the CA's issuance clock
(`ca.CA.IssueClock`) to the moment the snapshot's CRL was issued, and the
replay answers the same whatever today's date. Nothing else on the replay
path reads the clock in a way the contract compares: re-signing a CRL works
from an expired CA, and the replay bypasses the TLS client checks, which do
read it. A twin spec moves the
clock past the CA's expiry and requires a recorded signing to stop matching,
so the pin cannot quietly stop mattering.
