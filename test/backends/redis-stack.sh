#!/bin/bash
# Integration tests for the Redis (Valkey-compatible) storage backend driving
# the full Puppet stack.
#
# Two-phase test:
#   1. Run the standard puppet-stack TAP suite against compose-backends-redis.yml
#      -- proves catalog application, certificate revocation, and OpenVoxDB
#      reporting all work end-to-end with Redis as the CA's blob store.
#   2. Probe the Redis container directly to confirm that the CA actually
#      writes the expected key layout into Redis (and not, e.g., silently
#      falling back to the filesystem).
#
# Usage:
#   ./test/backends/redis-stack.sh              # run against running stack
#   ./test/backends/redis-stack.sh --up         # start stack, run, tear down
#   ./test/backends/redis-stack.sh --up --keep  # start stack, run, keep running
#
# Output: TAP format. Exit 0 on all pass, exit 1 on any failure.

set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

COMPOSE_FILE="compose-backends-redis.yml"
REDIS_PREFIX="puppet-ca-integ"

# -- Container engine / compose detection ----------------------------------
if [[ -n "${CONTAINER_ENGINE:-}" ]]; then
    _ENGINE="$CONTAINER_ENGINE"
elif command -v podman &>/dev/null; then
    _ENGINE=podman
elif command -v docker &>/dev/null; then
    _ENGINE=docker
else
    printf 'Error: neither podman nor docker found\n' >&2
    exit 1
fi

if [[ "$_ENGINE" == podman ]] && command -v podman-compose &>/dev/null; then
    _COMPOSE=(podman-compose -f "$COMPOSE_FILE")
elif docker compose version &>/dev/null 2>&1; then
    _COMPOSE=(docker compose -f "$COMPOSE_FILE")
elif command -v docker-compose &>/dev/null; then
    _COMPOSE=(docker-compose -f "$COMPOSE_FILE")
else
    printf 'Error: no compose tool found; install podman-compose or docker compose\n' >&2
    exit 1
fi

# -- Argument parsing ------------------------------------------------------
DO_UP=false
DO_KEEP=false

for arg in "$@"; do
    case "$arg" in
        --up)   DO_UP=true ;;
        --keep) DO_KEEP=true ;;
        *) printf 'Unknown argument: %s\n' "$arg" >&2; exit 1 ;;
    esac
done

# -- Stack lifecycle + temp dir cleanup ------------------------------------
WORK_DIR=$(mktemp -d /tmp/redis-stack-integ.XXXXXX)

cleanup() {
    rm -rf "$WORK_DIR"
    if $DO_UP && ! $DO_KEEP; then
        printf '\n# Tearing down compose stack...\n'
        "${_COMPOSE[@]}" down --volumes --timeout 10 2>/dev/null || true
    fi
}
trap cleanup EXIT

if $DO_UP; then
    printf '# Removing any leftover containers from previous runs...\n'
    "${_COMPOSE[@]}" down --volumes --remove-orphans --timeout 10 2>/dev/null || true

    printf '# Building compose images...\n'
    "${_COMPOSE[@]}" build

    printf '# Starting compose stack...\n'
    "${_COMPOSE[@]}" up -d
fi

# -- Phase 1: delegate to puppet-stack.sh against the redis topology -------
# Implemented by run-puppet-stack-on-redis.sh, which sed-rewrites a temp copy
# of test/puppet/puppet-stack.sh with the redis-variant compose file and host
# port mappings. The upstream script is left untouched.
# We pass --keep so the wrapper does not tear the stack down -- this script
# owns the lifecycle. We never pass --up: the stack is already healthy by the
# time we reach here.
printf '\n# Running puppet-stack TAP suite against Redis-backed CA\n'

# puppet-stack.sh expects the stack already healthy when invoked without --up.
# Wait for the CA + master ports the wrapper will use before delegating.
printf '# Waiting for Go CA on host port 8241'
for _i in $(seq 1 60); do
    curl -sfk "https://localhost:8241/puppet-ca/v1/certificate/ca" > /dev/null 2>&1 && break
    printf '.'; sleep 3
done
printf ' OK\n'

# OpenVox Server can take 5-7 minutes on first start.
printf '# Waiting for puppet master on host port 8240'
for _i in $(seq 1 90); do
    curl -sfk "https://localhost:8240/status/v1/simple" 2>/dev/null \
        | grep -q running && break
    printf '.'; sleep 5
done
printf ' OK\n'

# OpenVoxDB (PuppetDB) must be ready before the puppet agent test runs or the
# fact submission (replace_facts) returns 500 and the catalog run fails.
# puppet-stack.sh waits for this only inside its --up block, which is skipped
# when we call it with --keep; so we wait here instead.  Allow 600 s.
printf '# Waiting for OpenVoxDB on openvoxdb:8081'
for _i in $(seq 1 120); do
    _health=$("${_COMPOSE[@]}" exec -T puppet-master \
        curl -ksS "https://openvoxdb:8081/status/v1/simple" 2>/dev/null) || true
    [[ "${_health:-}" == "running" ]] && break
    printf '.'; sleep 5
done
printf ' OK\n'

PHASE1_RC=0
bash test/backends/run-puppet-stack-on-redis.sh --keep \
    || PHASE1_RC=$?

# Whether or not Phase 1 passed, run Phase 2 probes -- failures there are
# diagnostically valuable even when Phase 1 already failed.
printf '\n# Phase 2 -- Redis backend probes\n'

T=0
FAILURES=0

pass() {
    T=$(( T + 1 ))
    printf 'ok %d - %s\n' "$T" "$1"
}

fail() {
    T=$(( T + 1 ))
    FAILURES=$(( FAILURES + 1 ))
    printf 'not ok %d - %s\n' "$T" "$1"
    [ -n "${2:-}" ] && printf '  # %s\n' "$2"
}

# -- Helper: run redis-cli in the redis container -------------------------
redis_cli() {
    "${_COMPOSE[@]}" exec -T redis redis-cli "$@"
}

# -- Helper: redis EXISTS -> bool ----------------------------------------─
# Single source of truth for "does this key exist". redis-cli with --no-raw
# and trailing-whitespace handling lives here so each call site doesn't
# re-implement the parse.
redis_exists() {  # key
    local _v
    _v=$(redis_cli EXISTS "$1" 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
    [ "$_v" = "1" ]
}

# -- Helper: poll a predicate until it succeeds or a deadline elapses -----
# Replaces fixed `sleep N # wait for ...` calls. Polls at 200ms intervals
# (fine-grained enough that fast operations don't pay much wait, slow
# enough that a 10s-timeout test isn't running 50 round-trips a second).
# Usage:  poll_until <timeout-sec>  cmd args...
# Returns 0 once `cmd args...` returns 0; 1 once the deadline passes.
poll_until() {  # timeout_sec  cmd...
    local _to="$1"; shift
    local _deadline=$(( $(date +%s) + _to ))
    while ! "$@" >/dev/null 2>&1; do
        [ "$(date +%s)" -ge "$_deadline" ] && return 1
        sleep 0.2
    done
    return 0
}

# -- Helper: predicate "all of these redis keys exist" --------------------
all_redis_keys_exist() {  # key1 key2 ...
    local _k
    for _k in "$@"; do
        redis_exists "$_k" || return 1
    done
    return 0
}

# -- Helper: predicate "<inventory blob> contains every passed CN" --------
inventory_contains_all() {  # cn1 cn2 ...
    local _f="$WORK_DIR/.inv-poll.dat"
    redis_cli --raw GETRANGE "${REDIS_PREFIX}:inventory:data" 8 -1 \
        > "$_f" 2>/dev/null || return 1
    local _cn
    for _cn in "$@"; do
        grep -qF "$_cn" "$_f" || return 1
    done
    return 0
}

# -- Helper: revoke via the puppet-master container's mTLS admin cert -----
# puppet-master is already authorised as a CA admin (see ca-entrypoint-redis.sh
# servers.txt setup). Running curl from inside the master container avoids
# having to extract the master cert to the host. Returns the HTTP status
# code on stdout.
revoke_via_master() {  # subject  ca-host[:port]
    local _subj="$1" _host="${2:-puppet-ca:8140}"
    "${_COMPOSE[@]}" exec -T puppet-master curl -s -o /dev/null -w '%{http_code}' \
        --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
        --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
        --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
        -X PUT -H 'Content-Type: application/json' \
        -d '{"desired_state":"revoked"}' \
        "https://${_host}/puppet-ca/v1/certificate_status/${_subj}" \
        2>/dev/null
}

# -- Helper: count revoked entries in the CRL ----------------------------─
# Pulls the CRL from the given host:port via curl-from-master (uses the
# master's CA bundle). Returns the count of "Serial Number:" lines in
# `openssl crl -text -noout`.
count_crl_entries_via() {  # ca-host[:port]
    local _host="${1:-puppet-ca:8140}"
    "${_COMPOSE[@]}" exec -T puppet-master sh -c "
        curl -sf --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
            'https://${_host}/puppet-ca/v1/certificate_revocation_list/ca' \
            2>/dev/null | openssl crl -text -noout 2>/dev/null \
            | grep -c 'Serial Number:' \
            || echo 0
    " 2>/dev/null | tr -d '\r' | tr -d '[:space:]'
}

# -- Helper: predicate "CRL count on host >= N" ---------------------------
crl_count_at_least() {  # host  min
    local _c
    _c=$(count_crl_entries_via "$1")
    [ "${_c:-0}" -ge "$2" ]
}

# -- Probe: redis container is healthy ------------------------------------
_pong=$(redis_cli ping 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
if [ "$_pong" = "PONG" ]; then
    pass "Redis container responds to PING"
else
    fail "Redis container responds to PING" "got: '$_pong'"
fi

# -- Probe: CA cert blob stored under expected key ------------------------
# physicalKey for KeyCACert = "<prefix>:ca:cert" (see redisLayout in redis.go).
_ca_key="${REDIS_PREFIX}:ca:cert"
_ca_exists=$(redis_cli EXISTS "$_ca_key" 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
if [ "$_ca_exists" = "1" ]; then
    pass "CA cert stored in Redis at ${_ca_key}"
else
    fail "CA cert stored in Redis at ${_ca_key}" "EXISTS returned '$_ca_exists'"
fi

# Blob layout: 8-byte big-endian nanosecond mtime prefix, then PEM payload.
# STRLEN must be > 8 if a real PEM body is present.
_ca_len=$(redis_cli STRLEN "$_ca_key" 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
if [ -n "$_ca_len" ] && [ "$_ca_len" -gt 8 ] 2>/dev/null; then
    pass "CA cert blob has body bytes after mtime header (STRLEN=${_ca_len})"
else
    fail "CA cert blob has body bytes after mtime header" "STRLEN=$_ca_len"
fi

# Body should contain PEM markers. GETRANGE skips the 8-byte mtime header.
_ca_body=$(redis_cli --raw GETRANGE "$_ca_key" 8 -1 2>/dev/null) || _ca_body=""
if grep -q "BEGIN CERTIFICATE" <<< "$_ca_body"; then
    pass "CA cert blob payload contains PEM header"
else
    fail "CA cert blob payload contains PEM header" "first 80 chars: ${_ca_body:0:80}"
fi

# -- Probe: CA private key stored in Redis --------------------------------
# KeyCAKey -> "<prefix>:ca:key"
_cakey_key="${REDIS_PREFIX}:ca:key"
_cakey_exists=$(redis_cli EXISTS "$_cakey_key" 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
if [ "$_cakey_exists" = "1" ]; then
    pass "CA private key stored in Redis at ${_cakey_key}"
else
    fail "CA private key stored in Redis at ${_cakey_key}" "EXISTS returned '$_cakey_exists'"
fi

# -- Probe: CRL stored in Redis -------------------------------------------
_crl_key="${REDIS_PREFIX}:ca:crl"
_crl_exists=$(redis_cli EXISTS "$_crl_key" 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
if [ "$_crl_exists" = "1" ]; then
    pass "CRL stored in Redis at ${_crl_key}"
else
    fail "CRL stored in Redis at ${_crl_key}" "EXISTS returned '$_crl_exists'"
fi

# -- Probe: serial counter is ABSENT after fresh bootstrap ----------------
# The KeySerial blob is a Puppet-server-compat artifact: it is only written
# by seedSupportingState (CA cert+key pre-existing via overlay) or caImport.
# Fresh bootstrap uses a 128-bit cryptographic random for cert serials and
# never touches this key. Asserting absence catches a future regression
# where someone "helpfully" starts populating it on bootstrap and changes
# the migration semantics.
_serial_key="${REDIS_PREFIX}:serial"
_serial_exists=$(redis_cli EXISTS "$_serial_key" 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
if [ "$_serial_exists" = "0" ]; then
    pass "Serial counter ABSENT in Redis on fresh bootstrap (Puppet-compat artifact)"
else
    fail "Serial counter ABSENT in Redis on fresh bootstrap" \
         "EXISTS returned '$_serial_exists' -- bootstrap path may have changed"
fi

# -- Probe: signed certs from puppet-stack run appear under signed:* ------
# After Phase 1 the master and client both have signed certs. They land in
# Redis under <prefix>:signed:<subject>.  KEYS is fine here -- the keyspace is
# small and bounded by the test stack.
_signed_count=$(redis_cli --raw KEYS "${REDIS_PREFIX}:signed:*" 2>/dev/null | grep -c "^${REDIS_PREFIX}:signed:" || true)
if [ "${_signed_count:-0}" -ge 2 ]; then
    pass "Signed certs present in Redis (count=${_signed_count}, expected >=2)"
else
    fail "Signed certs present in Redis (>=2 expected)" "count=${_signed_count:-0}"
fi

# Specifically: puppet-master and the puppet-ca service cert itself must exist.
for _cn in puppet-master puppet-ca; do
    _signed_key="${REDIS_PREFIX}:signed:${_cn}"
    _signed_exists=$(redis_cli EXISTS "$_signed_key" 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
    if [ "$_signed_exists" = "1" ]; then
        pass "Signed cert for ${_cn} stored at ${_signed_key}"
    else
        fail "Signed cert for ${_cn} stored at ${_signed_key}" "EXISTS returned '$_signed_exists'"
    fi
done

# -- Probe: HMAC key for inventory was initialised ------------------------
_hmac_key="${REDIS_PREFIX}:private:hmac_key"
_hmac_exists=$(redis_cli EXISTS "$_hmac_key" 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
if [ "$_hmac_exists" = "1" ]; then
    pass "Inventory HMAC key stored in Redis at ${_hmac_key}"
else
    fail "Inventory HMAC key stored in Redis at ${_hmac_key}" "EXISTS returned '$_hmac_exists'"
fi

# -- Probe: round-trip a fresh CSR through the API and observe it in Redis ─
# This catches a regression where the CA might have started bypassing the
# storage backend entirely (e.g. caching writes only in memory).
PROBE_CN="redis-probe-$(date +%s)"

# Download CA cert from the host-mapped CA port (compose-backends-redis.yml
# maps puppet-ca:8140 to host:8241).
if curl -sfk "https://localhost:8241/puppet-ca/v1/certificate/ca" \
        -o "$WORK_DIR/ca.pem" 2>/dev/null; then
    pass "Downloaded CA cert from host-mapped CA port"
else
    fail "Downloaded CA cert from host-mapped CA port" "curl failed"
fi

openssl genrsa -out "$WORK_DIR/probe.key" 2048 2>/dev/null
chmod 600 "$WORK_DIR/probe.key"
openssl req -new -key "$WORK_DIR/probe.key" -subj "/CN=${PROBE_CN}" \
    -out "$WORK_DIR/probe.csr" 2>/dev/null

_csr_st=$(curl -s -o /dev/null -w '%{http_code}' \
    --cacert "$WORK_DIR/ca.pem" \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/probe.csr" \
    "https://localhost:8241/puppet-ca/v1/certificate_request/${PROBE_CN}" 2>/dev/null) || _csr_st=000
if [[ "$_csr_st" =~ ^2 ]]; then
    pass "Probe CSR submission to Redis-backed CA returns 2xx"
else
    fail "Probe CSR submission to Redis-backed CA returns 2xx" "got HTTP $_csr_st"
fi

# Wait for autosign by polling for the signed-cert blob in Redis rather
# than a fixed sleep -- the CA's autosign path is normally <100ms but a
# loaded CI runner can stretch it.
_probe_key="${REDIS_PREFIX}:signed:${PROBE_CN}"
poll_until 10 redis_exists "$_probe_key" || true

if redis_exists "$_probe_key"; then
    pass "Autosigned probe cert appears in Redis at ${_probe_key}"
else
    fail "Autosigned probe cert appears in Redis at ${_probe_key}" \
         "key never appeared within poll timeout"
fi

# And the cert downloaded from the API should match the Redis blob payload.
if curl -sf --cacert "$WORK_DIR/ca.pem" \
        "https://localhost:8241/puppet-ca/v1/certificate/${PROBE_CN}" \
        -o "$WORK_DIR/probe.crt" 2>/dev/null; then
    pass "Probe cert downloadable from API"
else
    fail "Probe cert downloadable from API"
fi

if openssl verify -CAfile "$WORK_DIR/ca.pem" "$WORK_DIR/probe.crt" \
       >/dev/null 2>&1; then
    pass "Probe cert verifies against CA"
else
    fail "Probe cert verifies against CA"
fi

# -- Probe: prefix isolation is real --------------------------------------
# All keys this test exercises must live under <prefix>:* . Any key outside
# the prefix would indicate a bug -- e.g. the backend storing something at
# the root namespace or under a different prefix than configured.
_total=$(redis_cli DBSIZE 2>/dev/null | tr -d '\r' | tr -d '[:space:]')
_under_prefix=$(redis_cli --raw KEYS "${REDIS_PREFIX}:*" 2>/dev/null \
    | grep -c "^${REDIS_PREFIX}:" || true)
if [ "${_total:-0}" -gt 0 ] && [ "${_under_prefix:-0}" = "${_total:-0}" ]; then
    pass "All Redis keys (${_total}) live under prefix '${REDIS_PREFIX}:'"
else
    fail "All Redis keys live under prefix '${REDIS_PREFIX}:'" \
         "total=${_total:-0}, under_prefix=${_under_prefix:-0}"
fi

# ═════════════════════════════════════════════════════════════════════════
# Phase 3 -- Deep "actually-in-Redis" assertions
# These tests are designed to catch regressions where the CA appears to work
# (the API responds correctly) but is silently bypassing the Redis backend
# (e.g. caching in process memory, or falling back to disk).
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Phase 3 -- Deep Redis-offload assertions\n'

# -- Cert identity: API-served cert and Redis blob are the same cert ------
# Comparing PEM bytes directly is fragile (redis-cli output formatting,
# trailing newlines). The robust check is to confirm both PEMs decode to a
# certificate with the same SHA-256 fingerprint. If they don't match, the
# API and the storage layer are not in sync.
# --raw forces redis-cli to emit binary-safe output regardless of TTY.
if [ -s "$WORK_DIR/probe.crt" ]; then
    redis_cli --raw GETRANGE "$_probe_key" 8 -1 \
        > "$WORK_DIR/probe.from-redis.pem" 2>/dev/null || true
    _api_fpr=$(openssl x509 -in "$WORK_DIR/probe.crt" \
        -noout -fingerprint -sha256 2>/dev/null) || _api_fpr=""
    _redis_fpr=$(openssl x509 -in "$WORK_DIR/probe.from-redis.pem" \
        -noout -fingerprint -sha256 2>/dev/null) || _redis_fpr=""
    if [ -n "$_api_fpr" ] && [ "$_api_fpr" = "$_redis_fpr" ]; then
        pass "API-served cert and Redis blob have identical SHA-256 fingerprint"
    else
        fail "API-served cert and Redis blob have identical SHA-256 fingerprint" \
             "api='${_api_fpr}' redis='${_redis_fpr}'"
    fi
else
    fail "API-served cert and Redis blob have identical SHA-256 fingerprint" \
         "probe cert was not downloaded earlier"
fi

# -- Filesystem absence: public blobs are NOT on local disk ---------------
# With the redis backend, signed certs and the CRL must live in Redis only.
# A regression that re-enables filesystem writes would create files under
# /data/signed/, /data/ca_crt.pem, /data/ca_key.pem on the CA container.
# We tolerate /data/signed/<replica-hostname>.pem and the matching key
# because the bootstrap entrypoint legitimately writes the TLS service cert
# there for Phase 2 startup; nothing else may exist under /data/signed/.
_unexpected_signed=$("${_COMPOSE[@]}" exec -T puppet-ca \
    sh -c "ls /data/signed 2>/dev/null | grep -v '^puppet-ca\.pem\$' || true" \
    2>/dev/null | tr -d '\r')
if [ -z "$_unexpected_signed" ]; then
    pass "puppet-ca /data/signed contains only its own TLS service cert"
else
    fail "puppet-ca /data/signed contains only its own TLS service cert" \
         "unexpected files: $(printf '%s' "$_unexpected_signed" | tr '\n' ' ')"
fi

# Probe-cert specifically must NOT be on disk on either replica.
for _svc in puppet-ca puppet-ca-2; do
    _on_disk=$("${_COMPOSE[@]}" exec -T "$_svc" \
        sh -c "test -e /data/signed/${PROBE_CN}.pem && echo yes || echo no" \
        2>/dev/null | tr -d '\r' | tr -d '[:space:]')
    if [ "$_on_disk" = "no" ]; then
        pass "Probe cert ${PROBE_CN} is NOT on local disk of ${_svc}"
    else
        fail "Probe cert ${PROBE_CN} is NOT on local disk of ${_svc}" \
             "ls returned: $_on_disk"
    fi
done

# Same check for the CRL: with redis backend it must NOT be at /data/ca_crl.pem.
_crl_on_disk=$("${_COMPOSE[@]}" exec -T puppet-ca \
    sh -c "test -e /data/ca_crl.pem && echo yes || echo no" \
    2>/dev/null | tr -d '\r' | tr -d '[:space:]')
if [ "$_crl_on_disk" = "no" ]; then
    pass "CRL is NOT on local disk of puppet-ca (Redis-only)"
else
    fail "CRL is NOT on local disk of puppet-ca (Redis-only)"
fi

# CA cert and CA key must also be Redis-only (no overlay configured).
for _name in ca_crt.pem ca_key.pem; do
    _f_on_disk=$("${_COMPOSE[@]}" exec -T puppet-ca \
        sh -c "test -e /data/${_name} && echo yes || echo no" \
        2>/dev/null | tr -d '\r' | tr -d '[:space:]')
    if [ "$_f_on_disk" = "no" ]; then
        pass "CA blob ${_name} is NOT on local disk of puppet-ca (Redis-only)"
    else
        fail "CA blob ${_name} is NOT on local disk of puppet-ca (Redis-only)"
    fi
done

# -- Tamper test: mutate the blob in Redis, the API must serve the change -
# Catches regressions where the CA caches the blob in process memory and
# stops consulting Redis after first read. We restore the original blob
# afterwards so we don't break subsequent assertions.
TAMPER_CN="${PROBE_CN}"
TAMPER_KEY="${REDIS_PREFIX}:signed:${TAMPER_CN}"
redis_cli --raw GET "$TAMPER_KEY" > "$WORK_DIR/tamper.original" 2>/dev/null || true
# Build a tampered blob: keep the 8-byte mtime header, replace the body.
TAMPERED_BODY="REDIS_TAMPER_SENTINEL_$(date +%s)"
# Use redis-cli SET to overwrite. We pass the body via stdin to avoid argv
# escaping issues; the blob is binary-safe.
redis_cli SETRANGE "$TAMPER_KEY" 8 "$TAMPERED_BODY" > /dev/null 2>&1 || true

# Pull the certificate via the CA's HTTP API; should now contain the sentinel.
_after=$(curl -s --cacert "$WORK_DIR/ca.pem" \
    "https://localhost:8241/puppet-ca/v1/certificate/${TAMPER_CN}" 2>/dev/null) || _after=""
if grep -qF "REDIS_TAMPER_SENTINEL" <<< "$_after"; then
    pass "API reads-through to Redis (tampered sentinel observed)"
else
    fail "API reads-through to Redis (tampered sentinel observed)" \
         "API response did not contain sentinel; first 80 chars: ${_after:0:80}"
fi

# Restore the original blob so the rest of the suite operates on a healthy
# value (avoids cascading failures from the deliberate corruption above).
if [ -s "$WORK_DIR/tamper.original" ]; then
    # SET via stdin via cat -- redis-cli -x reads the value from stdin, which
    # is the only safe way to push arbitrary bytes through the CLI.
    redis_cli -x SET "$TAMPER_KEY" < "$WORK_DIR/tamper.original" > /dev/null 2>&1 \
        || true
fi

# ═════════════════════════════════════════════════════════════════════════
# Phase 4 -- Multi-replica state visibility & concurrent writers
# Two CA replicas (puppet-ca + puppet-ca-2) share the same Redis prefix.
# This phase verifies they observe the same state, and that concurrent
# writes from both replicas produce a consistent result.
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Phase 4 -- Multi-replica visibility & concurrency\n'

# Wait for replica 2 to be healthy before probing it (its Phase 1 bootstrap
# may still be running when Phase 1's puppet-stack tests finish).
printf '# Waiting for puppet-ca-2 on host port 8242'
for _i in $(seq 1 60); do
    curl -sfk "https://localhost:8242/puppet-ca/v1/certificate/ca" > /dev/null 2>&1 && break
    printf '.'; sleep 3
done
printf ' OK\n'

# -- Bootstrap lock: only one CA cert/key should exist in Redis -----------
# Both replicas raced to bootstrap; the distributed lock must have ensured
# only one of them actually wrote ca:cert and ca:key. Multiple writers
# would manifest as a sequence of overwrites with the same key, so we can't
# detect that purely from key existence -- but we CAN check that the cert
# and key cross-validate as a pair (they would not if two replicas had each
# written a different freshly-generated CA).
"${_COMPOSE[@]}" exec -T puppet-ca \
    sh -c 'curl -sfk https://localhost:8140/puppet-ca/v1/certificate/ca' \
    > "$WORK_DIR/ca-from-r1.pem" 2>/dev/null || true
"${_COMPOSE[@]}" exec -T puppet-ca-2 \
    sh -c 'curl -sfk https://localhost:8140/puppet-ca/v1/certificate/ca' \
    > "$WORK_DIR/ca-from-r2.pem" 2>/dev/null || true

if cmp -s "$WORK_DIR/ca-from-r1.pem" "$WORK_DIR/ca-from-r2.pem"; then
    pass "Both CA replicas serve the identical CA cert (bootstrap lock worked)"
else
    fail "Both CA replicas serve the identical CA cert (bootstrap lock worked)" \
         "CA cert from replica 1 differs from replica 2"
fi

# -- Cross-replica visibility: a cert signed by replica 1 is fetchable
# byte-for-byte from replica 2.
XREP_CN="redis-xrep-$(date +%s)"
openssl genrsa -out "$WORK_DIR/xrep.key" 2048 2>/dev/null
chmod 600 "$WORK_DIR/xrep.key"
openssl req -new -key "$WORK_DIR/xrep.key" -subj "/CN=${XREP_CN}" \
    -out "$WORK_DIR/xrep.csr" 2>/dev/null

# Submit to replica 1.
_xrep_st=$(curl -s -o /dev/null -w '%{http_code}' \
    --cacert "$WORK_DIR/ca.pem" \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/xrep.csr" \
    "https://localhost:8241/puppet-ca/v1/certificate_request/${XREP_CN}" 2>/dev/null) || _xrep_st=000
if [[ "$_xrep_st" =~ ^2 ]]; then
    pass "CSR signed by replica 1 returns 2xx"
else
    fail "CSR signed by replica 1 returns 2xx" "got HTTP $_xrep_st"
fi

# Wait for the autosigned cert blob to appear before fetching it.
poll_until 10 redis_exists "${REDIS_PREFIX}:signed:${XREP_CN}" || true

# Fetch from replica 1.
curl -sf --cacert "$WORK_DIR/ca.pem" \
    "https://localhost:8241/puppet-ca/v1/certificate/${XREP_CN}" \
    -o "$WORK_DIR/xrep-r1.crt" 2>/dev/null || true

# Replica 2 was not asked to sign anything for ${XREP_CN}. If it serves an
# identical cert, it can only have come from shared Redis state.
# replica 2 uses its own self-signed TLS hostname (puppet-ca-2), so we use
# -k for the cert-fetch since we're only validating the *body*, not chain.
curl -sfk \
    "https://localhost:8242/puppet-ca/v1/certificate/${XREP_CN}" \
    -o "$WORK_DIR/xrep-r2.crt" 2>/dev/null || true

if [ -s "$WORK_DIR/xrep-r1.crt" ] && [ -s "$WORK_DIR/xrep-r2.crt" ] && \
   cmp -s "$WORK_DIR/xrep-r1.crt" "$WORK_DIR/xrep-r2.crt"; then
    pass "Replica 2 serves the same cert byte-for-byte as replica 1 (shared Redis state)"
else
    fail "Replica 2 serves the same cert byte-for-byte as replica 1" \
         "r1=$(stat -c %s "$WORK_DIR/xrep-r1.crt" 2>/dev/null) bytes, r2=$(stat -c %s "$WORK_DIR/xrep-r2.crt" 2>/dev/null) bytes"
fi

# -- Concurrent CSR submissions split across both replicas ----------------
# Submits N CSRs to each replica simultaneously. After all submissions:
#   1. Every CSR must be signed (cert downloadable from BOTH replicas).
#   2. The Redis signed:* count must reflect every new cert.
# This exercises the AppendLine-based inventory writes (single shared blob,
# multiple writers across replicas), the per-subject locks, and the
# bootstrap CRL lock when concurrent revocations happen.
N_PER_REPLICA=4
START_SIGNED_COUNT=$(redis_cli --raw KEYS "${REDIS_PREFIX}:signed:*" \
    2>/dev/null | grep -c "^${REDIS_PREFIX}:signed:" || true)

submit_one() {  # replica_port  cn
    local _port="$1" _cn="$2"
    openssl genrsa -out "$WORK_DIR/${_cn}.key" 2048 2>/dev/null
    chmod 600 "$WORK_DIR/${_cn}.key"
    openssl req -new -key "$WORK_DIR/${_cn}.key" -subj "/CN=${_cn}" \
        -out "$WORK_DIR/${_cn}.csr" 2>/dev/null
    curl -sk -o /dev/null \
        -X PUT -H "Content-Type: text/plain" \
        --data-binary @"$WORK_DIR/${_cn}.csr" \
        "https://localhost:${_port}/puppet-ca/v1/certificate_request/${_cn}" \
        2>/dev/null
}

CONC_NAMES=()
RUN_BASE=$(date +%s)
for _i in $(seq 1 "$N_PER_REPLICA"); do
    _r1_cn="conc-r1-${RUN_BASE}-${_i}"
    _r2_cn="conc-r2-${RUN_BASE}-${_i}"
    CONC_NAMES+=("$_r1_cn" "$_r2_cn")
    submit_one 8241 "$_r1_cn" &
    submit_one 8242 "$_r2_cn" &
done
wait

# Wait until every concurrent CSR has produced a signed:<cn> blob in Redis,
# rather than a fixed sleep that's both flaky on slow runners and wasteful
# on fast ones.
_expect_keys=()
for _cn in "${CONC_NAMES[@]}"; do
    _expect_keys+=("${REDIS_PREFIX}:signed:${_cn}")
done
poll_until 30 all_redis_keys_exist "${_expect_keys[@]}" || true

# After the deadline, count whatever did/didn't make it for the assertion.
_missing_in_redis=()
for _cn in "${CONC_NAMES[@]}"; do
    redis_exists "${REDIS_PREFIX}:signed:${_cn}" || _missing_in_redis+=("$_cn")
done
if [ "${#_missing_in_redis[@]}" -eq 0 ]; then
    pass "All ${#CONC_NAMES[@]} concurrent CSRs landed in Redis"
else
    fail "All ${#CONC_NAMES[@]} concurrent CSRs landed in Redis" \
         "missing: ${_missing_in_redis[*]:0:6}..."
fi

# Each cert must be retrievable from BOTH replicas.
_unreachable=()
for _cn in "${CONC_NAMES[@]}"; do
    for _port in 8241 8242; do
        _hc=$(curl -sk -o /dev/null -w '%{http_code}' \
            "https://localhost:${_port}/puppet-ca/v1/certificate/${_cn}" \
            2>/dev/null) || _hc=000
        if [[ ! "$_hc" =~ ^2 ]]; then
            _unreachable+=("${_cn}@${_port}=${_hc}")
        fi
    done
done
if [ "${#_unreachable[@]}" -eq 0 ]; then
    pass "All concurrent certs retrievable from both replicas"
else
    fail "All concurrent certs retrievable from both replicas" \
         "unreachable: ${_unreachable[*]:0:6}..."
fi

# Signed-key count must have grown by exactly 2*N_PER_REPLICA.
END_SIGNED_COUNT=$(redis_cli --raw KEYS "${REDIS_PREFIX}:signed:*" \
    2>/dev/null | grep -c "^${REDIS_PREFIX}:signed:" || true)
_expected_growth=$(( 2 * N_PER_REPLICA ))
_actual_growth=$(( END_SIGNED_COUNT - START_SIGNED_COUNT ))
if [ "$_actual_growth" -eq "$_expected_growth" ]; then
    pass "Signed-key count grew by exactly ${_expected_growth} (saw ${_actual_growth})"
else
    fail "Signed-key count grew by exactly ${_expected_growth}" \
         "saw growth ${_actual_growth} (start=${START_SIGNED_COUNT}, end=${END_SIGNED_COUNT})"
fi

# Inventory must contain a line per concurrent CN -- this is the AppendLine
# concurrency path under load. We grep the body (skipping mtime header) for
# each CN and require all to be present.
redis_cli --raw GETRANGE "${REDIS_PREFIX}:inventory:data" 8 -1 \
    > "$WORK_DIR/inventory.dat" 2>/dev/null || true
_missing_inventory=()
for _cn in "${CONC_NAMES[@]}"; do
    grep -qF "$_cn" "$WORK_DIR/inventory.dat" || _missing_inventory+=("$_cn")
done
if [ "${#_missing_inventory[@]}" -eq 0 ]; then
    pass "Inventory blob contains every concurrent CN (AppendLine atomicity)"
else
    fail "Inventory blob contains every concurrent CN (AppendLine atomicity)" \
         "missing from inventory: ${_missing_inventory[*]:0:6}..."
fi

# ═════════════════════════════════════════════════════════════════════════
# Phase 5 -- Aggressive race-condition torture
# Targets the three coordination paths in the redis backend:
#   (a) per-subject lock around CSR/cert writes (same-CN storm)
#   (b) "crl" distributed lock around revocations (concurrent revoke storm)
#   (c) AppendLine Lua atomicity on the shared inventory blob (line storm)
# Plus cross-replica visibility: state written via replica 1 must be
# observable from replica 2 within one round-trip after the writer returns.
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Phase 5 -- Race condition torture\n'

# -- Race A: same-CN CSR storm across both replicas ----------------------─
# Eight CSRs for the same CN, each with a different private key, fired in
# parallel and split across both replicas. After settling, exactly one cert
# must exist (the per-subject lock + last-write-wins SET semantics) and that
# cert must verify against the CA.
RACE_CN="race-samecn-$(date +%s)"
RACE_PARALLEL=8
for _i in $(seq 1 "$RACE_PARALLEL"); do
    openssl genrsa -out "$WORK_DIR/race-${_i}.key" 2048 2>/dev/null
    chmod 600 "$WORK_DIR/race-${_i}.key"
    openssl req -new -key "$WORK_DIR/race-${_i}.key" -subj "/CN=${RACE_CN}" \
        -out "$WORK_DIR/race-${_i}.csr" 2>/dev/null
done

# Fire all submissions in parallel, alternating replicas.
for _i in $(seq 1 "$RACE_PARALLEL"); do
    _port=8241
    [ $(( _i % 2 )) -eq 0 ] && _port=8242
    curl -sk -o /dev/null \
        -X PUT -H "Content-Type: text/plain" \
        --data-binary @"$WORK_DIR/race-${_i}.csr" \
        "https://localhost:${_port}/puppet-ca/v1/certificate_request/${RACE_CN}" \
        2>/dev/null &
done
wait

# Wait for at least one autosigned cert to land before assertion. The
# per-subject lock serialises the 8 concurrent writers; after the last
# writer drops the lock, signed:<RACE_CN> exists. Polling here also gives
# the SET-overwrite race a chance to converge to its final value (the
# "last writer wins" property is what we're about to assert).
poll_until 15 redis_exists "${REDIS_PREFIX}:signed:${RACE_CN}" || true

# Exactly one signed:<RACE_CN> blob must exist.
_race_signed_count=$(redis_cli --raw KEYS "${REDIS_PREFIX}:signed:${RACE_CN}" \
    2>/dev/null | grep -c "^${REDIS_PREFIX}:signed:${RACE_CN}\$" || true)
if [ "${_race_signed_count:-0}" = "1" ]; then
    pass "Same-CN race produced exactly one signed cert (per-subject lock)"
else
    fail "Same-CN race produced exactly one signed cert" \
         "found ${_race_signed_count} blobs at signed:${RACE_CN}"
fi

# The cert must verify against the CA, regardless of which CSR's key won.
curl -sf --cacert "$WORK_DIR/ca.pem" \
    "https://localhost:8241/puppet-ca/v1/certificate/${RACE_CN}" \
    -o "$WORK_DIR/race.crt" 2>/dev/null || true
if [ -s "$WORK_DIR/race.crt" ] && \
   openssl verify -CAfile "$WORK_DIR/ca.pem" "$WORK_DIR/race.crt" \
       >/dev/null 2>&1; then
    pass "Same-CN race winner verifies against CA"
else
    fail "Same-CN race winner verifies against CA"
fi

# The cert's public key must match exactly one of the submitted CSR keys
# (proves the cert wasn't fabricated from random data, and that the
# per-subject lock didn't somehow fuse keys from multiple CSRs).
_cert_pubkey_md5=$(openssl x509 -in "$WORK_DIR/race.crt" -pubkey -noout \
    2>/dev/null | openssl md5 2>/dev/null | awk '{print $NF}')
_match_count=0
for _i in $(seq 1 "$RACE_PARALLEL"); do
    _csr_pubkey_md5=$(openssl req -in "$WORK_DIR/race-${_i}.csr" -pubkey -noout \
        2>/dev/null | openssl md5 2>/dev/null | awk '{print $NF}')
    [ -n "$_cert_pubkey_md5" ] && [ "$_cert_pubkey_md5" = "$_csr_pubkey_md5" ] && \
        _match_count=$(( _match_count + 1 ))
done
if [ "$_match_count" = "1" ]; then
    pass "Same-CN race cert's pubkey matches exactly one submitted CSR"
else
    fail "Same-CN race cert's pubkey matches exactly one submitted CSR" \
         "matched ${_match_count} CSR keys (expected 1)"
fi

# -- Race B: concurrent revocations across both replicas ----------------─
# Use the certs minted in Phase 4's CSR storm as revocation targets.
# Half are revoked via replica 1, half via replica 2, all in parallel.
# After settling, every CN must appear in the CRL (via either replica).

# Snapshot the CRL count BEFORE the storm.
_crl_before=$(count_crl_entries_via "puppet-ca:8140")

# Fire revocations in parallel.
for _i in "${!CONC_NAMES[@]}"; do
    _cn="${CONC_NAMES[$_i]}"
    _host="puppet-ca:8140"
    [ $(( _i % 2 )) -eq 1 ] && _host="puppet-ca-2:8140"
    revoke_via_master "$_cn" "$_host" > /dev/null 2>&1 &
done
wait

# Wait until the CRL count reflects the storm on at least one replica;
# without this the assertion can fire before the last revocation has
# released the "crl" distributed lock and re-emitted the CRL.
_expected_growth=${#CONC_NAMES[@]}
_target=$(( _crl_before + _expected_growth ))
poll_until 60 crl_count_at_least "puppet-ca:8140" "$_target" || true
poll_until 60 crl_count_at_least "puppet-ca-2:8140" "$_target" || true

# CRL count must have grown by exactly the storm size on BOTH replicas.
_crl_after_r1=$(count_crl_entries_via "puppet-ca:8140")
_crl_after_r2=$(count_crl_entries_via "puppet-ca-2:8140")

# Each replica's CRL count grew by the expected amount.
if [ "${_crl_after_r1:-0}" -ge $(( _crl_before + _expected_growth )) ]; then
    pass "Replica 1 CRL count grew by >=${_expected_growth} after concurrent revoke storm"
else
    fail "Replica 1 CRL count grew by >=${_expected_growth} after concurrent revoke storm" \
         "before=${_crl_before} after=${_crl_after_r1:-?}"
fi
if [ "${_crl_after_r2:-0}" -ge $(( _crl_before + _expected_growth )) ]; then
    pass "Replica 2 CRL count grew by >=${_expected_growth} after concurrent revoke storm"
else
    fail "Replica 2 CRL count grew by >=${_expected_growth} after concurrent revoke storm" \
         "before=${_crl_before} after=${_crl_after_r2:-?}"
fi

# Both replicas must agree on the CRL count (cross-replica state coherence).
if [ "${_crl_after_r1:-0}" = "${_crl_after_r2:-0}" ]; then
    pass "Both replicas agree on CRL entry count after revoke storm (=${_crl_after_r1})"
else
    fail "Both replicas agree on CRL entry count" \
         "r1=${_crl_after_r1:-?} r2=${_crl_after_r2:-?}"
fi

# -- Race C: cross-replica revocation visibility (read-after-write) -------
# Revoke a fresh cert via replica 1 and immediately read the CRL from
# replica 2. The revocation must be observable on replica 2 (no caching).
# Comparing serials between cert hex (ABCDEF...) and CRL output
# (ab:cd:ef:...) is fragile; counting CRL entries on replica 2 before vs
# after the revoke is the same property in a robust form.
VIS_CN="redis-revvis-$(date +%s)"
openssl genrsa -out "$WORK_DIR/vis.key" 2048 2>/dev/null
chmod 600 "$WORK_DIR/vis.key"
openssl req -new -key "$WORK_DIR/vis.key" -subj "/CN=${VIS_CN}" \
    -out "$WORK_DIR/vis.csr" 2>/dev/null
curl -sf --cacert "$WORK_DIR/ca.pem" \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/vis.csr" \
    "https://localhost:8241/puppet-ca/v1/certificate_request/${VIS_CN}" \
    > /dev/null 2>&1 || true
# Wait for autosign before revoking so the revoke handler has a cert to act on.
poll_until 10 redis_exists "${REDIS_PREFIX}:signed:${VIS_CN}" || true

_vis_before=$(count_crl_entries_via "puppet-ca-2:8140")
revoke_via_master "$VIS_CN" "puppet-ca:8140" > /dev/null 2>&1
# No sleep here -- the entire point is that the revocation should be
# visible on replica 2 immediately, since both replicas share Redis.
_vis_after=$(count_crl_entries_via "puppet-ca-2:8140")

if [ -n "$_vis_after" ] && [ "${_vis_after:-0}" -gt "${_vis_before:-0}" ]; then
    pass "Revocation on replica 1 immediately visible on replica 2 (CRL: ${_vis_before} -> ${_vis_after})"
else
    fail "Revocation on replica 1 immediately visible on replica 2" \
         "r2 CRL count before=${_vis_before:-?} after=${_vis_after:-?}"
fi

# -- Race D: AppendLine torture under cross-replica contention -------------
# Many parallel writers call AppendLine on the inventory via the CA's CSR
# autosign path. Each CSR submission writes one inventory line. We spawn
# 2*N submitters, alternating replicas, with no per-replica slow-down.
# Every submitted CN must end up in the inventory blob exactly once.
TORTURE_BASE=$(date +%s)
TORTURE_PER_REPLICA=8
TORTURE_NAMES=()
for _i in $(seq 1 "$TORTURE_PER_REPLICA"); do
    _r1_cn="torture-r1-${TORTURE_BASE}-${_i}"
    _r2_cn="torture-r2-${TORTURE_BASE}-${_i}"
    TORTURE_NAMES+=("$_r1_cn" "$_r2_cn")
    submit_one 8241 "$_r1_cn" &
    submit_one 8242 "$_r2_cn" &
done
wait
# Wait until every torture CN is present in the inventory blob rather than
# guessing a sleep. Each AppendLine takes a Lua-script round-trip; with 16
# concurrent writers across replicas the tail latency can run to a couple
# of seconds on a contended runner.
poll_until 30 inventory_contains_all "${TORTURE_NAMES[@]}" || true

redis_cli --raw GETRANGE "${REDIS_PREFIX}:inventory:data" 8 -1 \
    > "$WORK_DIR/inventory-after-torture.dat" 2>/dev/null || true

_torture_missing=()
_torture_dupes=()
for _cn in "${TORTURE_NAMES[@]}"; do
    _hits=$(grep -cF "$_cn" "$WORK_DIR/inventory-after-torture.dat" || true)
    case "${_hits:-0}" in
        0) _torture_missing+=("$_cn") ;;
        1) ;;
        *) _torture_dupes+=("${_cn}=${_hits}") ;;
    esac
done
if [ "${#_torture_missing[@]}" -eq 0 ]; then
    pass "AppendLine torture: every CN appears in inventory (no lost writes)"
else
    fail "AppendLine torture: every CN appears in inventory" \
         "missing: ${_torture_missing[*]:0:6}..."
fi

# Inventory may legitimately have multiple entries for the same CN if a
# subject was issued more than once historically -- but inside one storm
# of fresh CNs, dupes would indicate the AppendLine script ran twice.
if [ "${#_torture_dupes[@]}" -eq 0 ]; then
    pass "AppendLine torture: no CN appears more than once (no double writes)"
else
    fail "AppendLine torture: no CN appears more than once" \
         "duped: ${_torture_dupes[*]:0:6}..."
fi

# -- Race E: distributed lock under contention -----------------------------
# Hammer Storage.WithLock("crl", ...) by issuing many concurrent revocations
# against an already-revoked subject. Each call should be a no-op
# (revocation is idempotent on the CRL by serial), but every call still
# acquires the "crl" distributed lock. With N=16 concurrent revoke calls
# split across replicas, every call must complete (HTTP 2xx) within the
# overall storm window without any caller getting wedged.
# Reuses the VIS_CN cert above (already revoked, single subject = single
# inventory serial).
LOCK_PARALLEL=16
_lock_results_file="$WORK_DIR/lock-results.txt"
: > "$_lock_results_file"
_t0=$(date +%s)
for _i in $(seq 1 "$LOCK_PARALLEL"); do
    _host="puppet-ca:8140"
    [ $(( _i % 2 )) -eq 0 ] && _host="puppet-ca-2:8140"
    (
        _rc=$(revoke_via_master "$VIS_CN" "$_host" 2>/dev/null)
        printf '%s\n' "$_rc" >> "$_lock_results_file"
    ) &
done
wait
_t1=$(date +%s)

_lock_2xx=$(grep -c "^2[0-9][0-9]\$" "$_lock_results_file" 2>/dev/null || echo 0)
if [ "${_lock_2xx:-0}" = "$LOCK_PARALLEL" ]; then
    pass "All ${LOCK_PARALLEL} contending revoke calls returned 2xx in $(( _t1 - _t0 ))s"
else
    fail "All ${LOCK_PARALLEL} contending revoke calls returned 2xx" \
         "2xx=${_lock_2xx} of ${LOCK_PARALLEL} (codes: $(sort -u "$_lock_results_file" | tr '\n' ' '))"
fi

# All contending callers must finish within a reasonable bound. With the
# 30-second default LockTTL and ~20 ms revocation work, 16 calls should
# clear in well under 30s; if the lock heartbeat or unlock path is broken,
# this test will time out at 30s+ and fail loudly.
if [ "$(( _t1 - _t0 ))" -le 30 ]; then
    pass "Contending lock storm cleared within 30s (took $(( _t1 - _t0 ))s)"
else
    fail "Contending lock storm cleared within 30s" \
         "took $(( _t1 - _t0 ))s -- possible heartbeat / unlock regression"
fi

# -- Race F: TTL recovery from a stuck distributed lock -------------------
# Simulates "holder process killed mid-revocation": plant a fake lock at
# <prefix>:locks:crl with someone else's token and a short TTL, then issue
# a real revocation. The contender must wait for the planted lock to
# expire (no Unlock will ever come), then succeed once the TTL elapses.
# This exercises the natural-expiry recovery path that lets a redis-backed
# CA cluster heal after a SIGKILL'd holder.
#
# TTL choice (5s) safety argument:
#   - internal/ca/revoke.go:42 wraps WithLock with
#     context.WithTimeout(ctx, lockTimeout) where lockTimeout = 60s
#     (internal/ca/init.go:49). The caller's ctx (HTTP request ctx) is
#     honored AND capped at 60s -- whichever fires first wins.
#   - cmd/puppet-ca/main.go:595 sets WriteTimeout=60s on the HTTP server.
#     curl in revoke_via_master uses no -m, so the client side does not
#     impose a tighter deadline.
#   - 5s wait + ~20ms of revoke work leaves ~55s of headroom on both
#     server-side ceilings.
# If lockTimeout shrinks below ~10s, or revoke_via_master gains a curl
# --max-time below ~10s, this test will start false-failing -- adjust
# TTL_LOCK_TTL_SEC (and the upper-bound assertion below) accordingly.
TTL_CN="redis-ttlrec-$(date +%s)"
openssl genrsa -out "$WORK_DIR/ttl.key" 2048 2>/dev/null
chmod 600 "$WORK_DIR/ttl.key"
openssl req -new -key "$WORK_DIR/ttl.key" -subj "/CN=${TTL_CN}" \
    -out "$WORK_DIR/ttl.csr" 2>/dev/null
curl -sf --cacert "$WORK_DIR/ca.pem" \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/ttl.csr" \
    "https://localhost:8241/puppet-ca/v1/certificate_request/${TTL_CN}" \
    > /dev/null 2>&1 || true
poll_until 10 redis_exists "${REDIS_PREFIX}:signed:${TTL_CN}" || true

TTL_LOCK_KEY="${REDIS_PREFIX}:locks:crl"
TTL_LOCK_TTL_SEC=5
TTL_FAKE_TOKEN="fake-dead-holder-$(date +%s%N)"
# Plant a fake lock. NX ensures we don't stomp on a legitimate holder; if
# it fails to take, we abort the timing assertions because the test
# wouldn't be meaningful (someone else holds the lock and our "stuck"
# scenario is contaminated).
redis_cli SET "$TTL_LOCK_KEY" "$TTL_FAKE_TOKEN" PX "$(( TTL_LOCK_TTL_SEC * 1000 ))" NX \
    > /dev/null 2>&1 || true
_planted=$(redis_cli GET "$TTL_LOCK_KEY" 2>/dev/null \
    | tr -d '\r' | tr -d '[:space:]')

if [ "$_planted" = "$TTL_FAKE_TOKEN" ]; then
    pass "Planted stuck lock with ${TTL_LOCK_TTL_SEC}s TTL"

    # Issue revocation; must wait for our planted lock to expire, then succeed.
    _t0=$(date +%s)
    _ttl_rev_rc=$(revoke_via_master "$TTL_CN" "puppet-ca:8140" 2>/dev/null)
    _t1=$(date +%s)
    _elapsed=$(( _t1 - _t0 ))

    if [[ "$_ttl_rev_rc" =~ ^2 ]]; then
        pass "Revocation succeeded after planted lock TTL expiry (HTTP ${_ttl_rev_rc}, ${_elapsed}s)"
    else
        fail "Revocation succeeded after planted lock TTL expiry" \
             "got HTTP ${_ttl_rev_rc} after ${_elapsed}s"
    fi

    # Lower bound: revocation must have actually waited. Acquiring before
    # ~TTL-1s would mean either the SetNX semantic is broken or our
    # planted lock vanished early.
    if [ "$_elapsed" -ge "$(( TTL_LOCK_TTL_SEC - 1 ))" ]; then
        pass "Revocation waited >=$(( TTL_LOCK_TTL_SEC - 1 ))s for stuck lock to expire (took ${_elapsed}s)"
    else
        fail "Revocation waited >=$(( TTL_LOCK_TTL_SEC - 1 ))s for stuck lock to expire" \
             "took only ${_elapsed}s -- NX semantic broken or planted lock not seen"
    fi

    # Upper bound: revocation must clear shortly after the TTL. A wider
    # gap suggests the AcquireLock backoff / heartbeat / TTL handling is
    # off; pegs the practical recovery latency for operators.
    if [ "$_elapsed" -le "$(( TTL_LOCK_TTL_SEC + 10 ))" ]; then
        pass "Revocation cleared within ${TTL_LOCK_TTL_SEC}+10s of planted-lock plant (took ${_elapsed}s)"
    else
        fail "Revocation cleared within ${TTL_LOCK_TTL_SEC}+10s of planted-lock plant" \
             "took ${_elapsed}s -- possible stuck retry/backoff path"
    fi

    # And the cert is actually revoked now -- no point in unblocking the
    # lock if the body of the critical section silently failed.
    _ttl_after_count=$(count_crl_entries_via "puppet-ca:8140")
    if [ "${_ttl_after_count:-0}" -gt "${_crl_after_r1:-0}" ]; then
        pass "TTL-recovered revocation reflected in CRL (count: ${_crl_after_r1} -> ${_ttl_after_count})"
    else
        fail "TTL-recovered revocation reflected in CRL" \
             "before=${_crl_after_r1:-?} after=${_ttl_after_count:-?}"
    fi
else
    fail "Planted stuck lock with ${TTL_LOCK_TTL_SEC}s TTL" \
         "GET returned: '${_planted}' -- another caller held the lock at plant time"
fi

# ═════════════════════════════════════════════════════════════════════════
# Results
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Phase 2 results: %d/%d passed, %d failed\n' \
    $(( T - FAILURES )) "$T" "$FAILURES"

if [ "$FAILURES" -ne 0 ] || [ "$PHASE1_RC" -ne 0 ]; then
    printf '# Overall: FAIL  (phase1_rc=%d phase2_failures=%d)\n' \
        "$PHASE1_RC" "$FAILURES"
    exit 1
fi
printf '# Overall: PASS\n'
exit 0
