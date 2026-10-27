#!/bin/bash
# Integration tests for the openvox-ca Puppet stack.
#
# Validates the full OpenVox 8 stack: Go CA (TLS) → OpenVox Server →
# OpenVoxDB, testing catalog application, PuppetDB reporting, and exported
# resources.
#
# Usage:
#   ./test/puppet/puppet-stack.sh              # run against running stack
#   ./test/puppet/puppet-stack.sh --up         # start stack, run, tear down
#   ./test/puppet/puppet-stack.sh --up --keep  # start stack, run, keep running
#
# Output: TAP format.  Exit 0 on all pass, exit 1 on any failure.
#
# On failure, an --up run replays every stack service's container log to
# stderr (all but puppet-client, whose log is empty by construction) before
# tearing the stack down, since teardown is what makes those logs
# unrecoverable. Each service is replayed from its *first* start attempt --
# under run-puppet-stack-on-redis.sh this same script drives CA replicas that
# restart on failure, so a tail alone would only ever show the last futile
# attempts (#281) -- with a tail beneath it for a service that failed late
# without restarting. --up --keep skips that teardown dump and leaves the
# containers up for `compose logs` instead; a readiness timeout still prints
# the timed-out service's own log either way.
#
# NOTE: Group 6 revokes the client cert.  clean_client_cert() cleans any
# stale cert and clears the client SSL dir before Groups 3 and 8.

set -uo pipefail

# Failure-log dump helpers, shared with test/backends/redis-stack.sh.
#
# Sourced by a path relative to the working directory rather than to
# ${BASH_SOURCE[0]}: test/backends/run-puppet-stack-on-redis.sh execs a
# sed-rewritten *copy* of this script from a temp directory, where a
# source-relative path would not resolve. Both callers already require the
# project root as the working directory -- every `compose -f` path below is
# relative to it.
# shellcheck source=test/failure-log.sh
. test/failure-log.sh

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

# Resolve the compose command independently of the engine: prefer
# podman-compose when running under podman and it is installed, then fall
# back to docker compose / docker-compose (matches composeCmd() in magefile.go
# and works on GitHub runners where podman is present but podman-compose is not).
if [[ "$_ENGINE" == podman ]] && command -v podman-compose &>/dev/null; then
    _COMPOSE=(podman-compose -f test/compose-puppet.yml)
elif docker compose version &>/dev/null 2>&1; then
    _COMPOSE=(docker compose -f test/compose-puppet.yml)
elif command -v docker-compose &>/dev/null; then
    _COMPOSE=(docker-compose -f test/compose-puppet.yml)
else
    printf 'Error: no compose tool found; install podman-compose or docker compose\n' >&2
    exit 1
fi

# -- Configuration --------------------------------------------------------─
# Host-side URLs (CA on 8141, master on 8140, as mapped in test/compose-puppet.yml).
CA_HOST_URL="https://localhost:8141"
# The Prometheus exporter, plain HTTP on its own listener (see compose-puppet.yml).
CA_METRICS_URL="http://localhost:9141/metrics"
MASTER_URL="https://puppet-master:8140"   # used from inside master container

WORK_DIR=$(mktemp -d /tmp/puppet-stack-integ.XXXXXX)
RUN_ID=$(date +%s)

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

# -- Container exec wrappers ----------------------------------------------─
# Use compose exec so container name resolution works regardless of whether
# the tool uses underscore (podman-compose/v1) or dash (docker compose v2)
# naming conventions.  -T disables TTY allocation so these work in CI.
exec_ca()       { "${_COMPOSE[@]}" exec -T openvox-ca     "$@"; }
exec_master()   { "${_COMPOSE[@]}" exec -T puppet-master "$@"; }
exec_master_i() { "${_COMPOSE[@]}" exec -T puppet-master "$@"; }
exec_client()   { "${_COMPOSE[@]}" exec -T puppet-client "$@"; }

copy_from_client() {   # src-path dest-path
    exec_client cat "$1" > "$2" 2>/dev/null
}

# -- Helper: query OpenVoxDB via master's mTLS cert ------------------------
pdb_query() {
    local path="$1"
    exec_master curl -sf \
        --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
        --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
        --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
        "https://openvoxdb:8081${path}" 2>/dev/null
}

# -- Helper: CA admin operation via master's mTLS cert --------------------
# The CA's --puppet-server-file allows the master cert as admin.
ca_admin_put() {   # subject json-body
    local subject="$1" body="$2"
    exec_master curl -sf -o /dev/null -w '%{http_code}' \
        --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
        --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
        --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
        -X PUT -H "Content-Type: application/json" \
        -d "$body" \
        "https://openvox-ca:8140/puppet-ca/v1/certificate_status/${subject}" \
        2>/dev/null || true
}

# -- Helper: refresh master's CRL from Go CA ------------------------------─
refresh_master_crl() {
    local _crl
    _crl=$(exec_master curl -sf \
        --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
        "https://openvox-ca:8140/puppet-ca/v1/certificate_revocation_list/ca" \
        2>/dev/null) || return 1
    printf '%s\n' "$_crl" | exec_master_i \
        sh -c 'cat > /etc/puppetlabs/puppet/ssl/ca/ca_crl.pem'
}

# -- Helper: clean the client cert, wipe local SSL dir --------------------─
clean_client_cert() {
    local _state
    _state=$(exec_master curl -s \
        --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
        --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
        --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
        "https://openvox-ca:8140/puppet-ca/v1/certificate_status/client.puppet.localdomain" \
        2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('state',''))" \
        2>/dev/null || true)
    # Clean rather than merely revoke: a subject holding a CSR or a certificate,
    # revoked or not, refuses the agent's next CSR until it is cleaned, as
    # OpenVox Server does with allow_duplicate_certs off.
    if [ -n "$_state" ]; then
        printf '#   cleaning stale client.puppet.localdomain (state=%s)\n' "$_state"
        local _clean_st
        _clean_st=$(exec_master curl -s -o /dev/null -w '%{http_code}' \
            --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
            --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
            --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
            -X DELETE \
            "https://openvox-ca:8140/puppet-ca/v1/certificate_status/client.puppet.localdomain" \
            2>/dev/null || true)
        # The agent run that follows depends on this: a subject left holding
        # anything refuses the agent's CSR, which would surface only as a
        # --waitforcert timeout.
        [ "$_clean_st" = "204" ] \
            || printf '#   WARNING: cleaning client.puppet.localdomain returned HTTP %s, not 204; the agent run below will be refused\n' "${_clean_st:-none}"
    fi
    exec_client rm -rf /etc/puppetlabs/puppet/ssl 2>/dev/null || true
    refresh_master_crl || true
}

# -- Helper: run puppet agent on client container --------------------------
# Explicit --confdir / --vardir / --logdir / --rundir override the non-root
# defaults (~/.puppetlabs/...) so puppet uses the pre-created directories
# that are writable by the puppet-agent user (see Dockerfile.client).
_PUPPET_DIRS=(
    --confdir   /etc/puppetlabs/puppet
    --vardir    /opt/puppetlabs/puppet/cache
    --logdir    /var/log/puppetlabs/puppet
    --rundir    /var/run/puppetlabs
    --publicdir /opt/puppetlabs/puppet/public
)
run_agent() {
    exec_client \
        puppet agent --test \
        "${_PUPPET_DIRS[@]}" \
        --server    puppet-master \
        --ca_server openvox-ca \
        --ca_port   8140 \
        "$@" 2>&1
}

# -- Helper: run puppet agent on master container (self-apply) ------------
# Explicit --confdir is required because puppetserver sets HOME to
# /opt/puppetlabs/server/data/puppetserver, causing puppet agent to derive
# confdir as $HOME/.puppetlabs/etc/puppet instead of /etc/puppetlabs/puppet.
run_master_agent() {
    exec_master \
        puppet agent --test \
        --confdir   /etc/puppetlabs/puppet \
        --server    puppet-master \
        --ca_server openvox-ca \
        --ca_port   8140 \
        --certname  puppet-master \
        "$@" 2>&1
}

# -- Helper: replay a service's container logs to our stderr ---------------
# Shared by the readiness aborts and cleanup()'s failure dump, both of which
# need the container's own account of what went wrong.
#
# This used to be a deliberate copy of the helper in
# test/backends/redis-stack.sh, on the grounds that it was coupled to each
# harness's `_COMPOSE` array so sharing it would mean sharing that too. Issue
# #281 was the cost of that: the same tail-only bug had to be fixed in both
# copies, and one fix would have left the other. The shared version in
# test/failure-log.sh takes the compose command as an argument, so the
# coupling that was the reason is gone.
#
# It matters here and not only in the backends harness because
# test/backends/run-puppet-stack-on-redis.sh runs a sed-rewritten copy of this
# script against test/compose-backends-redis.yml, whose two CA replicas carry
# `restart: on-failure` -- so the service this dumps really can be a stack of
# concatenated start attempts, even though the puppet stack's own compose file
# declares no restart policy. (Do not name that file here: the wrapper
# sed-rewrites every mention of it, and a comment rewritten mid-sentence would
# then assert the opposite of what it says.)
#
# To stderr, so it cannot corrupt the TAP stream a consumer is parsing.
dump_logs() {  # service-name
    failure_log_dump "$1" "${_COMPOSE[@]}" >&2
}

# -- Every container worth hearing from when the run fails -----------------
# postgres is included because OpenVoxDB will not start until it is healthy,
# so a postgres fault shows up as an empty OpenVoxDB log. puppet-client is
# deliberately absent: its entrypoint is `tail -f /dev/null` and the agent runs
# through exec_client, so its container log holds nothing to dump -- the
# agent's own output is captured by the caller instead.
FAILURE_LOG_SERVICES=(openvox-ca puppet-master openvoxdb postgres)

dump_failure_logs() {  # [service-already-dumped]
    local _skip="${1:-}" _svc
    for _svc in "${FAILURE_LOG_SERVICES[@]}"; do
        [ "$_svc" = "$_skip" ] && continue
        dump_logs "$_svc"
    done
}

# -- Stack lifecycle ------------------------------------------------------─
# Defined after the dump helpers above, so nothing the EXIT trap calls is
# still undefined at the moment the trap is installed.

cleanup() {
    # First statement: $? here is the status the script is exiting with.
    local _rc=$?
    rm -rf "$WORK_DIR"
    exec_client rm -rf /etc/puppetlabs/puppet/ssl 2>/dev/null || true

    # Any non-zero exit means something went wrong and the containers are about
    # to be destroyed, taking their account of it with them: a failed assertion
    # (which used to print its `not ok` line and nothing else), a readiness
    # abort, the pre-flight CA fetch, or a shell error. Dumping from the trap
    # rather than from each failure site is what makes that true of *every*
    # exit path, including ones added later. Ordered before the teardown below
    # so the containers still exist. On a --keep run (which is how
    # run-puppet-stack-on-redis.sh drives this script) nothing is destroyed
    # here, so the logs stay available to `compose logs` and to that caller's
    # own failure dump.
    if [ "$_rc" -ne 0 ] && $DO_UP && ! $DO_KEEP; then
        printf '\n# Run failed (exit %d) -- dumping container logs before teardown\n' "$_rc" >&2
        dump_failure_logs "${_ABORTED_SERVICE:-}"
    fi

    if $DO_UP && ! $DO_KEEP; then
        printf '\n# Tearing down compose stack...\n'
        "${_COMPOSE[@]}" down --volumes --timeout 10 2>/dev/null || true
    fi
}
trap cleanup EXIT

# -- Helper: abort a readiness wait loudly, dumping the culprit's logs ------
# Without this the wait loops below printed " OK" whether or not the endpoint
# ever answered, so a service that never came up surfaced only as a confusing
# cascade of downstream test failures. Aborting here instead yields one clear
# message plus the container logs that explain why.
abort_not_ready() {  # human-description  service-name
    printf ' TIMEOUT\n'
    printf 'FATAL: %s did not become ready in time\n' "$1" >&2
    dump_logs "$2"
    _ABORTED_SERVICE="$2"  # so cleanup() does not replay these lines again
    exit 1
}

if $DO_UP; then
    printf '# Removing any leftover containers from previous runs...\n'
    "${_COMPOSE[@]}" down --volumes --remove-orphans --timeout 10 2>/dev/null || true

    printf '# Building compose images...\n'
    "${_COMPOSE[@]}" build

    printf '# Starting compose stack...\n'
    "${_COMPOSE[@]}" up -d

    printf '# Waiting for Go CA (port 8141)'
    _ca_ready=false
    for _i in $(seq 1 60); do
        if curl -sfk "${CA_HOST_URL}/puppet-ca/v1/certificate/ca" > /dev/null 2>&1; then
            _ca_ready=true; break
        fi
        printf '.'; sleep 3
    done
    if $_ca_ready; then printf ' OK\n'; else
        abort_not_ready "Go CA (openvox-ca)" openvox-ca
    fi

    # OpenVox Server (JVM + JRuby) can take 5-7 minutes on first start.
    # Allow up to 450 s (matches healthcheck start_period + retries budget).
    printf '# Waiting for puppet master (port 8140)'
    _master_ready=false
    for _i in $(seq 1 90); do
        if curl -sfk "https://localhost:8140/status/v1/simple" 2>/dev/null \
            | grep -q running; then
            _master_ready=true; break
        fi
        printf '.'; sleep 5
    done
    if $_master_ready; then printf ' OK\n'; else
        abort_not_ready "puppet master" puppet-master
    fi

    # OpenVoxDB must wait for puppet-master to fully start first.  Allow 600 s.
    printf '# Waiting for OpenVoxDB'
    _pdb_ready=false
    for _i in $(seq 1 120); do
        _health=$(pdb_query /status/v1/simple 2>/dev/null) || true
        if [[ "$_health" == "running" ]]; then
            _pdb_ready=true; break
        fi
        printf '.'; sleep 5
    done
    if $_pdb_ready; then printf ' OK\n'; else
        abort_not_ready "OpenVoxDB" openvoxdb
    fi
fi

# -- TAP helpers ----------------------------------------------------------
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

assert_http() {
    local exp="$1" desc="$2"; shift 2
    local got
    got=$(curl -s -o /dev/null -w '%{http_code}' "$@" 2>/dev/null) || true
    [ "$got" = "$exp" ] \
        && pass "$desc" \
        || fail "$desc" "expected HTTP $exp, got HTTP $got"
}

assert_contains() {
    local pat="$1" desc="$2"; shift 2
    local body
    body=$(curl -s "$@" 2>/dev/null) || true
    grep -qF "$pat" <<< "$body" \
        && pass "$desc" \
        || fail "$desc" "pattern not found: $pat"
}

# -- Pre-flight: download CA cert ------------------------------------------
printf '\n# Downloading CA cert from %s...\n' "$CA_HOST_URL"
if ! curl -sfk "${CA_HOST_URL}/puppet-ca/v1/certificate/ca" \
          -o "$WORK_DIR/ca.pem" 2>/dev/null; then
    printf 'FATAL: CA not reachable at %s\n' "$CA_HOST_URL" >&2
    exit 1
fi
printf '# CA cert downloaded to %s/ca.pem\n\n' "$WORK_DIR"

# ═════════════════════════════════════════════════════════════════════════
# Group 1 -- Go CA HTTPS (port 8141 on host)
# Tests that the CA serves valid TLS and all public endpoints respond.
# ═════════════════════════════════════════════════════════════════════════
printf '# Group 1 -- Go CA HTTPS (port 8141 from host)\n'

# After the initial insecure fetch above, all CA requests use --cacert.
_CA=(--cacert "$WORK_DIR/ca.pem")

assert_http 200 "CA cert endpoint returns 200" \
    "${_CA[@]}" "${CA_HOST_URL}/puppet-ca/v1/certificate/ca"

assert_contains "BEGIN CERTIFICATE" "CA cert contains PEM header" \
    "${_CA[@]}" "${CA_HOST_URL}/puppet-ca/v1/certificate/ca"

assert_http 200 "CRL endpoint returns 200" \
    "${_CA[@]}" "${CA_HOST_URL}/puppet-ca/v1/certificate_revocation_list/ca"

assert_contains "BEGIN X509 CRL" "CRL contains PEM header" \
    "${_CA[@]}" "${CA_HOST_URL}/puppet-ca/v1/certificate_revocation_list/ca"

# CRL is publicly accessible even without a client cert.
assert_http 200 "CRL endpoint public (no client cert)" \
    --cacert "$WORK_DIR/ca.pem" \
    "${CA_HOST_URL}/puppet-ca/v1/certificate_revocation_list/ca"

assert_http 200 "Expirations endpoint returns 200" \
    "${_CA[@]}" "${CA_HOST_URL}/puppet-ca/v1/expirations"

# Generate a test cert via the CSR lifecycle (autosign=true → signs immediately).
# This is an *ordinary agent* credential. Since certificate_status became
# admin-only it is kept to prove that tier refuses it, not to reach it.
_INTEG_HOST="integ-${RUN_ID}.localdomain"
openssl genrsa -out "$WORK_DIR/integ.key" 2048 2>/dev/null || true
[ -f "$WORK_DIR/integ.key" ] && chmod 600 "$WORK_DIR/integ.key"
openssl req -new \
    -key  "$WORK_DIR/integ.key" \
    -subj "/CN=${_INTEG_HOST}" \
    -out  "$WORK_DIR/integ.csr" 2>/dev/null || true

_csr_st=$(curl -s -o /dev/null -w '%{http_code}' \
    "${_CA[@]}" \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/integ.csr" \
    "${CA_HOST_URL}/puppet-ca/v1/certificate_request/${_INTEG_HOST}") || true
[[ "$_csr_st" =~ ^2 ]] \
    && pass "CSR submission returns 2xx" \
    || fail "CSR submission returns 2xx" "got HTTP $_csr_st"

sleep 1  # autosign is immediate but allow a moment

if curl -sf "${_CA[@]}" \
        "${CA_HOST_URL}/puppet-ca/v1/certificate/${_INTEG_HOST}" \
        -o "$WORK_DIR/integ.crt" 2>/dev/null; then
    pass "Signed cert downloadable"
else
    fail "Signed cert downloadable"
fi

if openssl verify -CAfile "$WORK_DIR/ca.pem" \
                  "$WORK_DIR/integ.crt" >/dev/null 2>&1; then
    pass "Signed cert verifies against CA"
else
    fail "Signed cert verifies against CA"
fi

# mTLS credentials for an ordinary agent: a CA-signed client cert carrying
# neither an allow-listed CN nor pp_cli_auth.
_INTEG_MTLS=(
    --cacert "$WORK_DIR/ca.pem"
    --cert   "$WORK_DIR/integ.crt"
    --key    "$WORK_DIR/integ.key"
)

# certificate_status is admin-only, matching Puppet Server's shipped auth.conf,
# which grants certificate_status to pp_cli_auth only. Three cases: no client
# certificate, an ordinary agent certificate, and an admin one. Only the last
# gets through.
#
# The agent-certificate case is the end-to-end regression test for that change.
# It used to return the status body; an ordinary agent certificate reaching this
# route again means the tier has silently widened.
assert_http 403 "certificate_status without client cert returns 403" \
    "${_CA[@]}" "${CA_HOST_URL}/puppet-ca/v1/certificate_status/${_INTEG_HOST}"

assert_http 403 "certificate_status with an ordinary agent cert returns 403 (admin-only)" \
    "${_INTEG_MTLS[@]}" "${CA_HOST_URL}/puppet-ca/v1/certificate_status/${_INTEG_HOST}"

# The admin path: puppet-master is the CN in the CA's allow list (written by
# docker/puppet/ca-entrypoint.sh), so its certificate is what reads statuses now.
_status_body=$(exec_master curl -s \
    --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
    --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
    --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
    "https://openvox-ca:8140/puppet-ca/v1/certificate_status/${_INTEG_HOST}" \
    2>/dev/null) || true
grep -qF '"state":"signed"' <<< "$_status_body" \
    && pass "Autosigned cert status is 'signed' (admin mTLS)" \
    || fail "Autosigned cert status is 'signed' (admin mTLS)" "body: $_status_body"

_missing_st=$(exec_master curl -s -o /dev/null -w '%{http_code}' \
    --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
    --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
    --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
    "https://openvox-ca:8140/puppet-ca/v1/certificate_status/nonexistent" \
    2>/dev/null) || true
[ "$_missing_st" = "404" ] \
    && pass "Nonexistent cert status returns 404 (admin mTLS)" \
    || fail "Nonexistent cert status returns 404 (admin mTLS)" "got: $_missing_st"

# Revoke the integ cert (admin, requires master cert; run from master container).
_revoke_st=$(exec_master curl -s -o /dev/null -w '%{http_code}' \
    --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
    --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
    --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
    -X PUT -H "Content-Type: application/json" \
    -d '{"desired_state":"revoked"}' \
    "https://openvox-ca:8140/puppet-ca/v1/certificate_status/${_INTEG_HOST}" \
    2>/dev/null) || true
[[ "$_revoke_st" =~ ^2 ]] \
    && pass "Cert revocation returns 2xx" \
    || fail "Cert revocation returns 2xx" "got HTTP $_revoke_st"

# ═════════════════════════════════════════════════════════════════════════
# Group 1b -- puppet-server-file admin auth
# Verifies that the file-based CN allow list grants the puppet-master cert
# CA admin access, and that a cert whose CN is absent from the file is denied.
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Group 1b -- puppet-server-file admin auth\n'

_srv_file=$(exec_ca cat /etc/openvox-ca/servers.txt 2>/dev/null) || true

[ -n "$_srv_file" ] \
    && pass "puppet-server-file exists on CA container" \
    || fail "puppet-server-file exists on CA container" "file empty or missing"

grep -qF "puppet-master" <<< "$_srv_file" \
    && pass "puppet-server-file contains puppet-master CN" \
    || fail "puppet-server-file contains puppet-master CN" "file content: $_srv_file"

# An admin operation (list all cert statuses) must succeed using the master
# cert, which is authorised solely via puppet-server-file.
_srv_file_admin_st=$(exec_master curl -s -o /dev/null -w '%{http_code}' \
    --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
    --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
    --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
    "https://openvox-ca:8140/puppet-ca/v1/certificate_statuses/any" \
    2>/dev/null) || true
[[ "$_srv_file_admin_st" =~ ^2 ]] \
    && pass "Admin endpoint accessible via puppet-server-file CN" \
    || fail "Admin endpoint accessible via puppet-server-file CN" "got HTTP $_srv_file_admin_st"

# A cert whose CN is NOT in the file must be rejected for admin operations.
# Use the CA's /generate endpoint (requires master admin cert) to obtain a
# fresh key+cert pair, then probe an admin endpoint with it and expect 403.
_probe_cn="probe-noadmin-${RUN_ID}"
_probe_gen_ok=0
exec_master bash -c "
    set -e
    _json=\$(curl -sf \
        --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
        --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
        --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
        -X POST \
        'https://openvox-ca:8140/puppet-ca/v1/generate/${_probe_cn}')
    printf '%s' \"\$_json\" | python3 -c '
import sys, json
d = json.load(sys.stdin)
open(\"/tmp/probe.key\", \"w\").write(d[\"private_key\"])
open(\"/tmp/probe.crt\", \"w\").write(d[\"certificate\"])
'
    chmod 600 /tmp/probe.key
" 2>/dev/null || _probe_gen_ok=$?

if [ "$_probe_gen_ok" -eq 0 ]; then
    _probe_st=$(exec_master curl -s -o /dev/null -w '%{http_code}' \
        --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
        --cert   /tmp/probe.crt \
        --key    /tmp/probe.key \
        "https://openvox-ca:8140/puppet-ca/v1/certificate_statuses/any" \
        2>/dev/null) || true
    [ "$_probe_st" = "403" ] \
        && pass "Non-listed CN rejected for admin endpoint (403)" \
        || fail "Non-listed CN rejected for admin endpoint (403)" "got HTTP $_probe_st"

    # Revoke and clean up the probe cert.
    exec_master curl -sf -o /dev/null \
        --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
        --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
        --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
        -X PUT -H "Content-Type: application/json" \
        -d '{"desired_state":"revoked"}' \
        "https://openvox-ca:8140/puppet-ca/v1/certificate_status/${_probe_cn}" \
        2>/dev/null || true
    exec_master rm -f /tmp/probe.key /tmp/probe.crt 2>/dev/null || true
else
    fail "Non-listed CN rejected for admin endpoint (403)" \
         "could not generate probe cert for ${_probe_cn}"
fi

# ═════════════════════════════════════════════════════════════════════════
# Group 2 -- Puppet master reachability (port 8140 from host)
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Group 2 -- Puppet master reachability\n'

# Use the master's real hostname so TLS hostname verification passes.
# --resolve routes puppet-master:8140 to 127.0.0.1 (host port mapping).
_MASTER_HOST=(--cacert "$WORK_DIR/ca.pem" --resolve "puppet-master:8140:127.0.0.1")

assert_http 200 "Master status endpoint returns 200 (unauthenticated)" \
    "${_MASTER_HOST[@]}" \
    "https://puppet-master:8140/status/v1/simple"

assert_contains "running" "Master status body contains 'running'" \
    "${_MASTER_HOST[@]}" \
    "https://puppet-master:8140/status/v1/simple"

# Catalog endpoint should require an authenticated client cert.
assert_http 403 "Master catalog endpoint requires auth (returns 403 without cert)" \
    "${_MASTER_HOST[@]}" \
    "https://puppet-master:8140/puppet/v3/catalog/test?environment=production"

# ═════════════════════════════════════════════════════════════════════════
# Group 3 -- Full puppet agent end-to-end
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Group 3 -- Full puppet agent end-to-end\n'

clean_client_cert

AGENT_EXIT=0
AGENT_OUT=$(run_agent --waitforcert 30) || AGENT_EXIT=$?

[[ "$AGENT_EXIT" =~ ^(0|2)$ ]] \
    && pass "Puppet agent exits 0 or 2" \
    || fail "Puppet agent exits 0 or 2" "exit code: $AGENT_EXIT"

grep -qi "Applied catalog" <<< "$AGENT_OUT" \
    && pass "Agent output contains 'Applied catalog'" \
    || fail "Agent output contains 'Applied catalog'" "last 5 lines: $(tail -5 <<< "$AGENT_OUT" | tr '\n' '|')"

if grep -qiE "SSL_read|certificate revoked|SSL error" <<< "$AGENT_OUT"; then
    fail "Agent output contains no SSL/error messages" \
         "found error in: $(grep -iE 'SSL_read|certificate revoked|SSL error' <<< "$AGENT_OUT" | head -3 | tr '\n' '|')"
else
    pass "Agent output contains no SSL/error messages"
fi

grep -qF "Smoke test passed" <<< "$AGENT_OUT" \
    && pass "Agent output contains smoke test notify" \
    || fail "Agent output contains smoke test notify" "not found in output"

_client_managed=$(exec_client cat /tmp/puppet_managed 2>/dev/null) || true
[ -n "$_client_managed" ] \
    && pass "/tmp/puppet_managed exists on client" \
    || fail "/tmp/puppet_managed exists on client" "file not found or empty"

grep -qF "client.puppet.localdomain" <<< "$_client_managed" \
    && pass "/tmp/puppet_managed contains client certname" \
    || fail "/tmp/puppet_managed contains client certname"

# ═════════════════════════════════════════════════════════════════════════
# Group 3b -- Certificate auto-renewal (real agent, no CSR)
#
# Real Puppet/OpenVox agents auto-renew their client cert by default
# (hostcert_renewal_interval, default 30d): they POST an empty body to
# /certificate_renewal, relying solely on the mTLS-presented cert to prove
# identity and key possession, and expect the SAME key reissued with a fresh
# serial and validity. `puppet ssl renew_cert` drives exactly that code path
# deterministically (see lib/puppet/application/ssl.rb in the openvox repo),
# so this exercises the real agent binary against openvox-ca's AutoRenew
# (internal/ca/signing.go), not just a Go-mocked TLS certificate.
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Group 3b -- Certificate auto-renewal (real agent, no CSR)\n'

_client_cert_path=/etc/puppetlabs/puppet/ssl/certs/client.puppet.localdomain.pem

_serial_before=$(exec_client openssl x509 -in "$_client_cert_path" -noout -serial 2>/dev/null) || true
_pubkey_before=$(exec_client openssl x509 -in "$_client_cert_path" -noout -pubkey 2>/dev/null) || true

RENEW_EXIT=0
RENEW_OUT=$(exec_client \
    puppet ssl renew_cert \
    "${_PUPPET_DIRS[@]}" \
    --ca_server openvox-ca \
    --ca_port   8140 \
    --certname  client.puppet.localdomain \
    2>&1) || RENEW_EXIT=$?

[ "$RENEW_EXIT" -eq 0 ] \
    && pass "puppet ssl renew_cert exits 0" \
    || fail "puppet ssl renew_cert exits 0" "exit code: $RENEW_EXIT; output: $(tail -5 <<< "$RENEW_OUT" | tr '\n' '|')"

grep -qi "Downloaded certificate" <<< "$RENEW_OUT" \
    && pass "renew_cert output confirms a new certificate was downloaded" \
    || fail "renew_cert output confirms a new certificate was downloaded" "output: $(tail -5 <<< "$RENEW_OUT" | tr '\n' '|')"

_serial_after=$(exec_client openssl x509 -in "$_client_cert_path" -noout -serial 2>/dev/null) || true
_pubkey_after=$(exec_client openssl x509 -in "$_client_cert_path" -noout -pubkey 2>/dev/null) || true

[[ -n "$_serial_after" && "$_serial_after" != "$_serial_before" ]] \
    && pass "renewed cert carries a new serial" \
    || fail "renewed cert carries a new serial" "before=$_serial_before after=$_serial_after"

[[ -n "$_pubkey_after" && "$_pubkey_after" == "$_pubkey_before" ]] \
    && pass "renewed cert keeps the same public key (no CSR, no re-key)" \
    || fail "renewed cert keeps the same public key (no CSR, no re-key)" \
        "$([[ -z "$_pubkey_after" ]] && echo "post-renewal public key could not be extracted" || echo "public key changed across renewal")"

# Delayed supersession: superseded_cert_revoke_after_sec defaults to 24h, so the
# pre-renewal serial is deliberately NOT on the CRL yet. It is recorded instead,
# and a sweep revokes it once the window elapses. Both halves are asserted --
# absence from the CRL alone would also hold if the supersession had been
# silently dropped, which is the failure this feature must never have.
#
# Before this default existed the renewal revoked its predecessor inline and
# this block asserted the opposite. Set superseded_cert_revoke_after_sec: 0 to
# get that behaviour back.
_old_serial_hex=${_serial_before#serial=}
_crl_after_renew=$(curl -sfk "${_CA[@]}" \
    "${CA_HOST_URL}/puppet-ca/v1/certificate_revocation_list/ca" 2>/dev/null \
    | openssl crl -text -noout 2>/dev/null) || true
# Guard on a non-empty serial first: _serial_before is captured with `|| true`,
# so if the pre-renewal serial could not be extracted, _old_serial_hex is empty
# and `grep -qF ""` would match any CRL unconditionally. Here that would make the
# *absence* assertion fail rather than pass, but the guard is kept explicit so
# the two assertions below cannot be read as depending on which way it errs.
if [[ -z "$_old_serial_hex" ]]; then
    fail "pre-renewal serial stays valid inside its overlap window" "pre-renewal serial could not be extracted"
elif grep -qF "$_old_serial_hex" <<< "$_crl_after_renew"; then
    fail "pre-renewal serial stays valid inside its overlap window" \
        "serial '$_old_serial_hex' is already on the CRL; the 24h window should still be open"
else
    pass "pre-renewal serial stays valid inside its overlap window"
fi

# ...and it must be on the pending list, not merely un-revoked. The gauge is the
# backend-agnostic way to see that: this script also runs against the Redis and
# Redis stack (test/backends/redis-stack.sh runs this same script), where there
# is no superseded.json to read.
_pending=$(curl -sf "$CA_METRICS_URL" 2>/dev/null \
    | awk '$1 == "openvoxca_supersede_pending" { print $2 }') || true
[[ -n "$_pending" ]] \
    && pass "exporter publishes openvoxca_supersede_pending" \
    || fail "exporter publishes openvoxca_supersede_pending" "gauge absent from ${CA_METRICS_URL}"
# awk prints the Prometheus float verbatim ("1" or "1.0"); compare numerically
# so either form counts, and refuse an empty value rather than letting the
# arithmetic treat it as zero.
[[ -n "$_pending" ]] && awk -v v="$_pending" 'BEGIN { exit !(v >= 1) }' \
    && pass "the superseded certificate is recorded for delayed revocation" \
    || fail "the superseded certificate is recorded for delayed revocation" \
        "openvoxca_supersede_pending is '${_pending:-<absent>}'; the renewal left nothing on the pending list"

# The renewed cert must still work for a normal agent run (still trusted,
# same private key on disk as before the renewal). Match Group 3's depth:
# check the catalog actually applied and no revoked-cert/TLS error surfaced,
# not just the exit code — a revoked or untrusted cert would exit 1, but the
# output is the direct evidence the renewed cert is still accepted.
AGENT_RENEW_EXIT=0
AGENT_RENEW_OUT=$(run_agent) || AGENT_RENEW_EXIT=$?
[[ "$AGENT_RENEW_EXIT" =~ ^(0|2)$ ]] \
    && pass "Agent run with auto-renewed cert exits 0 or 2" \
    || fail "Agent run with auto-renewed cert exits 0 or 2" "exit code: $AGENT_RENEW_EXIT; output: $(tail -5 <<< "$AGENT_RENEW_OUT" | tr '\n' '|')"

grep -qi "Applied catalog" <<< "$AGENT_RENEW_OUT" \
    && pass "auto-renewed agent run applied the catalog" \
    || fail "auto-renewed agent run applied the catalog" "last 5 lines: $(tail -5 <<< "$AGENT_RENEW_OUT" | tr '\n' '|')"

if grep -qiE "certificate revoked|certificate verify failed|SSL_connect" <<< "$AGENT_RENEW_OUT"; then
    fail "auto-renewed agent run shows no revoked-cert/TLS error" "output: $(tail -5 <<< "$AGENT_RENEW_OUT" | tr '\n' '|')"
else
    pass "auto-renewed agent run shows no revoked-cert/TLS error"
fi

# ═════════════════════════════════════════════════════════════════════════
# Group 4 -- Server self-apply
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Group 4 -- Server self-apply\n'

MASTER_AGENT_EXIT=0
MASTER_AGENT_OUT=$(run_master_agent) || MASTER_AGENT_EXIT=$?

[[ "$MASTER_AGENT_EXIT" =~ ^(0|2)$ ]] \
    && pass "Master agent exits 0 or 2" \
    || fail "Master agent exits 0 or 2" "exit code: $MASTER_AGENT_EXIT"

grep -qi "Applied catalog" <<< "$MASTER_AGENT_OUT" \
    && pass "Master agent output contains 'Applied catalog'" \
    || fail "Master agent output contains 'Applied catalog'"

grep -qF "Smoke test passed" <<< "$MASTER_AGENT_OUT" \
    && pass "Master agent output contains smoke test notify" \
    || fail "Master agent output contains smoke test notify"

_master_managed=$(exec_master cat /tmp/puppet_managed 2>/dev/null) || true
[ -n "$_master_managed" ] \
    && pass "/tmp/puppet_managed exists on master" \
    || fail "/tmp/puppet_managed exists on master"

# ═════════════════════════════════════════════════════════════════════════
# Group 5 -- Individual master mTLS endpoints
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Group 5 -- Individual master mTLS endpoints\n'

copy_from_client \
    /etc/puppetlabs/puppet/ssl/certs/client.puppet.localdomain.pem \
    "$WORK_DIR/client.crt" 2>/dev/null || true
copy_from_client \
    /etc/puppetlabs/puppet/ssl/private_keys/client.puppet.localdomain.pem \
    "$WORK_DIR/client.key" 2>/dev/null || true
[ -f "$WORK_DIR/client.key" ] && chmod 600 "$WORK_DIR/client.key"

if [[ -s "$WORK_DIR/client.crt" && -s "$WORK_DIR/client.key" ]]; then
    _MTLS=(
        --cacert  "$WORK_DIR/ca.pem"
        --cert    "$WORK_DIR/client.crt"
        --key     "$WORK_DIR/client.key"
        --resolve "puppet-master:8140:127.0.0.1"
    )

    assert_http 200 "Node endpoint returns 200" \
        "${_MTLS[@]}" \
        "https://puppet-master:8140/puppet/v3/node/client.puppet.localdomain?environment=production"

    assert_contains '"name"' "Node endpoint contains 'name'" \
        "${_MTLS[@]}" \
        "https://puppet-master:8140/puppet/v3/node/client.puppet.localdomain?environment=production"

    assert_http 200 "File metadatas endpoint returns 200" \
        "${_MTLS[@]}" \
        "https://puppet-master:8140/puppet/v3/file_metadatas/plugins?recurse=false&links=manage&checksum_type=sha256&source_permissions=ignore&environment=production"

    AGENT2_EXIT=0
    AGENT2_OUT=$(run_agent) || AGENT2_EXIT=$?
    [[ "$AGENT2_EXIT" =~ ^(0|2)$ ]] \
        && pass "Second agent run (idempotency) exits 0 or 2" \
        || fail "Second agent run (idempotency) exits 0 or 2" "exit code: $AGENT2_EXIT"
else
    for _desc in \
        "Node endpoint returns 200" \
        "Node endpoint contains 'name'" \
        "File metadatas endpoint returns 200" \
        "Second agent run (idempotency) exits 0 or 2"
    do
        fail "$_desc" "could not copy client cert from container"
    done
fi

# ═════════════════════════════════════════════════════════════════════════
# Group 6 -- Certificate revocation
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Group 6 -- Certificate revocation\n'

# Revoke client cert via master's mTLS.
_revoke_client=$(ca_admin_put "client.puppet.localdomain" '{"desired_state":"revoked"}') || true
[[ "$_revoke_client" =~ ^2 ]] \
    && pass "Client cert revocation returns 2xx" \
    || fail "Client cert revocation returns 2xx" "got HTTP $_revoke_client"

# Verify the CRL now contains the revoked cert.
_crl_text=$(exec_master curl -sf \
    --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
    "https://openvox-ca:8140/puppet-ca/v1/certificate_revocation_list/ca" \
    2>/dev/null | openssl crl -text -noout 2>/dev/null) || true
grep -qi "Revoked Certificates" <<< "$_crl_text" \
    && pass "CRL contains 'Revoked Certificates' section after client revocation" \
    || fail "CRL contains 'Revoked Certificates' section after client revocation"

# Refresh master's CRL so it enforces the new revocation.
refresh_master_crl || true

# Puppet agent with the revoked cert should now be rejected.
AGENT3_EXIT=0
AGENT3_OUT=$(run_agent) || AGENT3_EXIT=$?
if grep -qiE "revoked|SSL_read|certificate verify|bad certificate" <<< "$AGENT3_OUT"; then
    pass "Agent run with revoked cert shows revocation/SSL error"
else
    fail "Agent run with revoked cert shows revocation/SSL error" \
         "exit=${AGENT3_EXIT}; last lines: $(tail -3 <<< "$AGENT3_OUT" | tr '\n' ' ')"
fi

# ═════════════════════════════════════════════════════════════════════════
# Group 6b -- Agent keeps waiting through a duplicate-request refusal
# ═════════════════════════════════════════════════════════════════════════
# The duplicate-certificate policy answers a CSR for a subject that already
# has a pending request with a 400, because the agent's SSL state machine
# reads a 400 on submission as "keep waiting" and any other non-2xx as fatal.
# The other suites pin the status; this is the one place a real agent
# receives it.
#
# The stack autosigns, so a pending request is planted by submitting one the
# autosign path refuses: a CSR asking for a subject alternative name, which
# allow_subject_alt_names (off) refuses after the CSR is saved. The agent's
# own CSR is then refused as a duplicate, its certificate GET finds nothing,
# and it waits. Rejecting the planted request mid-run lets its next
# submission through, to be autosigned.
printf '\n# Group 6b -- Agent keeps waiting through a duplicate-request refusal\n'

clean_client_cert

_WAIT_CN="client.puppet.localdomain"
openssl genrsa -out "$WORK_DIR/wait-plant.key" 2048 2>/dev/null || true
[ -f "$WORK_DIR/wait-plant.key" ] && chmod 600 "$WORK_DIR/wait-plant.key"
openssl req -new \
    -key  "$WORK_DIR/wait-plant.key" \
    -subj "/CN=${_WAIT_CN}" \
    -addext "subjectAltName=DNS:not-permitted.example" \
    -out  "$WORK_DIR/wait-plant.csr" 2>/dev/null || true
_plant_st=$(curl -s -o /dev/null -w '%{http_code}' \
    "${_CA[@]}" \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/wait-plant.csr" \
    "${CA_HOST_URL}/puppet-ca/v1/certificate_request/${_WAIT_CN}") || true
[ "$_plant_st" = "400" ] \
    && pass "Planted CSR with a refused SAN answers 400 under autosign" \
    || fail "Planted CSR with a refused SAN answers 400 under autosign" "got HTTP $_plant_st"

_plant_pending=$(exec_master curl -s -o /dev/null -w '%{http_code}' \
    --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
    --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
    --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
    "https://openvox-ca:8140/puppet-ca/v1/certificate_request/${_WAIT_CN}" \
    2>/dev/null || true)
[ "$_plant_pending" = "200" ] \
    && pass "Planted CSR stays pending after the autosign refusal" \
    || fail "Planted CSR stays pending after the autosign refusal" "GET certificate_request returned HTTP $_plant_pending"

# --maxwaitforcert bounds the run, so a regression ends in a failure rather
# than a hang.
run_agent --waitforcert 5 --maxwaitforcert 120 > "$WORK_DIR/agent-wait.out" 2>&1 &
_wait_agent_pid=$!

# Reject the planted request once the agent has been refused and is waiting,
# which it reports when its certificate GET finds nothing. The poll is bounded
# in case its output is buffered; the assertions below decide either way.
for _ in $(seq 1 60); do
    grep -qE "has not been signed yet|Couldn't fetch certificate" "$WORK_DIR/agent-wait.out" 2>/dev/null && break
    sleep 1
done
_reject_st=$(exec_master curl -s -o /dev/null -w '%{http_code}' \
    --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
    --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
    --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
    -X DELETE \
    "https://openvox-ca:8140/puppet-ca/v1/certificate_request/${_WAIT_CN}" \
    2>/dev/null || true)
[ "$_reject_st" = "204" ] \
    && pass "Rejecting the planted CSR returns 204" \
    || fail "Rejecting the planted CSR returns 204" "got HTTP $_reject_st"

_WAIT_AGENT_EXIT=0
wait "$_wait_agent_pid" || _WAIT_AGENT_EXIT=$?
_WAIT_AGENT_OUT=$(cat "$WORK_DIR/agent-wait.out" 2>/dev/null || true)

# The agent waited: its GET found no certificate, which only follows a
# refused submission it survived.
grep -qE "has not been signed yet|Couldn't fetch certificate" <<< "$_WAIT_AGENT_OUT" \
    && pass "Agent kept waiting after its CSR was refused with 400" \
    || fail "Agent kept waiting after its CSR was refused with 400" \
            "last lines: $(tail -5 <<< "$_WAIT_AGENT_OUT" | tr '\n' '|')"
[[ "$_WAIT_AGENT_EXIT" =~ ^(0|2)$ ]] \
    && pass "Agent enrolled and ran once the pending request was rejected" \
    || fail "Agent enrolled and ran once the pending request was rejected" \
            "exit=${_WAIT_AGENT_EXIT}; last lines: $(tail -5 <<< "$_WAIT_AGENT_OUT" | tr '\n' '|')"
grep -qi "Applied catalog" <<< "$_WAIT_AGENT_OUT" \
    && pass "Agent applied its catalog after waiting" \
    || fail "Agent applied its catalog after waiting" \
            "last lines: $(tail -5 <<< "$_WAIT_AGENT_OUT" | tr '\n' '|')"

# ═════════════════════════════════════════════════════════════════════════
# Group 7 -- OpenVoxDB validation
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Group 7 -- OpenVoxDB validation\n'

_pdb_nodes=$(pdb_query /pdb/query/v4/nodes 2>/dev/null) || true
grep -qF "client.puppet.localdomain" <<< "$_pdb_nodes" \
    && pass "OpenVoxDB knows about client.puppet.localdomain" \
    || fail "OpenVoxDB knows about client.puppet.localdomain" "not found in nodes response"

grep -qF "puppet-master" <<< "$_pdb_nodes" \
    && pass "OpenVoxDB knows about puppet-master" \
    || fail "OpenVoxDB knows about puppet-master" "not found in nodes response"

_pdb_facts=$(pdb_query '/pdb/query/v4/facts?query=%5B%22%3D%22%2C%22certname%22%2C%22client.puppet.localdomain%22%5D' 2>/dev/null) || true
[[ "$_pdb_facts" =~ ^\[.+\]$ ]] \
    && pass "OpenVoxDB has facts for client.puppet.localdomain" \
    || fail "OpenVoxDB has facts for client.puppet.localdomain" "response: $_pdb_facts"

_pdb_reports=$(pdb_query /pdb/query/v4/reports 2>/dev/null) || true
[[ "$_pdb_reports" =~ "certname" ]] \
    && pass "OpenVoxDB has at least one report" \
    || fail "OpenVoxDB has at least one report"

# ═════════════════════════════════════════════════════════════════════════
# Group 8 -- Exported resources (re-bootstrap client and collect exports)
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Group 8 -- Exported resources\n'

clean_client_cert

AGENT4_EXIT=0
AGENT4_OUT=$(run_agent --waitforcert 30) || AGENT4_EXIT=$?

[[ "$AGENT4_EXIT" =~ ^(0|2)$ ]] \
    && pass "Client re-bootstrap after revocation exits 0 or 2" \
    || fail "Client re-bootstrap after revocation exits 0 or 2" "exit code: $AGENT4_EXIT"

# After both master and client have run, client should have collected the
# master's exported file.
_exported_master=$(exec_client cat /tmp/exported_from_puppet-master 2>/dev/null) || true
[ -n "$_exported_master" ] \
    && pass "Client has exported file from puppet-master" \
    || fail "Client has exported file from puppet-master" "file not found or empty"

# ═════════════════════════════════════════════════════════════════════════
# Teardown: restore stack to a clean state for re-use
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Teardown\n'

# Revoke any per-run test certs that are still active.
for _td_host in "${_INTEG_HOST:-}"; do
    [[ -z "$_td_host" ]] && continue
    _td_state=$(exec_master curl -s \
        --cacert /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem \
        --cert   /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem \
        --key    /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem \
        "https://openvox-ca:8140/puppet-ca/v1/certificate_status/${_td_host}" \
        2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin).get('state',''))" \
        2>/dev/null || true)
    if [[ "$_td_state" = "signed" ]]; then
        ca_admin_put "$_td_host" '{"desired_state":"revoked"}' >/dev/null || true
        printf '#   revoked stale cert: %s\n' "$_td_host"
    fi
done

exec_client rm -rf /etc/puppetlabs/puppet/ssl 2>/dev/null && \
    printf '#   client SSL dir cleaned\n' || true

refresh_master_crl && printf '#   master CRL refreshed\n' || true

# ═════════════════════════════════════════════════════════════════════════
# Results
# ═════════════════════════════════════════════════════════════════════════
printf '\n# Results: %d/%d passed, %d failed\n' \
    $(( T - FAILURES )) "$T" "$FAILURES"

# A non-zero status here sends cleanup() down its failure-dump path, so a
# failed assertion is followed by the container logs that explain it.
[ "$FAILURES" -eq 0 ]
