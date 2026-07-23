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
# NOTE: Group 6 revokes the client cert.  clean_client_cert() revokes any
# stale cert and clears the client SSL dir before Groups 3 and 8.

set -uo pipefail

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
    _COMPOSE=(podman-compose -f compose-puppet.yml)
elif docker compose version &>/dev/null 2>&1; then
    _COMPOSE=(docker compose -f compose-puppet.yml)
elif command -v docker-compose &>/dev/null; then
    _COMPOSE=(docker-compose -f compose-puppet.yml)
else
    printf 'Error: no compose tool found; install podman-compose or docker compose\n' >&2
    exit 1
fi

# -- Configuration --------------------------------------------------------─
# Host-side URLs (CA on 8141, master on 8140, as mapped in compose-puppet.yml).
CA_HOST_URL="https://localhost:8141"
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

# -- Helper: revoke + clean the client cert, wipe local SSL dir ------------─
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
    if [ "$_state" = "signed" ] || [ "$_state" = "requested" ]; then
        printf '#   revoking stale client.puppet.localdomain (state=%s)\n' "$_state"
        ca_admin_put "client.puppet.localdomain" '{"desired_state":"revoked"}' \
            >/dev/null 2>&1 || true
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

# -- Stack lifecycle ------------------------------------------------------─

cleanup() {
    rm -rf "$WORK_DIR"
    exec_client rm -rf /etc/puppetlabs/puppet/ssl 2>/dev/null || true

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
    printf '# ---- last 80 log lines from %s ----\n' "$2" >&2
    # Send both the container's stdout and stderr to our stderr. Do NOT add
    # `2>/dev/null`: with `>&2` alone, fd1 is redirected to the current stderr
    # and fd2 already points there, so both streams reach the operator. A
    # `2>/dev/null` would instead route the command's stderr to the bit-bucket
    # -- and under `podman logs` a container's stderr (where Go services write
    # their startup/abort diagnostics) is replayed to *our* stderr, so the very
    # lines that explain the failed bootstrap would be discarded.
    "${_COMPOSE[@]}" logs --tail 80 "$2" >&2 || true
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
# This cert is reused below as an mTLS client credential for endpoints that
# require a CA-signed certificate (e.g. certificate_status).
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

# mTLS credentials for endpoints that require a CA-signed client cert.
_INTEG_MTLS=(
    --cacert "$WORK_DIR/ca.pem"
    --cert   "$WORK_DIR/integ.crt"
    --key    "$WORK_DIR/integ.key"
)

# certificate_status requires a CA-signed client cert (tierAnyClient).
# Unauthenticated requests must be rejected; authenticated ones must succeed.
assert_http 403 "certificate_status without client cert returns 403" \
    "${_CA[@]}" "${CA_HOST_URL}/puppet-ca/v1/certificate_status/${_INTEG_HOST}"

_status_body=$(curl -s "${_INTEG_MTLS[@]}" \
    "${CA_HOST_URL}/puppet-ca/v1/certificate_status/${_INTEG_HOST}" \
    2>/dev/null) || true
grep -qF '"state":"signed"' <<< "$_status_body" \
    && pass "Autosigned cert status is 'signed' (mTLS)" \
    || fail "Autosigned cert status is 'signed' (mTLS)" "body: $_status_body"

assert_http 404 "Nonexistent cert status returns 404 (mTLS)" \
    "${_INTEG_MTLS[@]}" "${CA_HOST_URL}/puppet-ca/v1/certificate_status/nonexistent"

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

_srv_file=$(exec_ca cat /etc/puppet-ca/servers.txt 2>/dev/null) || true

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

# revoke_on_auto_renew defaults to true: the pre-renewal serial must now be
# in the CRL, so only the newest serial for this subject stays valid.
_old_serial_hex=${_serial_before#serial=}
_crl_after_renew=$(curl -sfk "${_CA[@]}" \
    "${CA_HOST_URL}/puppet-ca/v1/certificate_revocation_list/ca" 2>/dev/null \
    | openssl crl -text -noout 2>/dev/null) || true
# Guard on a non-empty serial first: _serial_before is captured with `|| true`,
# so if the pre-renewal serial could not be extracted, _old_serial_hex is empty
# and `grep -qF ""` would match any CRL unconditionally — passing the assertion
# without ever testing revocation. Refuse to pass on an empty serial.
[[ -n "$_old_serial_hex" ]] && grep -qF "$_old_serial_hex" <<< "$_crl_after_renew" \
    && pass "pre-renewal serial is revoked by default after auto-renewal" \
    || fail "pre-renewal serial is revoked by default after auto-renewal" "serial '$_old_serial_hex' not found in CRL"

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

[ "$FAILURES" -eq 0 ]
