#!/bin/bash
# Migration integration test: VoxPupuli Puppet Server CA → openvox-ca.
#
# Runs inside the test-runner container (the integration fixture image built
# from test/Dockerfile.run, not the published openvox-ca image) with the old
# Puppet Server's CA directory mounted at /old-ca (read-only).
#
# Prerequisites (handled by test/compose-migration.yml):
#   - old-puppet service is healthy (JVM Puppet Server with built-in CA)
#   - /old-ca contains the real Puppet Server CA directory
#   - openvox-ca and openvox-ca-ctl are on PATH
#   - the fixture image provides the commands declared in
#     test/fixture-commands.sh (their packages in test/Dockerfile.run);
#     require_fixture_commands asserts this before Phase 1
#
# Output: TAP format.  Exit 0 when all pass, exit 1 if any fail.
#
# Diagnostics (issue #208)
# ------------------------
# Every `fail` here carries a second argument, and every request goes through
# the helpers in http-helpers.sh, because this suite runs unattended in CI
# against containers that are destroyed the moment it finishes.  Whatever a
# failing assertion does not print is gone.  When adding an assertion, assume
# you will be reading its output months later with no way to reproduce the
# run: say what was expected, what arrived, and where to look.
#
# The one retry policy worth stating explicitly: pre-flight checks against the
# old Puppet Server may retry, because that server is fixture.  Assertions
# about openvox-ca's own conduct (Phase 5 onwards) must not, because retrying
# there would hide the intermittent faults this suite exists to catch.
# Phase 4's readiness wait polls sixty times and is not a counter-example: it
# waits for the server to have started, which is a precondition, not a verdict
# being re-rolled until it comes out green.

set -uo pipefail

# Asserted before anything else, including the mktemp calls below. See
# test/fixture-commands.sh for what this guards against.
# shellcheck source=test/fixture-commands.sh
. "$(dirname "${BASH_SOURCE[0]}")/../fixture-commands.sh"
require_fixture_commands || exit 1

# shellcheck source=test/migration/http-helpers.sh
. "$(dirname "${BASH_SOURCE[0]}")/http-helpers.sh"

# -- Configuration ------------------------------------------------------------
OLD_CA_URL="https://old-puppet:8140"
OLD_CA_DIR="/old-ca"
NEW_CA_DIR=$(mktemp -d /tmp/openvox-ca-migration.XXXXXX)
NEW_CA_PORT=8140
WORK_DIR=$(mktemp -d /tmp/migration-work.XXXXXX)
RUN_ID=$(date +%s%N | tail -c 8)

# The openvox-ca under test runs as a background process inside this
# container, not as a compose service, so -- unlike old-puppet -- its output
# never reaches the CI log by compose's stream interleaving.  It used to go to
# /dev/null, which meant a server that failed to start surfaced only as
# "timed out waiting for health" with its own explanation discarded.  Keep it,
# and replay the tail when the run fails.  (This is the migration suite's
# equivalent of the failure-log dump the other compose harnesses gained in
# #207; the service that needed it here just is not a container.)
NEW_CA_LOG="$WORK_DIR/openvox-ca.log"
NEW_CA_LOG_TAIL=200

# -- TAP helpers --------------------------------------------------------------
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
    return 0
}

# -- Helper: replay the CA-under-test's own log to stderr ---------------------
# To stderr, not stdout, so it cannot corrupt the TAP stream a consumer is
# parsing -- the same split the other compose harnesses use for their
# container-log dumps.
dump_new_ca_log() {
    if [ ! -s "$NEW_CA_LOG" ]; then
        printf '# ---- openvox-ca under test wrote no log ----\n' >&2
        return 0
    fi
    printf '# ---- last %d log lines from the openvox-ca under test ----\n' \
        "$NEW_CA_LOG_TAIL" >&2
    tail -n "$NEW_CA_LOG_TAIL" "$NEW_CA_LOG" >&2
    printf '# ---- end of openvox-ca log ----\n' >&2
}

cleanup() {
    # First statement: $? is the status this script is exiting with.
    local _rc=$?

    if [ -n "${_NEW_CA_PID:-}" ]; then
        kill "$_NEW_CA_PID" 2>/dev/null
        wait "$_NEW_CA_PID" 2>/dev/null
    fi

    # Dump from the trap rather than from each failure site: that is what
    # makes it true of every exit path, including ones added later. After the
    # kill above so the server's shutdown lines are flushed, before the rm
    # below so the file still exists.
    if [ "$_rc" -ne 0 ] || [ "$FAILURES" -gt 0 ]; then
        printf '\n# Run failed (exit %d, %d failed assertions) -- openvox-ca log follows\n' \
            "$_rc" "$FAILURES" >&2
        dump_new_ca_log
    fi

    rm -rf "$NEW_CA_DIR" "$WORK_DIR" "$_HTTP_TMPDIR"
    fixture_missing_cleanup
}
trap cleanup EXIT

# ═════════════════════════════════════════════════════════════════════════════
# Phase 1 -- Verify the old Puppet Server CA is genuine
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 1 -- Verify old Puppet Server CA\n'

# 1a: Verify the old CA directory contains expected files.
[ -s "$OLD_CA_DIR/ca_crt.pem" ] \
    && pass "Old CA: ca_crt.pem exists and is readable" \
    || fail "Old CA: ca_crt.pem exists and is readable" "not found or empty at $OLD_CA_DIR/ca_crt.pem"

[ -s "$OLD_CA_DIR/ca_key.pem" ] \
    && pass "Old CA: ca_key.pem exists and is readable" \
    || fail "Old CA: ca_key.pem exists and is readable" "not found or empty at $OLD_CA_DIR/ca_key.pem"

[ -s "$OLD_CA_DIR/ca_crl.pem" ] \
    && pass "Old CA: ca_crl.pem exists and is readable" \
    || fail "Old CA: ca_crl.pem exists and is readable" "not found or empty at $OLD_CA_DIR/ca_crl.pem"

[ -d "$OLD_CA_DIR/signed" ] \
    && pass "Old CA: signed/ directory exists" \
    || fail "Old CA: signed/ directory exists" \
            "no directory at $OLD_CA_DIR/signed; $OLD_CA_DIR holds: $(ls -A "$OLD_CA_DIR" 2>&1 | diag_oneline)"

# 1b: Verify the CA cert is a genuine CA (BasicConstraints: CA:TRUE).
# Keep openssl's own complaint: an unreadable or non-PEM file and a genuine
# certificate that simply is not a CA both used to report as the same bare
# "certificate has CA:TRUE" failure.
_old_ca_text=$(openssl x509 -noout -text -in "$OLD_CA_DIR/ca_crt.pem" 2>&1) || true
_old_ca_is_ca=$(printf '%s' "$_old_ca_text" | grep -c "CA:TRUE") || true
[ "${_old_ca_is_ca:-0}" -gt 0 ] \
    && pass "Old CA: certificate has CA:TRUE" \
    || fail "Old CA: certificate has CA:TRUE" \
            "no CA:TRUE in $OLD_CA_DIR/ca_crt.pem; openssl said: $(printf '%s' "$_old_ca_text" | head -c 300 | diag_oneline)"

# 1c: The old server signed its own cert; verify it's in signed/.
_old_signed_count=$(find "$OLD_CA_DIR/signed" -name '*.pem' -type f 2>/dev/null | wc -l) || true
[ "${_old_signed_count:-0}" -gt 0 ] \
    && pass "Old CA: has at least one signed cert (count=$_old_signed_count)" \
    || fail "Old CA: has at least one signed cert" \
            "no *.pem under $OLD_CA_DIR/signed; it holds: $(ls -A "$OLD_CA_DIR/signed" 2>&1 | diag_oneline)"

# 1d: Fetch the CA cert via the old server's API.
#
# This is the assertion #208 was filed about. It is a pre-flight check on the
# fixture -- the migration itself is Phase 3 onwards -- so a bounded retry is
# legitimate here in a way it would not be for an assertion about openvox-ca.
# The observed failure was a clean 200 at the server with nothing usable
# arriving at the client, so the retry is keyed on the body containing a
# certificate and not merely on the status code.
http_get_retry "BEGIN CERTIFICATE" "$OLD_CA_URL/puppet-ca/v1/certificate/ca" -k
http_ok "BEGIN CERTIFICATE" \
    && pass "Old CA: API serves CA cert" \
    || fail "Old CA: API serves CA cert" "$_HTTP_INFO"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 2 -- Create test certificates on the old CA
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 2 -- Create test certs on old CA\n'

# 2a: Submit a CSR to the old CA and get it autosigned.
_OLD_AGENT="mig-agent-${RUN_ID}"
_keygen_err=$(openssl genrsa -out "$WORK_DIR/agent.key" 2048 2>&1) || true
_csrgen_err=$(openssl req -new \
    -key "$WORK_DIR/agent.key" \
    -subj "/CN=${_OLD_AGENT}" \
    -out "$WORK_DIR/agent.csr" 2>&1) || true
[ -s "$WORK_DIR/agent.csr" ] \
    && pass "Old CA: agent CSR generated" \
    || fail "Old CA: agent CSR generated" \
            "openssl genrsa: $(printf '%s' "$_keygen_err" | diag_oneline); openssl req: $(printf '%s' "$_csrgen_err" | diag_oneline)"

# Deliberately not retried, unlike the fetches either side of it: a CSR PUT is
# not idempotent -- resubmitting one the old server already holds is an error
# there -- so a retry could turn a transport hiccup into a hard rejection. The
# timing flakiness this step has is in waiting for autosign, which 2b's retry
# covers properly.
http_get "${OLD_CA_URL}/puppet-ca/v1/certificate_request/${_OLD_AGENT}" \
    -k -X PUT -H "Content-Type: text/plain" --data-binary @"$WORK_DIR/agent.csr" || true
http_ok \
    && pass "Old CA: CSR submission returns 2xx (status=$_HTTP_CODE)" \
    || fail "Old CA: CSR submission returns 2xx" "$_HTTP_INFO"

# 2b: Fetch the signed cert from the old CA.
#
# This used to be a blind `sleep 2` for autosign followed by a single attempt,
# which is the same shape of flake as 1d with a timer in front of it. The
# retry both waits and reports: it returns as soon as the cert is there, and
# says what it saw on every attempt when it never is.
http_get_retry "BEGIN CERTIFICATE" \
    "${OLD_CA_URL}/puppet-ca/v1/certificate/${_OLD_AGENT}" -k
_old_agent_cert=$_HTTP_BODY
http_ok "BEGIN CERTIFICATE" \
    && pass "Old CA: agent cert signed and fetchable" \
    || fail "Old CA: agent cert signed and fetchable" "$_HTTP_INFO"

# 2c: Verify the agent cert chains to the old CA.
printf '%s\n' "$_old_agent_cert" > "$WORK_DIR/agent.crt"
_verify_out=$(openssl verify -CAfile "$OLD_CA_DIR/ca_crt.pem" "$WORK_DIR/agent.crt" 2>&1) \
    && pass "Old CA: agent cert verifies against CA cert" \
    || fail "Old CA: agent cert verifies against CA cert" \
            "openssl verify: $(printf '%s' "$_verify_out" | diag_oneline)"

# 2d: Record fingerprints for later comparison.
# 2>&1, not 2>/dev/null: these values are only ever reported as one side of a
# mismatch, so when openssl refuses the input its complaint is exactly what the
# reader needs, and an empty side explains nothing.
_old_agent_fp=$(openssl x509 -noout -fingerprint -sha256 \
    -in "$WORK_DIR/agent.crt" 2>&1 | diag_oneline) || true
_old_ca_fp=$(openssl x509 -noout -fingerprint -sha256 \
    -in "$OLD_CA_DIR/ca_crt.pem" 2>&1 | diag_oneline) || true

# ═════════════════════════════════════════════════════════════════════════════
# Phase 3 -- Import old CA into openvox-ca
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 3 -- Import old CA into openvox-ca\n'

# 3a: Import using openvox-ca-ctl.
_import_out=$(openvox-ca-ctl import \
    --cadir       "$NEW_CA_DIR" \
    --cert-bundle "$OLD_CA_DIR/ca_crt.pem" \
    --private-key "$OLD_CA_DIR/ca_key.pem" \
    --crl-chain   "$OLD_CA_DIR/ca_crl.pem" \
    2>&1) && _import_rc=$? || _import_rc=$?
[ "$_import_rc" -eq 0 ] \
    && pass "Import: openvox-ca-ctl import succeeds" \
    || fail "Import: openvox-ca-ctl import succeeds" \
            "exit=$_import_rc output=$(printf '%s' "$_import_out" | diag_oneline)"

# 3b: Verify imported files.
# On failure, list what import actually produced: "the file is missing" and
# "the file landed somewhere else" are different bugs and used to look alike.
_import_tree=$(find "$NEW_CA_DIR" -maxdepth 2 2>&1 | diag_oneline)
[ -f "$NEW_CA_DIR/ca_crt.pem" ] \
    && pass "Import: CA cert at ca_crt.pem" \
    || fail "Import: CA cert at ca_crt.pem" "$NEW_CA_DIR holds: $_import_tree"
[ -f "$NEW_CA_DIR/private/ca_key.pem" ] \
    && pass "Import: CA key at private/ca_key.pem" \
    || fail "Import: CA key at private/ca_key.pem" "$NEW_CA_DIR holds: $_import_tree"
[ -f "$NEW_CA_DIR/ca_crl.pem" ] \
    && pass "Import: CRL at ca_crl.pem" \
    || fail "Import: CRL at ca_crl.pem" "$NEW_CA_DIR holds: $_import_tree"

# 3c: Verify the imported CA cert fingerprint matches the old one.
_new_ca_fp=$(openssl x509 -noout -fingerprint -sha256 \
    -in "$NEW_CA_DIR/ca_crt.pem" 2>&1 | diag_oneline) || true
[ "$_old_ca_fp" = "$_new_ca_fp" ] \
    && pass "Import: CA cert fingerprint matches old CA" \
    || fail "Import: CA cert fingerprint matches old CA" \
           "old=$_old_ca_fp new=$_new_ca_fp"

# 3d: Copy signed certificates from the old CA.
_cp_out=$(cp "$OLD_CA_DIR/signed/"*.pem "$NEW_CA_DIR/signed/" 2>&1) || true
_new_signed_count=$(find "$NEW_CA_DIR/signed" -name '*.pem' -type f 2>/dev/null | wc -l) || true
[ "${_new_signed_count:-0}" -gt 0 ] \
    && pass "Import: copied $_new_signed_count signed certs" \
    || fail "Import: copied signed certs" \
            "count=$_new_signed_count; cp said: $(printf '%s' "$_cp_out" | diag_oneline)"

# 3e: Rebuild inventory from copied certs.
# openvox-ca's inventory format: SERIAL NOT_BEFORE NOT_AFTER /SUBJECT
# Dates must be in Go's 2006-01-02T15:04:05UTC format (no spaces).
_inv_skipped=''
for _cert in "$NEW_CA_DIR/signed/"*.pem; do
    [ -f "$_cert" ] || continue
    _subj=$(basename "$_cert" .pem)
    _ser=$(openssl x509 -noout -serial -in "$_cert" 2>/dev/null | cut -d= -f2) \
        || { _inv_skipped="${_inv_skipped} ${_subj}(serial)"; continue; }
    _nb=$(date -u -d "$(openssl x509 -noout -startdate -in "$_cert" 2>/dev/null | sed 's/notBefore=//')" \
        '+%Y-%m-%dT%H:%M:%SUTC' 2>/dev/null) \
        || { _inv_skipped="${_inv_skipped} ${_subj}(notBefore)"; continue; }
    _na=$(date -u -d "$(openssl x509 -noout -enddate -in "$_cert" 2>/dev/null | sed 's/notAfter=//')" \
        '+%Y-%m-%dT%H:%M:%SUTC' 2>/dev/null) \
        || { _inv_skipped="${_inv_skipped} ${_subj}(notAfter)"; continue; }
    echo "$_ser $_nb $_na /$_subj" >> "$NEW_CA_DIR/inventory.txt"
done
_inv_lines=$(wc -l < "$NEW_CA_DIR/inventory.txt" 2>/dev/null) || _inv_lines=0
[ "$_inv_lines" -gt 0 ] \
    && pass "Import: inventory rebuilt with $_inv_lines entries" \
    || fail "Import: inventory rebuilt" \
            "lines=$_inv_lines from $_new_signed_count certs; skipped:${_inv_skipped:- none}"

# A cert silently dropped from the inventory is the kind of partial migration
# Phase 5's spot checks can pass over: 5f takes the first cert in signed/, and
# 5g greps only for the agent. So this is an assertion, not the TAP comment it
# started as -- a comment on a green run is a comment nobody reads, and
# "inventory rebuilt with 1 entries" from ten certs would otherwise pass.
[ -z "$_inv_skipped" ] \
    && pass "Import: every copied cert made it into the inventory" \
    || fail "Import: every copied cert made it into the inventory" \
            "skipped:${_inv_skipped}"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 4 -- Start openvox-ca with imported material
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 4 -- Start openvox-ca with imported CA\n'

openvox-ca --cadir "$NEW_CA_DIR" \
    --host 127.0.0.1 --port "$NEW_CA_PORT" \
    --no-tls-required \
    --autosign-config=true \
    >"$NEW_CA_LOG" 2>&1 &
_NEW_CA_PID=$!

_new_url="http://127.0.0.1:${NEW_CA_PORT}"
_new_ready=false

# A readiness probe against a loopback port on this same container has no
# reason to allow the default 60-second HTTP_MAX_TIME. Left at the default,
# a server that accepts the connection and then stalls -- the exact case the
# time bounds exist for -- makes each of the 60 probes cost up to a minute,
# so a loop meant to give up after ~20 seconds can run for an hour instead.
# Scoped to this loop only; the fixture fetches keep the generous default.
# The `VAR=x func` prefix below is temporary rather than leaking into the rest
# of the run -- verified in bash 5.3 and in the runner image's own bash
# (quay.io/centos/centos:stream10), because the two shells could have differed
# and a leak would silently shorten every later fetch's timeout.
READY_MAX_TIME=2
READY_ATTEMPTS=60
READY_SLEEP=0.3

# Measured, not assumed: the diagnostic below used to state a hardcoded "~18s"
# computed from the attempt count times the sleep, which is only true when
# every probe returns instantly. Reporting a number the run did not observe is
# the failure this suite exists to stop doing.
_ready_t0=$(date +%s)
for _i in $(seq 1 "$READY_ATTEMPTS"); do
    HTTP_MAX_TIME=$READY_MAX_TIME \
        http_get "${_new_url}/healthz/ready" >/dev/null 2>&1
    # http_ok with no EXPECT: transport success and a 2xx. Not the status
    # alone -- these helpers do not pass -f, so a 503 "not ready" is a
    # successful request that must not end the wait, and a 2xx that arrived
    # over a failed transfer must not end it either.
    if http_ok; then
        _new_ready=true; break
    fi
    sleep "$READY_SLEEP"
done
_ready_elapsed=$(( $(date +%s) - _ready_t0 ))

if [ "$_new_ready" != "true" ]; then
    # "never started" and "started but never became ready" need different
    # fixes and used to produce the same one-line failure.
    if kill -0 "$_NEW_CA_PID" 2>/dev/null; then
        _proc_state="process $_NEW_CA_PID still running"
    else
        _proc_state="process $_NEW_CA_PID already exited"
    fi
    fail "openvox-ca starts with imported CA" \
         "no ready response after ${_i} attempts over ${_ready_elapsed}s (bound: ${READY_ATTEMPTS} x (${READY_MAX_TIME}s + ${READY_SLEEP}s)); $_proc_state; last probe: $_HTTP_INFO"
    # No dump here: the EXIT trap below dumps on any non-zero exit, and doing
    # it in both places would print the log twice.
    # Reported here too: this early exit is the path most likely to be taken
    # when a command is missing, so it is the path that most needs to say so.
    fixture_missing_assert
    printf '\n1..%d\n' "$T"
    printf '# Results: %d passed, %d failed out of %d\n' \
        $(( T - FAILURES )) "$FAILURES" "$T"
    exit 1
fi
pass "openvox-ca starts with imported CA"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 5 -- Verify the migrated CA works
# ═════════════════════════════════════════════════════════════════════════════
# From here on the subject is openvox-ca's own conduct, so every request is a
# single attempt: http_get, never http_get_retry.
printf '\n# Phase 5 -- Verify migrated CA\n'

# 5a: CA cert is fetchable from the new server.
http_get "${_new_url}/puppet-ca/v1/certificate/ca" || true
_new_api_cert=$_HTTP_BODY
http_ok "BEGIN CERTIFICATE" \
    && pass "New CA: API serves CA cert" \
    || fail "New CA: API serves CA cert" "$_HTTP_INFO"

# 5b: CA cert from new server matches the old one.
_new_api_fp=$(printf '%s\n' "$_new_api_cert" | openssl x509 -noout -fingerprint -sha256 2>&1 | diag_oneline) || true
[ "$_old_ca_fp" = "$_new_api_fp" ] \
    && pass "New CA: API-served CA cert matches old CA fingerprint" \
    || fail "New CA: API-served CA cert matches old CA fingerprint" \
           "old=$_old_ca_fp new=$_new_api_fp"

# 5c: CRL is fetchable.
http_get "${_new_url}/puppet-ca/v1/certificate_revocation_list/ca" || true
http_ok "BEGIN X509 CRL" \
    && pass "New CA: CRL fetchable" \
    || fail "New CA: CRL fetchable" "$_HTTP_INFO"

# 5d: The agent cert signed by the old CA is fetchable from the new server.
http_get "${_new_url}/puppet-ca/v1/certificate/${_OLD_AGENT}" || true
_migrated_cert=$_HTTP_BODY
http_ok "BEGIN CERTIFICATE" \
    && pass "New CA: migrated agent cert fetchable by subject" \
    || fail "New CA: migrated agent cert fetchable by subject" \
            "subject=${_OLD_AGENT} $_HTTP_INFO"

# 5e: The fetched cert fingerprint matches the original.
_migrated_fp=$(printf '%s\n' "$_migrated_cert" | openssl x509 -noout -fingerprint -sha256 2>&1 | diag_oneline) || true
[ "$_old_agent_fp" = "$_migrated_fp" ] \
    && pass "New CA: migrated cert fingerprint matches original" \
    || fail "New CA: migrated cert fingerprint matches original" \
           "old=$_old_agent_fp new=$_migrated_fp"

# 5f: At least one pre-existing cert from the old CA is fetchable.
# The old Puppet Server's own cert may or may not be in the CA's signed/
# directory (depends on VoxPupuli version), so check the first cert we
# copied rather than hardcoding "old-puppet".
_old_pre_existing=$(basename "$(find "$NEW_CA_DIR/signed" -name '*.pem' -type f 2>/dev/null \
    | grep -v "${_OLD_AGENT}" | sort | head -1)" .pem 2>/dev/null) || true
if [ -n "$_old_pre_existing" ]; then
    http_get "${_new_url}/puppet-ca/v1/certificate/${_old_pre_existing}" || true
    http_ok "BEGIN CERTIFICATE" \
        && pass "New CA: pre-existing old cert (${_old_pre_existing}) fetchable" \
        || fail "New CA: pre-existing old cert (${_old_pre_existing}) fetchable" \
                "$_HTTP_INFO"
else
    # Not an assertion about openvox-ca at all: the fixture offered nothing to
    # check. A TAP SKIP directive rather than a bare pass, so a consumer can
    # see that coverage disappeared -- as a plain pass this was indistinguish-
    # able from the real check having run.
    pass "New CA: pre-existing old cert fetchable # SKIP no cert other than ${_OLD_AGENT} in signed/"
fi

# 5g: openvox-ca-ctl list shows the migrated certs.
_new_list=$(openvox-ca-ctl --server-url "$_new_url" list --all 2>&1) || true
printf '%s' "$_new_list" | grep -qF "${_OLD_AGENT}" \
    && pass "New CA: openvox-ca-ctl list shows migrated agent cert" \
    || fail "New CA: openvox-ca-ctl list shows migrated agent cert" \
            "looking for ${_OLD_AGENT} in: $(printf '%s' "$_new_list" | diag_oneline)"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 6 -- Sign new certs, revoke migrated certs
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 6 -- New signing and revocation on migrated CA\n'

# 6a: Submit and autosign a brand-new CSR on the migrated CA.
_NEW_AGENT="mig-newagent-${RUN_ID}"
_keygen_err=$(openssl genrsa -out "$WORK_DIR/new-agent.key" 2048 2>&1) || true
_csrgen_err=$(openssl req -new \
    -key "$WORK_DIR/new-agent.key" \
    -subj "/CN=${_NEW_AGENT}" \
    -out "$WORK_DIR/new-agent.csr" 2>&1) || true
[ -s "$WORK_DIR/new-agent.csr" ] \
    && pass "New CA: fresh CSR generated" \
    || fail "New CA: fresh CSR generated" \
            "openssl genrsa: $(printf '%s' "$_keygen_err" | diag_oneline); openssl req: $(printf '%s' "$_csrgen_err" | diag_oneline)"

# The submission's own status used to be discarded entirely (`-o /dev/null`
# with no `-w`), so a rejected CSR surfaced one assertion later as an
# unexplained "fresh cert signed by migrated CA" failure.
http_get "${_new_url}/puppet-ca/v1/certificate_request/${_NEW_AGENT}" \
    -X PUT -H "Content-Type: text/plain" --data-binary @"$WORK_DIR/new-agent.csr" || true
_submit_info=$_HTTP_INFO
http_ok \
    && pass "New CA: fresh CSR submission returns 2xx (status=$_HTTP_CODE)" \
    || fail "New CA: fresh CSR submission returns 2xx" "$_submit_info"

http_get "${_new_url}/puppet-ca/v1/certificate/${_NEW_AGENT}" || true
_new_agent_cert=$_HTTP_BODY
http_ok "BEGIN CERTIFICATE" \
    && pass "New CA: fresh cert signed by migrated CA" \
    || fail "New CA: fresh cert signed by migrated CA" \
            "fetch: $_HTTP_INFO; earlier submission: $_submit_info"

# 6b: New cert verifies against the imported (old) CA cert.
printf '%s\n' "$_new_agent_cert" > "$WORK_DIR/new-agent.crt"
_verify_out=$(openssl verify -CAfile "$NEW_CA_DIR/ca_crt.pem" "$WORK_DIR/new-agent.crt" 2>&1) \
    && pass "New CA: fresh cert chains to imported CA" \
    || fail "New CA: fresh cert chains to imported CA" \
            "openssl verify: $(printf '%s' "$_verify_out" | diag_oneline)"

# 6c: Revoke the migrated agent cert.
http_get "${_new_url}/puppet-ca/v1/certificate_status/${_OLD_AGENT}" \
    -X PUT -H "Content-Type: application/json" -d '{"desired_state":"revoked"}' || true
http_ok \
    && pass "New CA: revoke migrated agent cert returns 2xx (status=$_HTTP_CODE)" \
    || fail "New CA: revoke migrated agent cert returns 2xx" "$_HTTP_INFO"

# 6d: Verify the cert status shows 'revoked'.
http_get "${_new_url}/puppet-ca/v1/certificate_status/${_OLD_AGENT}" || true
http_ok '"revoked"' \
    && pass "New CA: migrated cert status shows 'revoked'" \
    || fail "New CA: migrated cert status shows 'revoked'" "$_HTTP_INFO"

# 6e: CRL now contains the revoked serial.
#
# The serial, not just the words "Revoked Certificates": openssl prints
# "No Revoked Certificates." for an empty CRL, which a case-insensitive
# substring test matches just as happily, so the old assertion passed whether
# or not 6c's revoke ever reached the CRL. It also could not tell a revocation
# this suite caused from one already present in the imported ca_crl.pem.
_revoked_serial=$(openssl x509 -noout -serial -in "$WORK_DIR/agent.crt" 2>&1 \
    | cut -d= -f2) || true
http_get "${_new_url}/puppet-ca/v1/certificate_revocation_list/ca" || true
_crl_text=$(printf '%s\n' "$_HTTP_BODY" | openssl crl -text -noout 2>&1) || true
if [ -n "$_revoked_serial" ] &&
   printf '%s' "$_crl_text" | grep -qi "serial number: *${_revoked_serial}\b"; then
    pass "New CA: CRL lists the revoked cert's serial (${_revoked_serial})"
else
    fail "New CA: CRL lists the revoked cert's serial" \
         "looking for serial [${_revoked_serial}]; fetch: $_HTTP_INFO; openssl crl: $(printf '%s' "$_crl_text" | head -c 400 | diag_oneline)"
fi

# 6f: Clean the revoked cert (puppet cert clean equivalent).
http_get "${_new_url}/puppet-ca/v1/certificate_status/${_OLD_AGENT}" -X DELETE || true
http_ok \
    && pass "New CA: clean migrated cert returns 2xx (status=$_HTTP_CODE)" \
    || fail "New CA: clean migrated cert returns 2xx" "$_HTTP_INFO"

# 6g: After clean, the cert should be gone (404).
http_get "${_new_url}/puppet-ca/v1/certificate/${_OLD_AGENT}" || true
[ "$_HTTP_CODE" = "404" ] \
    && pass "New CA: cleaned cert returns 404" \
    || fail "New CA: cleaned cert returns 404" "$_HTTP_INFO"

# 6h: The newly signed cert is still accessible.
http_get "${_new_url}/puppet-ca/v1/certificate/${_NEW_AGENT}" || true
http_ok "BEGIN CERTIFICATE" \
    && pass "New CA: fresh cert still accessible after migration cleanup" \
    || fail "New CA: fresh cert still accessible after migration cleanup" \
            "subject=${_NEW_AGENT} $_HTTP_INFO"

# ═════════════════════════════════════════════════════════════════════════════
# Results
# ═════════════════════════════════════════════════════════════════════════════
# Anything Bash could not resolve during the run. Without this the handler in
# fixture-commands.sh records misses that nothing ever reads, and an undeclared
# command that vanished would cost one line of stderr in a green run.
fixture_missing_assert

printf '\n1..%d\n' "$T"
printf '# Results: %d passed, %d failed out of %d\n' \
    $(( T - FAILURES )) "$FAILURES" "$T"

[ "$FAILURES" -eq 0 ]
