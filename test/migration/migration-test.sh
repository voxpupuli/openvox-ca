#!/bin/bash
# Migration integration test: VoxPupuli Puppet Server CA → puppet-ca.
#
# Runs inside the test-runner container (puppet-ca image) with the old
# Puppet Server's CA directory mounted at /old-ca (read-only).
#
# Prerequisites (handled by compose-migration.yml):
#   - old-puppet service is healthy (JVM Puppet Server with built-in CA)
#   - /old-ca contains the real Puppet Server CA directory
#   - puppet-ca and puppet-ca-ctl are on PATH
#
# Output: TAP format.  Exit 0 when all pass, exit 1 if any fail.

set -uo pipefail

# -- Configuration ------------------------------------------------------------
OLD_CA_URL="https://old-puppet:8140"
OLD_CA_DIR="/old-ca"
NEW_CA_DIR=$(mktemp -d /tmp/puppet-ca-migration.XXXXXX)
NEW_CA_PORT=8140
WORK_DIR=$(mktemp -d /tmp/migration-work.XXXXXX)
RUN_ID=$(date +%s%N | tail -c 8)

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
}

cleanup() {
    [ -n "${_NEW_CA_PID:-}" ] && kill "$_NEW_CA_PID" 2>/dev/null && \
        wait "$_NEW_CA_PID" 2>/dev/null || true
    rm -rf "$NEW_CA_DIR" "$WORK_DIR"
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
    || fail "Old CA: signed/ directory exists"

# 1b: Verify the CA cert is a genuine CA (BasicConstraints: CA:TRUE).
_old_ca_is_ca=$(openssl x509 -noout -text -in "$OLD_CA_DIR/ca_crt.pem" 2>/dev/null \
    | grep -c "CA:TRUE") || true
[ "${_old_ca_is_ca:-0}" -gt 0 ] \
    && pass "Old CA: certificate has CA:TRUE" \
    || fail "Old CA: certificate has CA:TRUE"

# 1c: The old server signed its own cert; verify it's in signed/.
_old_signed_count=$(find "$OLD_CA_DIR/signed" -name '*.pem' -type f 2>/dev/null | wc -l) || true
[ "${_old_signed_count:-0}" -gt 0 ] \
    && pass "Old CA: has at least one signed cert (count=$_old_signed_count)" \
    || fail "Old CA: has at least one signed cert"

# 1d: Fetch the CA cert via the old server's API.
_old_api_cert=$(curl -sfk "$OLD_CA_URL/puppet-ca/v1/certificate/ca" 2>/dev/null) || true
echo "$_old_api_cert" | grep -qF "BEGIN CERTIFICATE" \
    && pass "Old CA: API serves CA cert" \
    || fail "Old CA: API serves CA cert"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 2 -- Create test certificates on the old CA
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 2 -- Create test certs on old CA\n'

# 2a: Submit a CSR to the old CA and get it autosigned.
_OLD_AGENT="mig-agent-${RUN_ID}"
openssl genrsa -out "$WORK_DIR/agent.key" 2048 2>/dev/null
openssl req -new \
    -key "$WORK_DIR/agent.key" \
    -subj "/CN=${_OLD_AGENT}" \
    -out "$WORK_DIR/agent.csr" 2>/dev/null

_csr_st=$(curl -sk -o /dev/null -w '%{http_code}' \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/agent.csr" \
    "${OLD_CA_URL}/puppet-ca/v1/certificate_request/${_OLD_AGENT}" 2>/dev/null) || true
[[ "$_csr_st" =~ ^2 ]] \
    && pass "Old CA: CSR submission returns 2xx (status=$_csr_st)" \
    || fail "Old CA: CSR submission returns 2xx" "got HTTP $_csr_st"

# 2b: Fetch the signed cert from the old CA.
sleep 2  # give autosign a moment
_old_agent_cert=$(curl -sfk \
    "${OLD_CA_URL}/puppet-ca/v1/certificate/${_OLD_AGENT}" 2>/dev/null) || true
echo "$_old_agent_cert" | grep -qF "BEGIN CERTIFICATE" \
    && pass "Old CA: agent cert signed and fetchable" \
    || fail "Old CA: agent cert signed and fetchable"

# 2c: Verify the agent cert chains to the old CA.
echo "$_old_agent_cert" > "$WORK_DIR/agent.crt"
openssl verify -CAfile "$OLD_CA_DIR/ca_crt.pem" "$WORK_DIR/agent.crt" >/dev/null 2>&1 \
    && pass "Old CA: agent cert verifies against CA cert" \
    || fail "Old CA: agent cert verifies against CA cert"

# 2d: Record fingerprints for later comparison.
_old_agent_fp=$(openssl x509 -noout -fingerprint -sha256 \
    -in "$WORK_DIR/agent.crt" 2>/dev/null) || true
_old_ca_fp=$(openssl x509 -noout -fingerprint -sha256 \
    -in "$OLD_CA_DIR/ca_crt.pem" 2>/dev/null) || true

# ═════════════════════════════════════════════════════════════════════════════
# Phase 3 -- Import old CA into puppet-ca
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 3 -- Import old CA into puppet-ca\n'

# 3a: Import using puppet-ca-ctl.
_import_out=$(puppet-ca-ctl import \
    --cadir       "$NEW_CA_DIR" \
    --cert-bundle "$OLD_CA_DIR/ca_crt.pem" \
    --private-key "$OLD_CA_DIR/ca_key.pem" \
    --crl-chain   "$OLD_CA_DIR/ca_crl.pem" \
    2>&1) && _import_rc=$? || _import_rc=$?
[ "$_import_rc" -eq 0 ] \
    && pass "Import: puppet-ca-ctl import succeeds" \
    || fail "Import: puppet-ca-ctl import succeeds" "exit=$_import_rc output=$_import_out"

# 3b: Verify imported files.
[ -f "$NEW_CA_DIR/ca_crt.pem" ] \
    && pass "Import: CA cert at ca_crt.pem" \
    || fail "Import: CA cert at ca_crt.pem"
[ -f "$NEW_CA_DIR/private/ca_key.pem" ] \
    && pass "Import: CA key at private/ca_key.pem" \
    || fail "Import: CA key at private/ca_key.pem"
[ -f "$NEW_CA_DIR/ca_crl.pem" ] \
    && pass "Import: CRL at ca_crl.pem" \
    || fail "Import: CRL at ca_crl.pem"

# 3c: Verify the imported CA cert fingerprint matches the old one.
_new_ca_fp=$(openssl x509 -noout -fingerprint -sha256 \
    -in "$NEW_CA_DIR/ca_crt.pem" 2>/dev/null) || true
[ "$_old_ca_fp" = "$_new_ca_fp" ] \
    && pass "Import: CA cert fingerprint matches old CA" \
    || fail "Import: CA cert fingerprint matches old CA" \
           "old=$_old_ca_fp new=$_new_ca_fp"

# 3d: Copy signed certificates from the old CA.
cp "$OLD_CA_DIR/signed/"*.pem "$NEW_CA_DIR/signed/" 2>/dev/null || true
_new_signed_count=$(ls "$NEW_CA_DIR/signed/"*.pem 2>/dev/null | wc -l) || true
[ "${_new_signed_count:-0}" -gt 0 ] \
    && pass "Import: copied $_new_signed_count signed certs" \
    || fail "Import: copied signed certs" "count=$_new_signed_count"

# 3e: Rebuild inventory from copied certs.
# puppet-ca's inventory format: SERIAL NOT_BEFORE NOT_AFTER /SUBJECT
# Dates must be in Go's 2006-01-02T15:04:05UTC format (no spaces).
for _cert in "$NEW_CA_DIR/signed/"*.pem; do
    [ -f "$_cert" ] || continue
    _subj=$(basename "$_cert" .pem)
    _ser=$(openssl x509 -noout -serial -in "$_cert" 2>/dev/null | cut -d= -f2) || continue
    _nb=$(date -u -d "$(openssl x509 -noout -startdate -in "$_cert" 2>/dev/null | sed 's/notBefore=//')" \
        '+%Y-%m-%dT%H:%M:%SUTC' 2>/dev/null) || continue
    _na=$(date -u -d "$(openssl x509 -noout -enddate -in "$_cert" 2>/dev/null | sed 's/notAfter=//')" \
        '+%Y-%m-%dT%H:%M:%SUTC' 2>/dev/null) || continue
    echo "$_ser $_nb $_na /$_subj" >> "$NEW_CA_DIR/inventory.txt"
done
_inv_lines=$(wc -l < "$NEW_CA_DIR/inventory.txt" 2>/dev/null) || _inv_lines=0
[ "$_inv_lines" -gt 0 ] \
    && pass "Import: inventory rebuilt with $_inv_lines entries" \
    || fail "Import: inventory rebuilt" "lines=$_inv_lines"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 4 -- Start puppet-ca with imported material
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 4 -- Start puppet-ca with imported CA\n'

puppet-ca --cadir "$NEW_CA_DIR" \
    --host 127.0.0.1 --port "$NEW_CA_PORT" \
    --no-tls-required \
    --autosign-config=true \
    >/dev/null 2>&1 &
_NEW_CA_PID=$!

_new_url="http://127.0.0.1:${NEW_CA_PORT}"
_new_ready=false
for _i in $(seq 1 60); do
    if curl -sf "${_new_url}/healthz/ready" -o /dev/null 2>/dev/null; then
        _new_ready=true; break
    fi
    sleep 0.3
done

if [ "$_new_ready" != "true" ]; then
    fail "puppet-ca starts with imported CA" "timed out waiting for health"
    printf '\n1..%d\n' "$T"
    printf '# Results: %d passed, %d failed out of %d\n' \
        $(( T - FAILURES )) "$FAILURES" "$T"
    exit 1
fi
pass "puppet-ca starts with imported CA"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 5 -- Verify the migrated CA works
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 5 -- Verify migrated CA\n'

# 5a: CA cert is fetchable from the new server.
_new_api_cert=$(curl -sf "${_new_url}/puppet-ca/v1/certificate/ca" 2>/dev/null) || true
echo "$_new_api_cert" | grep -qF "BEGIN CERTIFICATE" \
    && pass "New CA: API serves CA cert" \
    || fail "New CA: API serves CA cert"

# 5b: CA cert from new server matches the old one.
_new_api_fp=$(echo "$_new_api_cert" | openssl x509 -noout -fingerprint -sha256 2>/dev/null) || true
[ "$_old_ca_fp" = "$_new_api_fp" ] \
    && pass "New CA: API-served CA cert matches old CA fingerprint" \
    || fail "New CA: API-served CA cert matches old CA fingerprint" \
           "old=$_old_ca_fp new=$_new_api_fp"

# 5c: CRL is fetchable.
_new_crl=$(curl -sf "${_new_url}/puppet-ca/v1/certificate_revocation_list/ca" 2>/dev/null) || true
echo "$_new_crl" | grep -qF "BEGIN X509 CRL" \
    && pass "New CA: CRL fetchable" \
    || fail "New CA: CRL fetchable"

# 5d: The agent cert signed by the old CA is fetchable from the new server.
_migrated_cert=$(curl -sf \
    "${_new_url}/puppet-ca/v1/certificate/${_OLD_AGENT}" 2>/dev/null) || true
echo "$_migrated_cert" | grep -qF "BEGIN CERTIFICATE" \
    && pass "New CA: migrated agent cert fetchable by subject" \
    || fail "New CA: migrated agent cert fetchable by subject"

# 5e: The fetched cert fingerprint matches the original.
_migrated_fp=$(echo "$_migrated_cert" | openssl x509 -noout -fingerprint -sha256 2>/dev/null) || true
[ "$_old_agent_fp" = "$_migrated_fp" ] \
    && pass "New CA: migrated cert fingerprint matches original" \
    || fail "New CA: migrated cert fingerprint matches original" \
           "old=$_old_agent_fp new=$_migrated_fp"

# 5f: At least one pre-existing cert from the old CA is fetchable.
# The old Puppet Server's own cert may or may not be in the CA's signed/
# directory (depends on VoxPupuli version), so check the first cert we
# copied rather than hardcoding "old-puppet".
_old_pre_existing=$(basename "$(ls "$NEW_CA_DIR/signed/"*.pem 2>/dev/null | grep -v "${_OLD_AGENT}" | head -1)" .pem 2>/dev/null) || true
if [ -n "$_old_pre_existing" ]; then
    _old_server_cert=$(curl -sf \
        "${_new_url}/puppet-ca/v1/certificate/${_old_pre_existing}" 2>/dev/null) || true
    echo "$_old_server_cert" | grep -qF "BEGIN CERTIFICATE" \
        && pass "New CA: pre-existing old cert (${_old_pre_existing}) fetchable" \
        || fail "New CA: pre-existing old cert (${_old_pre_existing}) fetchable"
else
    pass "New CA: no pre-existing old certs to check (only agent cert)"
fi

# 5g: puppet-ca-ctl list shows the migrated certs.
_new_list=$(puppet-ca-ctl --server-url "$_new_url" list --all 2>/dev/null) || true
echo "$_new_list" | grep -qF "${_OLD_AGENT}" \
    && pass "New CA: puppet-ca-ctl list shows migrated agent cert" \
    || fail "New CA: puppet-ca-ctl list shows migrated agent cert" "output: $_new_list"

# ═════════════════════════════════════════════════════════════════════════════
# Phase 6 -- Sign new certs, revoke migrated certs
# ═════════════════════════════════════════════════════════════════════════════
printf '\n# Phase 6 -- New signing and revocation on migrated CA\n'

# 6a: Submit and autosign a brand-new CSR on the migrated CA.
_NEW_AGENT="mig-newagent-${RUN_ID}"
openssl genrsa -out "$WORK_DIR/new-agent.key" 2048 2>/dev/null
openssl req -new \
    -key "$WORK_DIR/new-agent.key" \
    -subj "/CN=${_NEW_AGENT}" \
    -out "$WORK_DIR/new-agent.csr" 2>/dev/null

curl -s -o /dev/null \
    -X PUT -H "Content-Type: text/plain" \
    --data-binary @"$WORK_DIR/new-agent.csr" \
    "${_new_url}/puppet-ca/v1/certificate_request/${_NEW_AGENT}" 2>/dev/null || true

_new_agent_cert=$(curl -sf \
    "${_new_url}/puppet-ca/v1/certificate/${_NEW_AGENT}" 2>/dev/null) || true
echo "$_new_agent_cert" | grep -qF "BEGIN CERTIFICATE" \
    && pass "New CA: fresh cert signed by migrated CA" \
    || fail "New CA: fresh cert signed by migrated CA"

# 6b: New cert verifies against the imported (old) CA cert.
echo "$_new_agent_cert" > "$WORK_DIR/new-agent.crt"
openssl verify -CAfile "$NEW_CA_DIR/ca_crt.pem" "$WORK_DIR/new-agent.crt" >/dev/null 2>&1 \
    && pass "New CA: fresh cert chains to imported CA" \
    || fail "New CA: fresh cert chains to imported CA"

# 6c: Revoke the migrated agent cert.
_rev_st=$(curl -s -o /dev/null -w '%{http_code}' \
    -X PUT -H "Content-Type: application/json" \
    -d '{"desired_state":"revoked"}' \
    "${_new_url}/puppet-ca/v1/certificate_status/${_OLD_AGENT}" 2>/dev/null) || true
[[ "$_rev_st" =~ ^2 ]] \
    && pass "New CA: revoke migrated agent cert returns 2xx" \
    || fail "New CA: revoke migrated agent cert returns 2xx" "got HTTP $_rev_st"

# 6d: Verify the cert status shows 'revoked'.
_rev_status=$(curl -sf \
    "${_new_url}/puppet-ca/v1/certificate_status/${_OLD_AGENT}" 2>/dev/null) || true
echo "$_rev_status" | grep -qF '"revoked"' \
    && pass "New CA: migrated cert status shows 'revoked'" \
    || fail "New CA: migrated cert status shows 'revoked'" "status: $_rev_status"

# 6e: CRL now contains the revoked serial.
_crl_after=$(curl -sf "${_new_url}/puppet-ca/v1/certificate_revocation_list/ca" 2>/dev/null) || true
_crl_text=$(echo "$_crl_after" | openssl crl -text -noout 2>/dev/null) || true
echo "$_crl_text" | grep -qi "Revoked Certificates" \
    && pass "New CA: CRL shows revoked certificates" \
    || fail "New CA: CRL shows revoked certificates"

# 6f: Clean the revoked cert (puppet cert clean equivalent).
_clean_st=$(curl -s -o /dev/null -w '%{http_code}' \
    -X DELETE \
    "${_new_url}/puppet-ca/v1/certificate_status/${_OLD_AGENT}" 2>/dev/null) || true
[[ "$_clean_st" =~ ^2 ]] \
    && pass "New CA: clean migrated cert returns 2xx" \
    || fail "New CA: clean migrated cert returns 2xx" "got HTTP $_clean_st"

# 6g: After clean, the cert should be gone (404).
_gone_st=$(curl -s -o /dev/null -w '%{http_code}' \
    "${_new_url}/puppet-ca/v1/certificate/${_OLD_AGENT}" 2>/dev/null) || true
[ "$_gone_st" = "404" ] \
    && pass "New CA: cleaned cert returns 404" \
    || fail "New CA: cleaned cert returns 404" "got HTTP $_gone_st"

# 6h: The newly signed cert is still accessible.
_still_there=$(curl -sf \
    "${_new_url}/puppet-ca/v1/certificate/${_NEW_AGENT}" 2>/dev/null) || true
echo "$_still_there" | grep -qF "BEGIN CERTIFICATE" \
    && pass "New CA: fresh cert still accessible after migration cleanup" \
    || fail "New CA: fresh cert still accessible after migration cleanup"

# ═════════════════════════════════════════════════════════════════════════════
# Results
# ═════════════════════════════════════════════════════════════════════════════
printf '\n1..%d\n' "$T"
printf '# Results: %d passed, %d failed out of %d\n' \
    $(( T - FAILURES )) "$FAILURES" "$T"

[ "$FAILURES" -eq 0 ]
