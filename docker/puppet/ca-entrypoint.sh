#!/bin/bash
# Two-phase entrypoint for openvox-ca in the Puppet stack.
#
# Phase 1: Start CA on loopback (plain HTTP) to bootstrap a TLS cert for the
#           "openvox-ca" service hostname.
# Phase 2: Restart CA on all interfaces with TLS using the generated cert.
#
# This ensures that all inter-service traffic to the CA uses genuine TLS with
# verifiable hostname matching, rather than a self-signed CA cert whose CN
# ("Puppet CA: <hostname>") would not match the service DNS name.

set -euo pipefail

CA_DIR=/data
TLS_CERT="${CA_DIR}/signed/openvox-ca.pem"
TLS_KEY="${CA_DIR}/private/openvox-ca_key.pem"

# Write the puppet-server admin allow file.  Using --puppet-server-file
# (rather than --puppet-server) exercises the file-based CN allow list in the
# integration stack so it is tested end-to-end alongside the inline flag.
SERVERS_FILE=/etc/puppet-ca/servers.txt
mkdir -p "$(dirname "$SERVERS_FILE")"
cat > "$SERVERS_FILE" <<'EOF'
# Puppet server CNs allowed CA admin access.
# One CN per line; # comments and blank lines are ignored.
puppet-master
EOF

# Phase 2 passthrough: if the TLS cert was already generated (e.g. container
# restart), skip directly to the real CA startup.
if [ -s "${TLS_CERT}" ] && [ -s "${TLS_KEY}" ]; then
    echo "TLS cert already exists -- starting CA with TLS."
    exec /usr/local/bin/openvox-ca \
        --cadir="${CA_DIR}" \
        --hostname=openvox-ca \
        --autosign-config=true \
        --tls-cert="${TLS_CERT}" \
        --tls-key="${TLS_KEY}" \
        --puppet-server-file="${SERVERS_FILE}" \
        "$@"
fi

# -- Phase 1: bootstrap CA on loopback --------------------------------------
echo "Phase 1: bootstrapping CA on loopback to generate TLS cert..."
/usr/local/bin/openvox-ca \
    --cadir="${CA_DIR}" \
    --hostname=openvox-ca \
    --host=127.0.0.1 \
    --autosign-config=true &
PHASE1_PID=$!

# Wait for the loopback CA to accept connections.
echo "Waiting for loopback CA..."
for _i in $(seq 1 30); do
    if curl -sf http://127.0.0.1:8140/puppet-ca/v1/certificate/ca > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

if ! curl -sf http://127.0.0.1:8140/puppet-ca/v1/certificate/ca > /dev/null 2>&1; then
    echo "ERROR: loopback CA did not start in time." >&2
    kill "${PHASE1_PID}" 2>/dev/null || true
    exit 1
fi
echo "Loopback CA is ready."

# Generate an RSA key + certificate for the "openvox-ca" service hostname.
# The server saves the cert to signed/openvox-ca.pem and the key to
# private/openvox-ca_key.pem; openvox-ca-ctl also writes the key to --out-dir.
echo "Generating TLS cert for openvox-ca service hostname..."
/usr/local/bin/openvox-ca-ctl \
    --server-url http://127.0.0.1:8140 \
    generate \
    --certname openvox-ca \
    --dns openvox-ca,localhost \
    --out-dir "${CA_DIR}/private"

# Verify both files were written before proceeding to Phase 2.
if [ ! -s "${TLS_CERT}" ] || [ ! -s "${TLS_KEY}" ]; then
    echo "ERROR: TLS cert (${TLS_CERT}) or key (${TLS_KEY}) missing after generate." >&2
    kill "${PHASE1_PID}" 2>/dev/null || true
    exit 1
fi
chmod 644 "${TLS_CERT}"
chmod 640 "${TLS_KEY}"
echo "TLS cert generated at ${TLS_CERT}"

# Stop the Phase 1 loopback CA gracefully.
kill "${PHASE1_PID}" 2>/dev/null || true
wait "${PHASE1_PID}" 2>/dev/null || true

# -- Phase 2: start CA with TLS on all interfaces ----------------------------
echo "Phase 2: starting CA with TLS on all interfaces..."
exec /usr/local/bin/openvox-ca \
    --cadir="${CA_DIR}" \
    --hostname=openvox-ca \
    --autosign-config=true \
    --tls-cert="${TLS_CERT}" \
    --tls-key="${TLS_KEY}" \
    --puppet-server-file="${SERVERS_FILE}" \
    "$@"
