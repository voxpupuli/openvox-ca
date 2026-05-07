#!/bin/bash
# Two-phase entrypoint for puppet-ca when its storage backend is Redis/Valkey.
#
# Differs from ca-entrypoint.sh in two ways:
#   1. Waits for the Redis service before starting the CA, so Phase 1 does
#      not race the redis container's healthcheck.
#   2. Captures the TLS service certificate from `puppet-ca-ctl generate`
#      stdout (filesystem backend stores it under <cadir>/signed/<name>.pem
#      where the original entrypoint reads it; with the Redis backend that
#      blob lives in Redis, not on disk).
#
# Phase 1: Start CA on loopback (plain HTTP) to bootstrap a TLS cert for the
#           "puppet-ca" service hostname. Storage backend = Redis.
# Phase 2: Restart CA on all interfaces with TLS using the generated cert.

set -euo pipefail

CA_DIR=/data
# Each replica gets its own service-cert subject so they can be addressed
# individually for direct-replica tests, while sharing the same CA identity
# (CA cert/key) via the shared Redis backend. PUPPET_CA_HOSTNAME defaults to
# "puppet-ca" for the single-replica case.
HOSTNAME_FOR_TLS="${PUPPET_CA_HOSTNAME:-puppet-ca}"
DNS_ALT_NAMES="${PUPPET_CA_DNS_ALT_NAMES:-${HOSTNAME_FOR_TLS},localhost}"
TLS_CERT="${CA_DIR}/signed/${HOSTNAME_FOR_TLS}.pem"
TLS_KEY="${CA_DIR}/private/${HOSTNAME_FOR_TLS}_key.pem"

mkdir -p "$(dirname "${TLS_CERT}")" "$(dirname "${TLS_KEY}")"

# Write the puppet-server admin allow file. Same content as the filesystem
# variant so the integration test suite is identical aside from the backend.
SERVERS_FILE=/etc/puppet-ca/servers.txt
mkdir -p "$(dirname "$SERVERS_FILE")"
cat > "$SERVERS_FILE" <<EOF
# Puppet server CNs allowed CA admin access.
# One CN per line; # comments and blank lines are ignored.
puppet-master
EOF
# Authorise sibling CA replicas so they can call admin endpoints on each other
# during integration tests (e.g. reading certificate_status). Each replica's
# service cert CN is its own hostname.
if [ -n "${PUPPET_CA_PEER_HOSTNAMES:-}" ]; then
    for _peer in $(printf '%s' "${PUPPET_CA_PEER_HOSTNAMES}" | tr ',' ' '); do
        printf '%s\n' "$_peer" >> "$SERVERS_FILE"
    done
fi

# -- Wait for Redis to accept connections -----------------------------------
# The CA's own Redis client retries internally, but waiting here gives a
# clearer log line and a definite failure mode if the redis container fails
# to come up at all.
REDIS_HOST="${PUPPET_CA_REDIS_HOST:-redis}"
REDIS_PORT="${PUPPET_CA_REDIS_PORT:-6379}"
echo "Waiting for Redis at ${REDIS_HOST}:${REDIS_PORT}..."
for _i in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/${REDIS_HOST}/${REDIS_PORT}") 2>/dev/null; then
        exec 3<&-
        exec 3>&-
        echo "Redis is reachable."
        break
    fi
    sleep 1
done
if ! (exec 3<>"/dev/tcp/${REDIS_HOST}/${REDIS_PORT}") 2>/dev/null; then
    echo "ERROR: Redis at ${REDIS_HOST}:${REDIS_PORT} did not become reachable." >&2
    exit 1
fi
exec 3<&- 2>/dev/null || true
exec 3>&- 2>/dev/null || true

# Phase 2 passthrough: if a previous start already wrote the TLS cert/key to
# disk (e.g. container restart with persistent /data volume), skip Phase 1.
# The CA blobs in Redis survive across restarts independently.
if [ -s "${TLS_CERT}" ] && [ -s "${TLS_KEY}" ]; then
    echo "TLS cert already exists -- starting CA with TLS."
    exec /usr/local/bin/puppet-ca \
        --cadir="${CA_DIR}" \
        --hostname="${HOSTNAME_FOR_TLS}" \
        --autosign-config=true \
        --tls-cert="${TLS_CERT}" \
        --tls-key="${TLS_KEY}" \
        --puppet-server-file="${SERVERS_FILE}" \
        "$@"
fi

# -- Phase 1: bootstrap CA on loopback --------------------------------------
echo "Phase 1: bootstrapping CA on loopback to generate TLS cert..."
/usr/local/bin/puppet-ca \
    --cadir="${CA_DIR}" \
    --hostname="${HOSTNAME_FOR_TLS}" \
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

# Generate an RSA key + certificate for the "puppet-ca" service hostname.
# Unlike the filesystem-backend entrypoint, we capture the certificate from
# puppet-ca-ctl's stdout: with the Redis backend the cert is stored in Redis,
# not under <cadir>/signed/. The private key is still written locally to
# --out-dir because per-subject private keys remain on the local disk.
echo "Generating TLS cert for ${HOSTNAME_FOR_TLS} service hostname..."
/usr/local/bin/puppet-ca-ctl \
    --server-url http://127.0.0.1:8140 \
    generate \
    --certname "${HOSTNAME_FOR_TLS}" \
    --dns "${DNS_ALT_NAMES}" \
    --out-dir "${CA_DIR}/private" \
    > "${TLS_CERT}"

# Verify both files were written before proceeding to Phase 2.
if [ ! -s "${TLS_CERT}" ] || [ ! -s "${TLS_KEY}" ]; then
    echo "ERROR: TLS cert (${TLS_CERT}) or key (${TLS_KEY}) missing after generate." >&2
    kill "${PHASE1_PID}" 2>/dev/null || true
    exit 1
fi
chmod 644 "${TLS_CERT}"
chmod 640 "${TLS_KEY}"
echo "TLS cert generated at ${TLS_CERT} (cert blob also persisted in Redis)"

# Stop the Phase 1 loopback CA gracefully.
kill "${PHASE1_PID}" 2>/dev/null || true
wait "${PHASE1_PID}" 2>/dev/null || true

# -- Phase 2: start CA with TLS on all interfaces ----------------------------
echo "Phase 2: starting CA with TLS on all interfaces (storage backend = redis)..."
exec /usr/local/bin/puppet-ca \
    --cadir="${CA_DIR}" \
    --hostname="${HOSTNAME_FOR_TLS}" \
    --autosign-config=true \
    --tls-cert="${TLS_CERT}" \
    --tls-key="${TLS_KEY}" \
    --puppet-server-file="${SERVERS_FILE}" \
    "$@"
