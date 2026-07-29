# Migrating from OpenVox Server (or Puppet Server) to openvox-ca

This guide walks through replacing the certificate authority built into OpenVox
Server (or Puppet Server) with `openvox-ca`. The Go CA uses the same HTTP API
and a compatible flat-file layout, so existing agents continue to work without
reconfiguration, provided the CA hostname and port stay the same.

OpenVox Server is the Vox Pupuli fork of Puppet Server and keeps the same
`/etc/puppetlabs` paths and `puppetserver` command, so the steps below apply to
both; where a path or command is shown, it is identical on each.

## Prerequisites

- `openvox-ca` and `openvox-ca-ctl` binaries built and installed
- Access to the existing OpenVox/Puppet Server CA directory
  (typically `/etc/puppetlabs/puppet/ssl` or `/etc/puppetlabs/puppetserver/ca`)
- Maintenance window: agents cannot sign new certs during migration

## Quick overview

```
1. Back up the existing CA directory
2. Import the CA cert, key, and CRL into a new openvox-ca directory
3. Copy signed certificates and inventory
4. Disable the built-in CA in OpenVox Server
5. Start openvox-ca
6. Verify agent connectivity
```

## Step 1: Back up the existing CA

```bash
PUPPET_SSL=/etc/puppetlabs/puppet/ssl
BACKUP_DIR=/root/openvox-ca-backup-$(date +%Y%m%d)

cp -a "$PUPPET_SSL" "$BACKUP_DIR"
echo "Backed up to $BACKUP_DIR"
```

## Step 2: Identify your CA files

OpenVox Server (and Puppet Server) store CA material in one of two locations
depending on version:

| Version | CA directory |
| --- | --- |
| OpenVox / Puppet Server 6+ (monolithic) | `/etc/puppetlabs/puppet/ssl/ca/` |
| OpenVox / Puppet Server 6+ (external CA) | `/etc/puppetlabs/puppetserver/ca/` |
| Older Puppet | `/var/lib/puppet/ssl/ca/` |

Find your CA cert and key:

```bash
# Typical locations -- adjust for your installation
CA_CERT="$PUPPET_SSL/ca/ca_crt.pem"
CA_KEY="$PUPPET_SSL/ca/ca_key.pem"
CA_CRL="$PUPPET_SSL/ca/ca_crl.pem"

# Verify they exist and the key matches the cert
openssl x509 -noout -modulus -in "$CA_CERT" | md5sum
openssl rsa  -noout -modulus -in "$CA_KEY"  | md5sum
# Both MD5 sums must match
```

## Step 3: Import the CA

```bash
NEW_CADIR=/etc/puppet-ca/ssl

openvox-ca-ctl import \
  --cadir       "$NEW_CADIR" \
  --cert-bundle "$CA_CERT" \
  --private-key "$CA_KEY" \
  --crl-chain   "$CA_CRL"

echo "CA imported into $NEW_CADIR"
```

`--crl-chain` accepts a multi-CRL bundle in any order. Every `X509 CRL` block must
parse, or the whole import is refused; PEM blocks of other types are ignored and
are not stored, because the blob is served
to every agent and Puppet's default `certificate_revocation = chain` makes an
agent parse all of it.

This CA's own CRL is moved to the front, since every reader takes the first
block as ours, and every other CRL is preserved through subsequent re-signing —
so `certificate_revocation = chain` keeps working after a revocation or a CRL
refresh. Which CRL is "ours" is decided by verifying the signature against this
CA's certificate, not by comparing issuer names or key identifiers: a CRL from
`openssl ca -gencrl` carries no Authority Key Identifier under the stock
`openssl.cnf`, and a shared root can issue two sub-CAs with the same name. If
the bundle contains no CRL signed by this CA, the one already in storage is kept
at the front, and only if there is none is an empty CRL generated. That makes
re-running the import with a newer ancestor bundle the way to refresh ancestor
CRLs today, without exporting and concatenating your own first.

Some limits worth knowing before you rely on re-import as a refresh mechanism.

**The bundle replaces the stored ancestor set wholesale.** Only *this CA's own*
CRL is recovered from storage; ancestors are taken solely from what you supply.
So a refresh bundle must contain **every** ancestor CRL, not just the one that
changed — supplying a new root CRL alone drops the intermediate's, which is
exactly the loss this preservation exists to prevent. (Re-*signing* preserves
ancestors; importing replaces them. The two paths differ deliberately: the file
you hand to `import` is authoritative.)

**Ancestor CRLs age in place.** This CA cannot re-sign another CA's list, so
whatever was imported stays until something replaces it, and it must be replaced
before its own `nextUpdate` lapses. Nothing alerts on this — see
[the metrics reference](metrics.md#crl) — so track those deadlines out of band.

**`import` writes to a local filesystem directory only.** It takes `--cadir` and
constructs filesystem storage directly; unlike `migrate` it has no
`--source-config`/`--dest-config`. If your CA runs on **sqlite, postgres, mysql,
etcd or redis**, re-importing writes to a directory the server never reads,
prints `CA imported into <dir>`, and changes nothing — the live chain expires
anyway. (SQLite is in that list: it keeps the CRL in its database file, so a
cadir-based import misses it exactly as a networked backend does. See
[storage backends](storage-backends.md).)

On those backends the refresh is a round trip with the CA stopped, and the
return leg needs `--force` because the destination still holds a CA
certificate. **Back up the destination first** — `migrate` is not
transactional, and the write-back covers the cert, key, inventory, inventory
HMAC and every signed certificate in order to refresh one PEM blob:

`scratch.yaml` must describe a **filesystem** backend whose `cadir` is the same
directory the middle step passes to `--cadir`. `migrate` resolves its destination
from that file; `import` resolves its own from the flag. If the two disagree,
all three commands exit 0 and print success while the middle step writes
somewhere the third never reads — the same silent no-op described above,
reintroduced inside the workaround for it. The scratch directory must also start
empty, or the first leg needs `--force` as well.

```bash
# scratch.yaml: storage_backend: filesystem, cadir: /tmp/scratch
openvox-ca-ctl migrate --source-config live.yaml --dest-config scratch.yaml

# --cert-bundle and --private-key are the copies the first leg just wrote there.
openvox-ca-ctl import --cadir /tmp/scratch \
  --cert-bundle /tmp/scratch/ca_crt.pem \
  --private-key /tmp/scratch/private/ca_key.pem \
  --crl-chain refreshed-chain.pem

openvox-ca-ctl migrate --source-config scratch.yaml --dest-config live.yaml --force
```

On the **filesystem** backend `import` does write where the server reads, but
stop the CA anyway: `import` takes the CRL lock, and that lock is only
cross-process on backends that implement one — filesystem and sqlite both fall
back to a mutex inside each process.

**Re-import rewrites the CA key, so two custody modes cannot use it.** `import`
writes whatever `--private-key` holds, and offers no encryption flags. Under
`encrypt_ca_key` the stored key is an `ENCRYPTED PRIVATE KEY` block that
`import` cannot parse, so feeding it back fails — and feeding the original
plaintext key instead succeeds while silently replacing the encrypted at-rest
key with a plaintext one, because key loading accepts both forms and nothing
warns. Under `ca_key_provider: openbao` there is no exportable key at all, so
re-import is unavailable outright. Neither mode has another ancestor-refresh
mechanism today.

**An older replica still flattens the chain.** A build from before this change
rewrites the stored blob as a single block, so one un-upgraded replica handling
one revocation drops the ancestors for everyone. Complete the rollout before
importing a chain.

Re-import is also not signalled to consumers: the Kubernetes exporter republishes
on CRL notifications, which the import path deliberately does not send. After a
live ancestor refresh, run `openvox-ca-ctl reissue-crl` or restart to republish
the exported copies.

The `import` command creates the directory structure, writes the CA cert/key/CRL, and
initialises `inventory.txt` and `serial` (the serial file is written for compatibility but is not used at runtime; openvox-ca generates random serial numbers).

## Step 4: Copy signed certificates

The `import` command only brings in the CA material. Existing signed
certificates must be copied separately so agents can fetch their certs
from the new CA.

```bash
# Puppet Server stores signed certs in ca/signed/ or certs/
# openvox-ca stores them in <cadir>/signed/
OLD_SIGNED="$PUPPET_SSL/ca/signed"

if [ -d "$OLD_SIGNED" ]; then
    cp "$OLD_SIGNED"/*.pem "$NEW_CADIR/signed/"
    echo "Copied $(ls "$NEW_CADIR/signed/" | wc -l) signed certificates"
fi
```

## Step 5: Rebuild the inventory

openvox-ca tracks signed certificates in `inventory.txt`. After copying
certs, rebuild it from the signed certificate files:

```bash
> "$NEW_CADIR/inventory.txt"  # truncate

for cert in "$NEW_CADIR/signed/"*.pem; do
    [ -f "$cert" ] || continue
    subject=$(basename "$cert" .pem)
    serial=$(openssl x509 -noout -serial -in "$cert" | cut -d= -f2)
    not_before=$(openssl x509 -noout -startdate -in "$cert" \
        | sed 's/notBefore=//' \
        | date -f- -u +%Y-%m-%dT%H:%M:%SUTC 2>/dev/null || echo "unknown")
    not_after=$(openssl x509 -noout -enddate -in "$cert" \
        | sed 's/notAfter=//' \
        | date -f- -u +%Y-%m-%dT%H:%M:%SUTC 2>/dev/null || echo "unknown")
    echo "$serial $not_before $not_after /$subject" >> "$NEW_CADIR/inventory.txt"
done

echo "Inventory rebuilt with $(wc -l < "$NEW_CADIR/inventory.txt") entries"
```

## Step 6: Disable the built-in CA

In OpenVox Server's (or Puppet Server's) service configuration, replace the CA
service with the disabled stub:

```bash
# OpenVox / Puppet Server 7+ uses services.d/ca.cfg
CA_CFG=/etc/puppetlabs/puppetserver/services.d/ca.cfg
[ -f "$CA_CFG" ] || CA_CFG=/etc/puppetlabs/puppetserver/bootstrap.cfg

sed -i \
  's|certificate-authority-service/certificate-authority-service|certificate-authority-disabled-service/certificate-authority-disabled-service|g' \
  "$CA_CFG"
```

Configure `puppet.conf` to point to the external CA:

```ini
[main]
ca_server = openvox-ca.example.com
ca_port   = 8140
```

## Step 7: Start openvox-ca

First, generate a TLS server certificate for openvox-ca itself:

```bash
openvox-ca-ctl generate \
  --server-url http://127.0.0.1:8140 \
  --certname   openvox-ca.example.com

# Or, if you prefer a DNS SAN for the old puppet-master hostname:
openvox-ca-ctl generate \
  --server-url http://127.0.0.1:8140 \
  --certname   openvox-ca.example.com \
  --dns        puppet-master.example.com
```

> **Note:** `generate` requires a running openvox-ca instance. Start it
> temporarily on loopback without TLS, generate the cert, then restart
> with TLS:

```bash
# Temporary start (loopback only, no TLS)
openvox-ca --cadir "$NEW_CADIR" --host 127.0.0.1 --port 8140 &
PCA_PID=$!
sleep 2

openvox-ca-ctl generate \
  --server-url http://127.0.0.1:8140 \
  --certname   openvox-ca.example.com

kill $PCA_PID; wait $PCA_PID 2>/dev/null

# Production start with TLS
openvox-ca \
  --cadir    "$NEW_CADIR" \
  --hostname openvox-ca.example.com \
  --tls-cert "$NEW_CADIR/signed/openvox-ca.example.com.pem" \
  --tls-key  "$NEW_CADIR/private/openvox-ca.example.com_key.pem" \
  --puppet-server puppet-master.example.com
```

If migrating in-place (same hostname and port), agents will connect to the
new CA without any reconfiguration.

## Step 8: Verify

```bash
# Check the CA is serving
curl -sfk https://openvox-ca.example.com:8140/puppet-ca/v1/certificate/ca | head -1

# List all certificates
openvox-ca-ctl \
  --server-url https://openvox-ca.example.com:8140 \
  --ca-cert "$NEW_CADIR/ca_crt.pem" \
  list --all

# Run a puppet agent to verify connectivity
puppet agent --test --noop
```

## Directory layout mapping

| OpenVox / Puppet Server | openvox-ca | Notes |
| --- | --- | --- |
| `ssl/ca/ca_crt.pem` | `<cadir>/ca_crt.pem` | Same filename |
| `ssl/ca/ca_key.pem` | `<cadir>/private/ca_key.pem` | Moved into `private/` |
| `ssl/ca/ca_crl.pem` | `<cadir>/ca_crl.pem` | Same filename |
| `ssl/ca/signed/*.pem` | `<cadir>/signed/*.pem` | Same structure |
| `ssl/ca/inventory.txt` | `<cadir>/inventory.txt` | Same format |
| `ssl/ca/serial` | (not used) | openvox-ca uses random 128-bit serials |
| `ssl/certificate_requests/*.pem` | `<cadir>/requests/*.pem` | Directory renamed |
| `ssl/certs/ca.pem` | (not needed) | Symlink; agents fetch CA cert via API |
| `ssl/crl.pem` | (not needed) | Symlink; agents fetch CRL via API |

## CLI command mapping

| Puppet / puppetserver ca | openvox-ca-ctl | Notes |
| --- | --- | --- |
| `puppet cert list` | `openvox-ca-ctl list` | Pending CSRs |
| `puppet cert list --all` | `openvox-ca-ctl list --all` | All certs |
| `puppet cert sign <name>` | `openvox-ca-ctl sign --certname <name>` | |
| `puppet cert sign --all` | `openvox-ca-ctl sign --all` | |
| `puppet cert revoke <name>` | `openvox-ca-ctl revoke --certname <name>` | |
| `puppet cert clean <name>` | `openvox-ca-ctl clean --certname <name>` | Revoke + delete |
| `puppetserver ca setup` | `openvox-ca-ctl setup --cadir <path>` | |
| `puppetserver ca import` | `openvox-ca-ctl import --cadir <path> ...` | |
| `puppetserver ca generate` | `openvox-ca-ctl generate --certname <name>` | |

## Differences to be aware of

### Serial numbers

openvox-ca uses cryptographically random 128-bit serial numbers instead of
sequential integers. This is a security improvement (CA/Browser Forum
guidance) but means serial numbers will look different from what you're
used to. The `serial` file from old Puppet CAs is ignored.

### Auth-arc OID stripping

openvox-ca strips Puppet authorization-arc OIDs (`1.3.6.1.4.1.34380.1.3.*`)
from CSRs during signing as a security measure to prevent privilege
escalation. This means you cannot create admin certificates (with
`pp_cli_auth`) by submitting a CSR through the API.

To create admin certificates with `pp_cli_auth`, sign them directly using
the CA key with openssl:

```bash
# Generate key and CSR with pp_cli_auth extension
openssl genrsa -out admin.key 2048
cat > admin.cnf <<EOF
[req]
distinguished_name = dn
req_extensions     = v3_req
prompt             = no
[dn]
CN = admin-tool
[v3_req]
1.3.6.1.4.1.34380.1.3.39 = DER:0c:04:74:72:75:65
EOF
openssl req -new -key admin.key -config admin.cnf -out admin.csr

# Sign directly with the CA key
cat > admin_ext.cnf <<EOF
1.3.6.1.4.1.34380.1.3.39 = DER:0c:04:74:72:75:65
EOF
openssl x509 -req \
  -in admin.csr \
  -CA <cadir>/ca_crt.pem \
  -CAkey <cadir>/private/ca_key.pem \
  -CAcreateserial \
  -days 365 \
  -extfile admin_ext.cnf \
  -out admin.crt
```

Alternatively, use the `--puppet-server` flag to grant admin access by CN
without needing the `pp_cli_auth` extension at all.

### No `puppet cert` compatibility shim

openvox-ca does not accept `puppet cert` command syntax directly. Use
`openvox-ca-ctl` instead (see the CLI command mapping table above). The HTTP
API is fully compatible; only the CLI tool name and flag syntax differ.

### Agent configuration

If openvox-ca runs on the same hostname and port as the old CA, agents need
no configuration changes. If the hostname changes, update `ca_server` in
each agent's `puppet.conf`:

```ini
[main]
ca_server = new-ca-hostname.example.com
```

## Rollback

If something goes wrong, restore from backup:

```bash
# Stop openvox-ca
systemctl stop openvox-ca  # or kill the process

# Restore the old CA directory
cp -a "$BACKUP_DIR" "$PUPPET_SSL"

# Re-enable the built-in CA in OpenVox Server (or Puppet Server)
sed -i \
  's|certificate-authority-disabled-service/certificate-authority-disabled-service|certificate-authority-service/certificate-authority-service|g' \
  /etc/puppetlabs/puppetserver/services.d/ca.cfg

# Restart the server
systemctl restart puppetserver
```
