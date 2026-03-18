# Migrating from Puppet Server CA to puppet-ca

This guide walks through replacing Puppet Server's built-in CA with `puppet-ca`.
The Go CA uses the same HTTP API and a compatible flat-file layout, so existing
agents continue to work without reconfiguration — provided the CA hostname and
port stay the same.

## Prerequisites

- `puppet-ca` and `puppet-ca-ctl` binaries built and installed
- Access to the existing Puppet Server CA directory
  (typically `/etc/puppetlabs/puppet/ssl` or `/etc/puppetlabs/puppetserver/ca`)
- Maintenance window — agents cannot sign new certs during migration

## Quick overview

```
1. Back up the existing CA directory
2. Import the CA cert, key, and CRL into a new puppet-ca directory
3. Copy signed certificates and inventory
4. Disable the built-in CA in Puppet Server
5. Start puppet-ca
6. Verify agent connectivity
```

## Step 1: Back up the existing CA

```bash
PUPPET_SSL=/etc/puppetlabs/puppet/ssl
BACKUP_DIR=/root/puppet-ca-backup-$(date +%Y%m%d)

cp -a "$PUPPET_SSL" "$BACKUP_DIR"
echo "Backed up to $BACKUP_DIR"
```

## Step 2: Identify your CA files

Puppet Server stores CA material in one of two locations depending on version:

| Version | CA directory |
|---------|-------------|
| Puppet Server 6+ (monolithic) | `/etc/puppetlabs/puppet/ssl/ca/` |
| Puppet Server 6+ (external CA) | `/etc/puppetlabs/puppetserver/ca/` |
| Older Puppet | `/var/lib/puppet/ssl/ca/` |

Find your CA cert and key:

```bash
# Typical locations — adjust for your installation
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

puppet-ca-ctl import \
  --cadir       "$NEW_CADIR" \
  --cert-bundle "$CA_CERT" \
  --private-key "$CA_KEY" \
  --crl-chain   "$CA_CRL"

echo "CA imported into $NEW_CADIR"
```

This creates the directory structure, writes the CA cert/key/CRL, and
initialises `inventory.txt` and `serial` (the serial file is written for compatibility but is not used at runtime — puppet-ca generates random serial numbers).

## Step 4: Copy signed certificates

The `import` command only brings in the CA material. Existing signed
certificates must be copied separately so agents can fetch their certs
from the new CA.

```bash
# Puppet Server stores signed certs in ca/signed/ or certs/
# puppet-ca stores them in <cadir>/signed/
OLD_SIGNED="$PUPPET_SSL/ca/signed"

if [ -d "$OLD_SIGNED" ]; then
    cp "$OLD_SIGNED"/*.pem "$NEW_CADIR/signed/"
    echo "Copied $(ls "$NEW_CADIR/signed/" | wc -l) signed certificates"
fi
```

## Step 5: Rebuild the inventory

puppet-ca tracks signed certificates in `inventory.txt`. After copying
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

## Step 6: Disable the built-in Puppet CA

In Puppet Server's service configuration, replace the CA service with the
disabled stub:

```bash
# Puppet Server 7+ uses services.d/ca.cfg
CA_CFG=/etc/puppetlabs/puppetserver/services.d/ca.cfg
[ -f "$CA_CFG" ] || CA_CFG=/etc/puppetlabs/puppetserver/bootstrap.cfg

sed -i \
  's|certificate-authority-service/certificate-authority-service|certificate-authority-disabled-service/certificate-authority-disabled-service|g' \
  "$CA_CFG"
```

Configure `puppet.conf` to point to the external CA:

```ini
[main]
ca_server = puppet-ca.example.com
ca_port   = 8140
```

## Step 7: Start puppet-ca

First, generate a TLS server certificate for puppet-ca itself:

```bash
puppet-ca-ctl generate \
  --server-url http://127.0.0.1:8140 \
  --certname   puppet-ca.example.com

# Or, if you prefer a DNS SAN for the old puppet-master hostname:
puppet-ca-ctl generate \
  --server-url http://127.0.0.1:8140 \
  --certname   puppet-ca.example.com \
  --dns        puppet-master.example.com
```

> **Note:** `generate` requires a running puppet-ca instance. Start it
> temporarily on loopback without TLS, generate the cert, then restart
> with TLS:

```bash
# Temporary start (loopback only, no TLS)
puppet-ca --cadir "$NEW_CADIR" --host 127.0.0.1 --port 8140 &
PCA_PID=$!
sleep 2

puppet-ca-ctl generate \
  --server-url http://127.0.0.1:8140 \
  --certname   puppet-ca.example.com

kill $PCA_PID; wait $PCA_PID 2>/dev/null

# Production start with TLS
puppet-ca \
  --cadir    "$NEW_CADIR" \
  --hostname puppet-ca.example.com \
  --tls-cert "$NEW_CADIR/signed/puppet-ca.example.com.pem" \
  --tls-key  "$NEW_CADIR/private/puppet-ca.example.com_key.pem" \
  --puppet-server puppet-master.example.com
```

If migrating in-place (same hostname and port), agents will connect to the
new CA without any reconfiguration.

## Step 8: Verify

```bash
# Check the CA is serving
curl -sfk https://puppet-ca.example.com:8140/puppet-ca/v1/certificate/ca | head -1

# List all certificates
puppet-ca-ctl \
  --server-url https://puppet-ca.example.com:8140 \
  --ca-cert "$NEW_CADIR/ca_crt.pem" \
  list --all

# Run a puppet agent to verify connectivity
puppet agent --test --noop
```

## Directory layout mapping

| Puppet Server | puppet-ca | Notes |
|--------------|-----------|-------|
| `ssl/ca/ca_crt.pem` | `<cadir>/ca_crt.pem` | Same filename |
| `ssl/ca/ca_key.pem` | `<cadir>/private/ca_key.pem` | Moved into `private/` |
| `ssl/ca/ca_crl.pem` | `<cadir>/ca_crl.pem` | Same filename |
| `ssl/ca/signed/*.pem` | `<cadir>/signed/*.pem` | Same structure |
| `ssl/ca/inventory.txt` | `<cadir>/inventory.txt` | Same format |
| `ssl/ca/serial` | (not used) | puppet-ca uses random 128-bit serials |
| `ssl/certificate_requests/*.pem` | `<cadir>/requests/*.pem` | Directory renamed |
| `ssl/certs/ca.pem` | (not needed) | Symlink; agents fetch CA cert via API |
| `ssl/crl.pem` | (not needed) | Symlink; agents fetch CRL via API |

## CLI command mapping

| Puppet / puppetserver ca | puppet-ca-ctl | Notes |
|--------------------------|---------------|-------|
| `puppet cert list` | `puppet-ca-ctl list` | Pending CSRs |
| `puppet cert list --all` | `puppet-ca-ctl list --all` | All certs |
| `puppet cert sign <name>` | `puppet-ca-ctl sign --certname <name>` | |
| `puppet cert sign --all` | `puppet-ca-ctl sign --all` | |
| `puppet cert revoke <name>` | `puppet-ca-ctl revoke --certname <name>` | |
| `puppet cert clean <name>` | `puppet-ca-ctl clean --certname <name>` | Revoke + delete |
| `puppetserver ca setup` | `puppet-ca-ctl setup --cadir <path>` | |
| `puppetserver ca import` | `puppet-ca-ctl import --cadir <path> ...` | |
| `puppetserver ca generate` | `puppet-ca-ctl generate --certname <name>` | |

## Differences to be aware of

### Serial numbers

puppet-ca uses cryptographically random 128-bit serial numbers instead of
sequential integers. This is a security improvement (CA/Browser Forum
guidance) but means serial numbers will look different from what you're
used to. The `serial` file from old Puppet CAs is ignored.

### Auth-arc OID stripping

puppet-ca strips Puppet authorization-arc OIDs (`1.3.6.1.4.1.34380.1.3.*`)
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

puppet-ca does not accept `puppet cert` command syntax directly. Use
`puppet-ca-ctl` instead (see the CLI command mapping table above). The HTTP
API is fully compatible — only the CLI tool name and flag syntax differ.

### Agent configuration

If puppet-ca runs on the same hostname and port as the old CA, agents need
no configuration changes. If the hostname changes, update `ca_server` in
each agent's `puppet.conf`:

```ini
[main]
ca_server = new-ca-hostname.example.com
```

## Rollback

If something goes wrong, restore from backup:

```bash
# Stop puppet-ca
systemctl stop puppet-ca  # or kill the process

# Restore the old CA directory
cp -a "$BACKUP_DIR" "$PUPPET_SSL"

# Re-enable the built-in CA in Puppet Server
sed -i \
  's|certificate-authority-disabled-service/certificate-authority-disabled-service|certificate-authority-service/certificate-authority-service|g' \
  /etc/puppetlabs/puppetserver/services.d/ca.cfg

# Restart Puppet Server
systemctl restart puppetserver
```
