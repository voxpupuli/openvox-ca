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
  --crl-chain   "$CA_CRL"   # only X509 CRL blocks; anything else is refused

echo "CA imported into $NEW_CADIR"
```

This creates the directory structure, writes the CA cert/key/CRL, and
initialises `inventory.txt` and `serial` (the serial file is written for compatibility but is not used at runtime; openvox-ca generates random serial numbers).

`--cert-bundle` must be a **complete chain, ordered nearest first**: the CA's own
certificate, each issuer after it, ending with a self-signed root. A self-signed
Puppet Server CA already is exactly that — one certificate, which is its own
root — so the common case needs nothing extra.

If your Puppet Server ran under an external root, its `ca_crt.pem` may hold only
its own intermediate certificate. Assemble the full chain before importing:

```bash
# ca_crt.pem first, then each issuer, then the root
cat "$PUPPET_SSL/ca/ca_crt.pem" intermediate.pem root.pem > ca_chain.pem
CA_CERT=ca_chain.pem   # re-run the import above with this
```

Certificates only: a bundle containing the private key is rejected, because this
file is stored world-readable and served to every agent. Every certificate in
the chain must also be within its validity window — an expired root is refused
at import rather than surfacing as verification failures across the fleet.

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
openvox-ca generate \
  --certname openvox-ca.example.com \
  --ttl      8760h \
  --key-out  "$NEW_CADIR/private/openvox-ca.example.com_key.pem" \
  > "$NEW_CADIR/signed/openvox-ca.example.com.pem"

# Or, if you prefer a DNS SAN for the old puppet-master hostname:
openvox-ca generate \
  --certname openvox-ca.example.com \
  --ttl      8760h \
  --dns      openvox-ca.example.com,puppet-master.example.com \
  --key-out  "$NEW_CADIR/private/openvox-ca.example.com_key.pem" \
  > "$NEW_CADIR/signed/openvox-ca.example.com.pem"
```

This runs before the server starts, against the cadir `openvox-ca-ctl import`
populated in the previous step. Earlier versions of this guide had to start the
CA temporarily on loopback without TLS to mint this certificate through the API,
then restart it with TLS; that is no longer necessary.

```bash
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
| `puppetserver ca generate` | `openvox-ca-ctl generate --certname <name>` | Needs a running server. Use `openvox-ca generate --certname <name> --ttl <duration>` to mint offline, which is also the only way to obtain a `pp_cli_auth` certificate |

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
`pp_cli_auth`) by submitting a CSR through the API. That is deliberate and
unchanged: a request that could ask for `pp_cli_auth` would let any agent ask
for CA admin.

Mint one offline instead:

```bash
openvox-ca generate --certname admin-cli --ttl 8760h --pp-cli-auth \
  --key-out admin-cli_key.pem > admin-cli.crt
```

Run it on the CA host, against the server's own configuration. No running
server, no admin certificate, and no API.

This is not merely a shorter recipe than signing with `openssl` by hand. It
needs no access to the raw CA key, so it works under `ca_key_provider: openbao`
— where the key never leaves the vault — and under `encrypt_ca_key`, neither of
which can be fed to `openssl x509 -req` at all. And the certificate it produces
is one the CA can see: it takes a serial from the CA's own generator, is written
to the inventory, appears in `openvox-ca-ctl list --all`, is swept by the expiry
job, and can be revoked by name.

`pp_cli_auth` grants the entire admin tier — signing, revoking, cleaning,
importing, replacing the CRL. Withdrawing it takes three steps rather than one,
and `--pp-cli-auth` has other requirements and caveats worth reading before you
use it: see [`generate`](operator-cli.md#administrator-credentials).

It has no effect where `no_pp_cli_auth: true` is set; the command refuses rather
than issuing a certificate that would grant nothing.

Alternatively, use the `--puppet-server` flag to grant admin access by CN
without needing the `pp_cli_auth` extension at all. Prefer it where the caller
has a stable CN: an allow-list entry is withdrawn by editing a file and
restarting, whereas this grant is withdrawn only by revoking the certificate and
restarting every replica.

#### Certificates you already minted with openssl

Earlier versions of this guide told you to sign admin certificates directly with
the CA key. Those certificates have no inventory row, which means
`openvox-ca-ctl revoke --certname` cannot find them and `--force` cannot replace
them: they were never in the CA's storage. They are nonetheless valid,
CA-signed, admin-granting credentials until they expire.

To retire one, register it first so the CA can see it, then revoke it:

```bash
# 1. With the server running, authenticated by the very certificate you are
#    retiring (it is still an admin credential until you revoke it).
openvox-ca-ctl import-cert --certname admin-tool --cert-file admin.crt

# 2. It is now in the inventory and revocable by name.
openvox-ca-ctl revoke --certname admin-tool

# 3. Restart every replica so the revocation is honoured, then re-mint.
openvox-ca generate --certname admin-tool --ttl 8760h --pp-cli-auth \
  --key-out admin-tool_key.pem > admin-tool.crt
```

Note that step 1 is an admin-authenticated API call and needs a running server —
importing is a prerequisite for revoking here, not an alternative to it.

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
