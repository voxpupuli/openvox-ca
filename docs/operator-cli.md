# Operator CLI (`openvox-ca-ctl`)

`openvox-ca-ctl` mirrors the `puppet cert` / `puppetserver ca` subcommands and communicates with a running `openvox-ca` server over HTTP(S). The `setup`, `import` and `migrate` subcommands operate directly on storage and need no running server.

## Global flags

```text
--config       ""                       Path to YAML config file (auto-detected at /etc/puppet-ca/ctl.yaml)
--server-url   https://localhost:8140   openvox-ca server URL
--ca-cert      ""                       CA cert PEM for TLS verification (omit to skip verify)
--client-cert  ""                       Client certificate PEM for mTLS
--client-key   ""                       Client private key PEM for mTLS
--verbose                               Enable debug logging
```

Global flags may be placed before or after the subcommand name.

## Configuration

All global flags can be set via a YAML config file or environment variables. Precedence
(highest → lowest): **CLI flag** → **environment variable** → **config file** → **built-in default**.

The config file is located by checking, in order:

1. `--config /path/to/ctl.yaml` (explicit flag)
2. `PUPPET_CA_CTL_CONFIG` environment variable
3. `/etc/puppet-ca/ctl.yaml` (auto-detected if the file exists)

**Example `/etc/puppet-ca/ctl.yaml`:**

```yaml
server_url:  https://openvox-ca.example.com:8140
ca_cert:     /etc/puppetlabs/puppet/ssl/ca/ca_crt.pem
client_cert: /etc/puppetlabs/puppet/ssl/certs/puppet-master.pem
client_key:  /etc/puppetlabs/puppet/ssl/private_keys/puppet-master.pem
verbose:     false
```

**Environment variables:**

| Flag | Environment variable |
| --- | --- |
| `--server-url` | `PUPPET_CA_CTL_SERVER_URL` |
| `--ca-cert` | `PUPPET_CA_CTL_CA_CERT` |
| `--client-cert` | `PUPPET_CA_CTL_CLIENT_CERT` |
| `--client-key` | `PUPPET_CA_CTL_CLIENT_KEY` |
| `--verbose` | `PUPPET_CA_CTL_VERBOSE` |

## Subcommands

```bash
# List pending CSRs
openvox-ca-ctl list

# List all certificates (signed, revoked, requested)
openvox-ca-ctl list --all

# Sign a pending CSR
openvox-ca-ctl sign --certname agent.example.com

# Sign all pending CSRs
openvox-ca-ctl sign --all

# Revoke a certificate
openvox-ca-ctl revoke --certname agent.example.com

# Revoke + delete cert and CSR
openvox-ca-ctl clean --certname agent.example.com

# Re-sign the CRL with a fresh validity window (preserves all revocations)
openvox-ca-ctl reissue-crl

# Generate a server-side key+cert pair (key saved to ./agent.example.com_key.pem)
openvox-ca-ctl generate --certname agent.example.com
openvox-ca-ctl generate --certname agent.example.com --dns alt.example.com --out-dir /etc/ssl

# Import a certificate issued outside this CA's normal flow (e.g. migrated
# from a legacy CA sharing this CA's key)
openvox-ca-ctl import-cert --certname legacy-node.example.com --cert-file legacy-node_cert.pem

# Bootstrap a new CA offline (no server required)
openvox-ca-ctl setup --cadir /etc/puppetlabs/puppet/ssl --hostname puppet.example.com

# Import an external CA cert/key offline
openvox-ca-ctl import \
  --cadir      /etc/puppetlabs/puppet/ssl \
  --cert-bundle ca_cert.pem \
  --private-key ca_key.pem \
  --crl-chain   ca_crl.pem     # optional; omitting it leaves the stored CRL
                               # chain alone. One is generated if none is
                               # stored, and the import is refused if nothing
                               # stored was signed by the certificate being
                               # imported -- pass --crl-chain to replace it.
# --crl-chain may hold several concatenated CRLs in any order. This CA's own is
# identified by signature and moved to the front; the rest are kept and served
# so agents can do full-chain revocation checking. Every X509 CRL block must parse; other PEM block types are ignored and not stored.

# Migrate an entire CA between storage backends offline (any pair of backends:
# filesystem, sqlite, postgres, mysql, etcd, redis/valkey). Each backend is
# described by a normal openvox-ca config file. Refuses a non-empty destination
# unless --force.
openvox-ca-ctl migrate \
  --source-config /etc/puppet-ca/filesystem.yaml \
  --dest-config   /etc/puppet-ca/postgres.yaml
```

`setup`, `import` and `migrate` operate directly on storage. No running server is needed.
See [storage backends](storage-backends.md#migrating-between-backends) for migration details.
