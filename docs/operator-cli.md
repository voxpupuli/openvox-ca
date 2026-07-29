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
  --crl-chain   ca_crl.pem     # optional; a new CRL is generated if omitted
# The bundle must be a complete chain, nearest first, ending at a self-signed
# root, and every certificate in it must be within its validity window. If the
# CA's key is held by a provider rather than a file, there is no --private-key
# to pass: use `openvox-ca import-ca-cert` instead (below).
#
# --crl-chain must contain only X509 CRL blocks. Every one is parsed, and only
# the parsed CRLs are stored -- so a file with a certificate or a key
# concatenated into it is refused, for the same reason the certificate bundle
# rejects keys: the result is world-readable and served to every agent.

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

## Offline subcommands on the server binary

Two subcommands live on `openvox-ca` rather than `openvox-ca-ctl`, because they
must reach the storage backend and CA key provider named in the *server's*
configuration. `openvox-ca-ctl` reads a different configuration file and can
only address a local filesystem directory, so it cannot serve a CA whose state
is in PostgreSQL or whose key is in OpenBao Transit.

Neither needs a running server.

Both read the **server's** configuration, not `openvox-ca-ctl`'s: `--config`, or
`PUPPET_CA_CONFIG`, defaulting to `/etc/puppet-ca/config.yaml`. A working
`ctl.yaml` has no effect on them. `--cadir` overrides the configured storage
directory for a one-off run.

```bash
# Emit a certificate signing request for the CA's own key, for an external
# parent CA to sign. Works for every ca_key_provider.
openvox-ca csr --out ca-request.pem

# ... and create the key first, if it does not exist yet
openvox-ca csr --hostname puppet.example.com --create-key --out ca-request.pem

# Install the chain the parent signed, completing the round trip
openvox-ca import-ca-cert --cert-bundle signed-chain.pem
```

`csr` reuses an existing CA certificate's subject verbatim — the encoded DN is
carried across byte for byte, so re-issuance reproduces the established name
exactly, including attributes the `ca_subject_*` settings cannot express. When
no certificate exists yet it builds the name from `hostname` and those settings —
the same name a self-signed bootstrap would use — and refuses if `hostname` is
unset rather than guessing, because the request is about to be signed by a third
party.

`--create-key` creates the CA key when it does not exist, and never replaces one
that does. Between `csr --create-key` and `import-ca-cert` the CA has a key but
no certificate, and **the server will refuse to start** in that window rather
than bootstrap over the key your parent CA is in the middle of signing. This
holds for every `ca_key_provider`, including the default. Run the two steps
together, or stop the service while you do.

> **These subcommands read the config file and `PUPPET_CA_*` environment only.**
> The server's storage and key-provider flags (`--storage-backend`, `--sql-dsn`,
> `--ca-key-provider`, `--openbao-*`, `--encrypt-ca-key`, …) belong to the server
> command itself and are not available here, so a server configured entirely by
> flags — including the container image's own `CMD` — is invisible to them. That
> matters: with no config file, `csr --create-key` would resolve
> `ca_key_provider: file`, mint a **local** CA key, and emit a request bound to a
> key a Transit-backed server will never use, so the parent would sign the wrong
> key. Both commands therefore print the config file, storage backend and key
> provider they resolved before doing anything — check those lines match the
> server. If your server is configured by flags, mirror the storage and
> key-provider settings into the config file or `PUPPET_CA_*` environment for
> these commands.

`import-ca-cert` requires a **complete chain, nearest first**: this CA's own
certificate, each issuer after it, ending with a self-signed root. Supply only
certificates; a bundle carrying a private key is rejected, because this file is
stored world-readable and served to every agent.

Two further rules, both checked before anything is written, and both worth
knowing before you ask the parent to sign rather than after:

- **The leading certificate must carry a CA profile.** If a KeyUsage extension
  is present it must include `keyCertSign` and `cRLSign`; without them the
  certificate installs cleanly and then cannot issue certificates or publish a
  CRL. A parent signing through a narrowed role — an OpenBao PKI role with a
  restricted `key_usage`, say — is the usual cause. An absent KeyUsage extension
  is unconstrained by RFC 5280 and is accepted. `pathlen:0` is correct for this
  CA, not a fault: it permits end-entity certificates and forbids further CAs,
  which is exactly what openvox-ca issues.
- **Every certificate in the chain must be within its validity window.** Not
  just the leading one: an expired root or issuer further up is refused here
  rather than discovered as chain-verification failures across the fleet, after
  the bundle has been written and served.

The command never needs the private key *material*: it proves the certificate
binds the key the configured `ca_key_provider` holds, which is what makes
importing without a key file safe. With the default `file` provider that means
reading the key from storage (and decrypting it, if `encrypt_ca_key` is set);
with OpenBao Transit the key never leaves the vault and only its public
component is compared.

Use `--force` to replace an existing CA certificate — it re-signs the stored
CRL, which the replacement would otherwise invalidate, and reminds you to
restart every replica afterwards.

When the CA certificate is mounted read-only from outside (`ca_cert_file`
pointing at a Kubernetes Secret, say), `--out` validates the bundle — including
the key-binding proof — and writes it to a file instead of to storage, for
loading into the Secret out of band.

See [running under an external root CA](openbao-transit.md#running-under-an-external-root-ca)
— written against OpenBao Transit, but the procedure is identical for every
`ca_key_provider`, including the default file provider —
for the end-to-end procedure.
