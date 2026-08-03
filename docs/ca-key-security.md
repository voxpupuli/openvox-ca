# CA key security

This page covers how the CA private key is protected at rest, the options for
moving key custody off the CA host entirely, and the detective control that
watches for anomalous destructive operations.

## CA key encryption at rest

By default, the CA private key is stored as unencrypted PEM at `<cadir>/private/ca_key.pem`.
Enable `--encrypt-ca-key` to encrypt the key at rest using AES-256-GCM with an Argon2id-derived key.

### How it works

- The private key is marshalled to PKCS#8 DER, then encrypted with AES-256-GCM.
- The encryption key is derived from a passphrase using Argon2id (time=3, memory=64 MiB, threads=4).
- The encrypted key is stored as a PEM block with type `ENCRYPTED PRIVATE KEY`.
- On startup, the key is decrypted into memory and used for all signing operations.

### Passphrase resolution order

1. **`--ca-key-passphrase-file`:** reads the first line of the specified file.
2. **`PUPPET_CA_KEY_PASSPHRASE`** environment variable: avoids CLI `/proc/cmdline` exposure.
3. **Auto-generated:** if no passphrase source is configured, a cryptographically random
   passphrase is generated and saved to `<cadir>/private/.ca_key_passphrase` (mode `0600`).
   The path is logged at startup so operators know where it is.

### Example usage

```bash
# Bootstrap with encryption (auto-generated passphrase):
openvox-ca --cadir /var/lib/puppet-ca --encrypt-ca-key

# Bootstrap with an explicit passphrase file:
echo "my-secret-passphrase" > /etc/puppet-ca/key-passphrase
chmod 600 /etc/puppet-ca/key-passphrase
openvox-ca --cadir /var/lib/puppet-ca --encrypt-ca-key \
  --ca-key-passphrase-file /etc/puppet-ca/key-passphrase

# Or via environment variable:
export PUPPET_CA_KEY_PASSPHRASE="my-secret-passphrase"
openvox-ca --cadir /var/lib/puppet-ca --encrypt-ca-key

# openvox-ca-ctl setup also supports encryption:
openvox-ca-ctl setup --cadir /var/lib/puppet-ca --encrypt-ca-key
```

### Backward compatibility

Existing CAs with unencrypted keys continue to work without changes. The `--encrypt-ca-key`
flag only affects new CA bootstraps. Loading transparently handles both encrypted and
unencrypted PEM files.

### Security considerations

Encrypting the CA key at rest protects against **offline exfiltration**. If an attacker
obtains the key file from a backup, disk image, or volume snapshot, the key is unusable
without the passphrase. It does **not** protect against a live host compromise where the
attacker can read the passphrase source or dump the process memory.

For stronger protection, either delegate key custody to OpenBao entirely (available
today; see [OpenBao Transit-engine key custody](#openbao-transit-engine-key-custody)
below) or consider a hardware security module (HSM) via PKCS#11 (planned; see
[Planned: PKCS#11 / HSM support](#planned-pkcs11--hsm-support) below).

## OpenBao Transit-engine key custody

`--ca-key-provider openbao` delegates the CA private key entirely to an
[OpenBao](https://openbao.org/) Transit secrets engine key: the key never exists inside
any `openvox-ca` process at all, on disk or in memory — only a digest crosses the wire
to be signed. This works identically whether `openvox-ca` runs as a plain systemd
service (AppRole or a static token file) or as a Kubernetes pod authenticating via its
own ServiceAccount (Kubernetes auth) — with no Vault/OpenBao Agent sidecar required:
`openvox-ca` maintains its own OpenBao token lifecycle, proactively renewing it and
re-authenticating from source credentials whenever renewal fails.

Every existing storage backend keeps working unmodified in this mode — OpenBao only
ever supplants key custody, never CSR/certificate/CRL/inventory storage. See
[OpenBao Transit-engine CA key](openbao-transit.md) for full configuration
reference and setup instructions.

Whatever holds the key, the CA can run as an intermediate under an external root
rather than as its own root: `openvox-ca csr` emits a signing request bound to
the key the configured provider holds, and `openvox-ca import-ca-cert` installs
the chain the parent signs. No key material is passed on the command line at any
point, which is what lets the same procedure work for a Transit key that never
leaves the vault. See [offline subcommands on the server
binary](operator-cli.md#offline-subcommands-on-the-server-binary).

This integration is built and tested against OpenBao specifically, against current
OpenBao releases. It should also work against HashiCorp Vault, since Vault's Transit
engine, AppRole/Kubernetes auth methods, and Go client API are what OpenBao forked from
and remains wire-compatible with — but Vault is not part of the test matrix, so this is
currently unverified. Compatibility bug reports (and fixes) for Vault are welcome.

## Planned: PKCS#11 / HSM support

A future enhancement will add PKCS#11 support so the CA private key can be held in a
hardware security module (HSM), TPM, or software token (e.g. SoftHSM2). The key would
never leave the token; only signing operations would be delegated via the PKCS#11 API.
It would slot in as a third `--ca-key-provider` value, alongside `file` (default) and
`openbao`.

**Planned design:**

- `--ca-key-provider pkcs11`: a PKCS#11 module URI or library path, slot/token label, and PIN
  (via file or env var, same pattern as `--ca-key-passphrase-file`)
- Integration with **p11-kit** for module discovery, allowing operators to configure the
  PKCS#11 backend (SoftHSM2, TPM2 PKCS#11, cloud KMS bridges, Nitrokey, YubiHSM, etc.)
  via the system p11-kit configuration rather than hardcoding library paths
- CGo dependency for the PKCS#11 C bindings (build-time opt-in)

This is tracked as a separate feature. Contributions welcome.

## Monitoring destructive operations

The server tracks the rate of destructive operations (certificate revocation and
deletion) per authenticated client. When a single client exceeds **5 destructive
operations per minute**, a warning is emitted to the structured log:

```text
level=WARN msg="High rate of destructive operations detected" client=admin.example.com operation=revoke
```

This is a detective control, not a preventive one. It does not block the operation, but alerts
operators to potentially anomalous administrative activity. Operators should:

- Forward `openvox-ca` logs to a centralized log aggregator (e.g. Loki,
  Elasticsearch, Splunk)
- Create alerts on `"High rate of destructive operations"` log messages
- Investigate any alerts promptly. A burst of revocations may indicate a
  compromised admin certificate or an operational error
- Consider whether the `--puppet-server` allow list should be tightened if
  unexpected clients appear in these warnings

The threshold (5 ops/minute) is a sensible default for environments where
bulk revocation is uncommon. Future versions may make this configurable.
