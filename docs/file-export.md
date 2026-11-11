# File export

openvox-ca can keep local copies of its **CA certificate** and **CRL** current
on disk, for a consumer on the same host that reads them from a file: an
OpenVox Server compiler's `localcacert` and `hostcrl`, a reverse proxy's
client-certificate trust bundle, or anything else that wants a PEM file rather
than an HTTP request.

- Any number of targets, each a file holding **one** material: the CA
  certificate or the CRL.
- Each target can hold the stored chain verbatim (the default), this CA's own
  block alone, or (for the certificate) the root alone.
- Every target is compared with storage **every minute** and rewritten only
  when it differs.

The feature is **disabled by default**; it activates only when at least one
target is configured.

## When you need it

With the **filesystem** backend you usually do not. The CA directory holds a
CRL that is current by construction, and the packages link the
Puppet-compatible paths (`/etc/puppetlabs/puppet/ssl/certs/ca.pem` and
`/etc/puppetlabs/puppet/ssl/crl.pem`) into it, exactly as OpenVox Server
arranges them.

With **PostgreSQL, MySQL, etcd or Redis** there is no such directory. Without
this feature, the only way to get a current CA certificate and CRL onto disk is
to fetch them over the [HTTP API](api.md) on a schedule of your own.

## Configuration

File export is **YAML-file only**: a list of targets has no flag or
environment-variable spelling. Add a `file_export` block to the config file:

```yaml
file_export:
  # How often every target is compared with storage, in seconds.
  # Optional; 0 or unset means 60. At most 300.
  interval_sec: 60

  targets:
    # The CRL chain, where OpenVox Server's hostcrl expects it.
    - path: /etc/puppetlabs/puppet/ssl/crl.pem
      material: crl

    # The CA bundle, where localcacert expects it.
    - path: /etc/puppetlabs/puppet/ssl/certs/ca.pem
      material: cert

    # This CA's certificate alone, without its ancestors.
    - path: /srv/trust/openvox-ca.pem
      material: cert
      scope: self
```

| Key | Required | Meaning |
| --- | --- | --- |
| `interval_sec` | no | Seconds between syncs. `0` or unset means 60, which matches `crl_sync_interval_sec`'s default. Refused when negative or above 300 (see [alerting](#metrics-and-alerting)). |
| `targets[].path` | yes | Absolute path of the file. Its directory must already exist. |
| `targets[].material` | yes | `cert` or `crl`, in lower case. |
| `targets[].scope` | no | `chain` (default): the stored bundle or CRL chain verbatim, which is what the HTTP endpoints serve. `self`: this CA's block alone. `root`: the last certificate in the bundle, the trust anchor; certificates only. The same words mean the same blocks as `cert_scope` and `crl_scope` in the [Kubernetes export](kubernetes-export.md). |

The block is validated before the server starts serving, and before it forks
under `--daemon`, so a mistake is refused where you can see it. Besides the
checks the table implies, a configuration is refused when:

- two targets name the same file (after cleaning the path);
- a target is inside `cadir`, or is one of the CA's own files (`ca_cert_file`,
  `ca_key_file`, `crl_chain_file`, `tls_cert`, `tls_key`, a `client_ca` anchor or
  CRL, the config file itself, and the rest of the set the
  [managed-certificate path check](configuration.md#managed-certificates)
  reserves);
- a target is a file a managed certificate or the CA's
  [serving certificate](configuration.md#the-cas-own-serving-certificate)
  writes. Two writers on one file would undo each other on every pass.

That check compares paths as written, not the files they resolve to, so a
target reached through a symlinked directory is not caught. It is a guard
against typos, not a sandbox; directory permissions are what keep the export
out of places it should not be.

The block is read at startup. Changing it needs a restart; `SIGHUP` does not
reload it.

## How it works

Every running instance syncs its own configured files. That includes every
replica on a shared backend, because each host needs its own copy. Only the
process that serves HTTP runs the export: under the default process split
that is the frontend, never the signer, which holds the CA key. No lock is
taken. Two instances on one host writing the same path converge, since each
write is an atomic rename of the same content.

A sync reads the CA certificate and CRL from storage and, for each target,
compares the selected material with the file:

- **A regular file that already holds it** is left alone. It is not rewritten,
  and its mode, owner and timestamps stay whatever you made them.
- **A missing file, or one that differs,** is replaced: the new content goes to
  a temporary file beside it, created with mode `0644`, flushed to disk, and
  renamed over the path. A reader sees the old file or the new one, never a
  partial one. The replacement is a new file, so a mode or owner you set by hand
  on the old one does not carry over. The CA certificate and CRL are public;
  `0644` reflects that, and the export never writes key material.
- **A symbolic link** is replaced by a regular file, and a warning names where
  it pointed. Nothing is ever written *through* a link, dangling or not: the
  rename replaces the link itself. This is the expected case when you move off
  the filesystem backend and point the export at a path the packages had linked
  into the old CA directory.
- **Anything else** at the path (a directory, a FIFO, a device) is refused and
  left in place. A FIFO is never read, since reading one would block the
  export, and the comparison judges the file it actually opened, so a FIFO or
  link swapped in after the check is refused too.

The export does not create directories, change the mode or owner of an existing
file, or remove a file.

A revocation therefore reaches the file within one interval, whichever replica
made it: the same bound `crl_sync_interval_sec` puts on a revocation reaching
another replica's own checks. The export does not wait to be told the CRL
changed. The CRL-update signal the Kubernetes export uses does not fire on a
replica that picks up another replica's re-sign, which is right for a
Kubernetes object every replica writes to the same place, and wrong for a file
on each host.

### When a write fails

**The previous file is kept.** A stale CRL copy is a problem, because
Puppet's default `certificate_revocation = chain` fails closed once the copy
passes its NextUpdate. But removing the file would fail closed at once, and on
the default `crl_validity_days` (30, re-signed when 10 remain) a copy that
stops updating still has days of validity left. The export logs the failure at
`WARN` (`File export failed for target`, naming the path), counts it, and tries
again on the next interval. The CA keeps serving.

The same applies when the material cannot be read from storage: a CRL that
cannot be read fails only the CRL targets, and an empty material is never
written.

A write that the kernel does not return from (a network filesystem that has
stopped answering, for example) blocks the export until it does, and holds up
shutdown with it. The alert below reports the first, because nothing is
confirmed current while it lasts; the service manager's stop timeout ends the
second.

### Under systemd

The shipped unit runs with `ProtectSystem=strict`, which makes everything
outside the CA directory read-only to the CA. Grant each target's directory with
a drop-in, as [running under systemd](systemd.md#installing-the-unit) describes
for `cadir`:

```ini
# /etc/systemd/system/openvox-ca.service.d/file-export.conf
[Service]
ReadWritePaths=-/etc/puppetlabs/puppet/ssl -/srv/trust
ReadOnlyPaths=-/etc/puppetlabs/puppet/ssl/private_keys
```

That covers all three targets in the example above: `/etc/puppetlabs/puppet/ssl`
holds `crl.pem` and, below it, `certs/ca.pem`. The writable path has to be the
**directory**, not the file: each write creates a temporary file beside the
target and renames it into place. Without the drop-in every sync fails with a
read-only filesystem error, and the alert below fires.

Keep the `-` in front of each path. It tells systemd to skip a path that does
not exist, so a directory missing on one host fails only the export that
needed it. Without it, systemd refuses to start the CA at all (status
`226/NAMESPACE`), which is a much larger failure than the one the export is
designed to have (checked on systemd 257).

The drop-in lifts systemd's read-only mount and nothing more. The shipped unit
runs as `User=puppet`, so each target's directory must also let that user
create files in it, as a [managed certificate's `files`
store](configuration.md#managed-certificates) does; either missing fails the
same way. On a host where openvox-agent created `/etc/puppetlabs/puppet/ssl` and
`certs/` as root, making them writable by `puppet` hands that account the
agent's own trust anchor, which is a decision to take knowingly (see [why
`puppet` and not a private account](systemd.md#why-puppet-and-not-a-private-account)).
A directory of the CA's own avoids the question.

`ReadWritePaths=` lifts the read-only mount for the whole tree below each path,
so granting `/etc/puppetlabs/puppet/ssl` alone would leave only file
permissions between the CA's user and everything else in it, the host's own
agent key included. The `ReadOnlyPaths=` line puts `private_keys/` back under
the read-only mount: systemd applies the deeper path, whichever order the two
lines are in (checked on systemd 257). Leave that line out if a
[`serving_cert`](configuration.md#the-cas-own-serving-certificate) or managed
certificate `files` store writes its key under `private_keys/`, or that store
cannot be written. Where your consumer allows it, a directory that holds
nothing else is simpler still.

### Under Kubernetes

The chart runs the CA with `readOnlyRootFilesystem: true`, so a target's
directory must be a writable volume: add it with `extraVolumes` and
`extraVolumeMounts`, as a managed certificate's `files` store needs (see
[deploying with Helm](helm-chart.md)). Mount the same volume in whichever
container reads the file. Inside a cluster the
[Kubernetes export](kubernetes-export.md) is usually the better fit: it puts the
material in a Secret or ConfigMap that any pod can mount.

## Metrics and alerting

When the [Prometheus exporter](metrics.md) is enabled, each sync of each target
is counted in `openvoxca_file_export_syncs_total{path,result}`, and per-target
`last_success_timestamp_seconds` and `last_error_timestamp_seconds` gauges
record the most recent outcomes. A success means the file was confirmed to
hold the current material, whether or not it had to be rewritten, so
`time() - openvoxca_file_export_last_success_timestamp_seconds` is how stale
the file may be.

The [monitoring mixin](https://github.com/voxpupuli/openvox-ca/tree/main/mixin)
ships one alert, `OpenVoxCAFileExportStale` (warning). It fires when a target
has not been confirmed current for more than ten minutes and stays so for five
more, or when a target has not succeeded once in the five minutes since the CA
started. It covers failed writes, failed storage reads and a write that never
returns alike, because all three stop `last_success` from moving. The CA
publishes `syncs_total` at zero for every target before the first sync, which
is what lets the alert see a target that has never succeeded.

`interval_sec` is capped at 300 so that the ten-minute threshold always spans
at least two attempts. If you raise the cap in your own build, raise
`fileExportStaleAfterSeconds` in the mixin's `config.libsonnet` with it.

## Operational notes

- **Each host is its own case.** A replica that cannot write its files says so
  on its own `instance` label; the others are unaffected.
- **A hand edit is undone** on the next sync, and so is a copy restored from a
  backup that differs from storage. That is the point: the export makes the
  file match storage, and storage is the source of truth.
- **Removing a target from the configuration leaves its file in place.** The
  export never deletes. Remove the file yourself if nothing should read it, or
  it will go stale without anything reporting it.
