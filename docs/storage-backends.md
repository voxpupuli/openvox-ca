# Storage backends

`openvox-ca` keeps its CA state — the CA certificate, private key, CRL,
certificate inventory, pending CSRs and issued certificates — in a pluggable
storage backend. Pick the one that matches how you want to run the CA:

| Kind | Status | Best for |
| --- | --- | --- |
| `filesystem` | default | single-node installs; drop-in compatibility with the OpenVox/Puppet Server CA layout |
| `etcd` | stable | HA clusters where multiple `openvox-ca` replicas share a single CA |
| `redis` (incl. Valkey) | stable | clusters that already run Redis/Valkey (direct or Sentinel-managed) |
| `sqlite` | stable | single-node installs that prefer a single database file over a cadir tree |
| `postgres` | stable | HA clusters that already run PostgreSQL; shared CA across replicas |
| `mysql` (incl. MariaDB) | stable | HA clusters that already run MySQL/MariaDB; shared CA across replicas |

`sqlite`, `postgres` and `mysql` share one SQL implementation and differ only in
driver. All drivers are pure Go, so the default `CGO_ENABLED=0` and FIPS
(`GOEXPERIMENT=boringcrypto`) builds work with every backend.

Two things are true regardless of backend:

- **Server-generated per-subject private keys always live on local disk** (under
  `cadir`). They are issued once, handed back to the requester, and kept locally
  for operator convenience only; they are never written to a remote store.
- The **CA certificate and/or CA private key can be pinned to a local file**
  (e.g. a mounted secret volume) independent of the chosen backend — see
  [CA cert/key as local files](#ca-certkey-as-local-files).

Because those per-subject keys are local files, generating them on a platform
that may start the CA as a different uid from one run to the next needs a stable
uid or some preparation: see [Server-side key generation and the
uid](#server-side-key-generation-and-the-uid).

In the HA backends (`etcd`, `redis`, `postgres`, `mysql`), any replica can sign,
revoke, or refresh the CRL, and everything it writes lands in shared storage and
is immediately visible to the others; `openvox-ca` coordinates the replicas and
recovers automatically if one crashes. You don't need to configure any of that.
The CRL an agent downloads is served straight from storage, so it is current on
whichever replica answers.

What is not instant is a replica's *own* revocation verdicts — both the client
certificates it will accept and the OCSP responses it signs. Those are answered
from a CRL it holds in memory and reloads on a timer, so a certificate revoked
on one replica stops working against the others within `crl_sync_interval_sec`
(60s by default) rather than at once. See
[Revocation across replicas](configuration.md#revocation-across-replicas).

The responder keeps a second such copy: the set of serials this CA has issued,
which decides whether it will speak about a certificate at all. On the shared
backends it is reloaded on its own timer, so a certificate signed on one replica
stops being reported `unknown` by the others within `ocsp_index_sync_interval_sec`
(5m by default). `filesystem` and `sqlite` do not run that job — they
support a single running instance, so nothing else should be writing
certificates there — so on those two the set is what it was at startup. See [OCSP status across
replicas](configuration.md#ocsp-status-across-replicas).

---

## Running a second process against a live store

**Running more than one `openvox-ca` against a `filesystem` or `sqlite` store is
not supported.** Those two have no distributed locking, and a backend without it
permits exactly one running instance. Stop the server before running any command
that reaches storage directly.

This is a property of the backend's locking rather than of its name. The HA
backends — `etcd`, `redis`, `postgres` and `mysql` — coordinate writers across
processes *and* hosts, so on those you may run as many instances as you like, on
as many machines as you like, and none of this section applies to them. A future
backend inherits whichever behaviour its locking earns it.

### Why only one

Not because of what lands on disk, but because of what does not. Each running CA
answers from state held in its own memory and reconciled through shared storage:
the index of serials it has issued, its OCSP cache, and the CRL its revocation
checks read. On a backend with distributed locking, storage is what the replicas
reconcile that state through. `filesystem` and `sqlite` have no such mechanism,
by design — so a second instance issues certificates the first never hears of,
and **a certificate revoked on one goes on being accepted by the other**. No
amount of finer-grained locking fixes that; only running one instance does.

### What the server does about it

At startup the server takes an exclusive `flock(2)` on the store and holds it
until it exits — under `<cadir>/locks/` for `filesystem`, and in the hidden
directory beside the database file for `sqlite`. So:

- **A second `openvox-ca` fails to start**, naming the process that holds the
  store: `another openvox-ca process is already running against this store:
  openvox-ca (pid 1234) on ca1.example.com since …`. It is a refusal rather than
  a wait, because waiting would only postpone the same answer.
- **`openvox-ca-ctl setup`, `import` and `migrate` are refused the same way**,
  as are the offline `openvox-ca` subcommands (`csr`, `generate`,
  `import-ca-cert`, and `rebuild-inventory-hmac` on its `--yes-re-bless` path;
  reporting takes no store-wide instance lock). Those are the commands that
  reach storage directly.
  Every other `openvox-ca-ctl` subcommand works through the admin API over HTTP
  instead, never opens the store, and is unaffected — asking a running CA to
  sign, revoke or list remains an ordinary thing to do.
- **`migrate` no longer hangs when both ends are the same store.** That was
  never supported, and it used to wait for ever on a lock it had already taken
  itself; it now fails immediately.
- **Nothing to clean up after a crash.** The kernel releases an `flock` when the
  holding process dies, however it dies. There is no stale lock to remove and no
  lock file that needs deleting — see the note on `locks/` under
  [the filesystem backend](#filesystem-backend-default).
- **Under `--daemon` the refusal comes before the fork.** That flag re-execs the
  server and discards the child's output, so a refusal raised there would reach
  nobody: you would be told the CA had started, get a zero exit, and have the
  child die in silence. The check therefore runs in the process you started,
  which fails with a non-zero exit and names the holder. It is a pre-flight — it
  takes the lock and releases it again, and the child takes the real one — so a
  third process that wins the moment between them still produces the silent
  failure. A server that is already running does not, which is the case this
  exists for.

Under the default isolated-process topology the lock is held by the supervisor
process, once, on behalf of the signer and frontend children it starts. One
instance means one `openvox-ca` service, not one operating-system process.

### What the lock cannot do, and why the rule matters more than it does

The lock is a backstop, not a licence. It reduces the damage when the
unsupported thing is attempted on one host. It cannot do more than that:

- **`flock(2)` says nothing useful over NFS**, so a cadir or SQLite file shared
  between hosts is not protected at all, and sharing one was never supported.
- **A second process on another host cannot be excluded**, by this or by
  anything else we could build.
- **Both processes must be on a release that has this.** The exclusion works
  only if each side takes the lock, so a new `openvox-ca-ctl` beside an older
  running server — or the reverse, during a staged upgrade where the package is
  updated but the service has not been restarted — silently gets the old
  behaviour: no coordination at all. Upgrade and restart the server before
  relying on any of it.
- **Absolute paths matter.** Two processes exclude each other only if they
  resolve the same lock directory, so `cadir` and `sql_dsn` should be absolute.
  A relative path used from two different working directories, or one store
  reached through two different symlinks, gives two independent locks and no
  mutual exclusion.
- **A lock file that is not a plain file is refused.** The lock directory can
  be group-writable (see the SQLite section), so a symbolic link, a hard link or
  any other special file found at a lock file's name stops the acquisition with
  an error naming it, and nothing is followed or changed. `openvox-ca` only
  ever creates lock files as plain files, so remove it by hand and find out who
  put it there.
- **Where the store cannot be locked at all** — a filesystem without `flock(2)`,
  a read-only mount — the server logs a warning and starts anyway, because
  refusing over a lock that is unavailable rather than held would take down a CA
  that worked before. The rule still holds; only the enforcement is missing.

So the rule is not "the lock will stop you". It is that these backends support
one instance, and the lock catches the case it can.

### Running `openvox-ca-ctl` as the service user

- **Run `openvox-ca-ctl` as the user the server runs as**, not under `sudo`.
  The lock files are group-accessible at most, but a command run as root still
  leaves a root-owned lock file the service account cannot open, and the
  server's next acquisition of that name fails — deliberately and loudly, with
  an error naming the file, its owner and `chown -R`, because the alternative is
  it quietly giving up on locking while the root process believes it holds an
  exclusive one. Under systemd that means `sudo -u puppet openvox-ca-ctl …`
  (or `runuser -u puppet --`), matching the `User=` in the unit. It applies
  even to commands that only read, such as `migrate` from a live source, since
  taking the lock is what creates the file.

Within a single instance the per-lock-name `flock(2)` coordination added for
`filesystem` and `sqlite` still applies: a command that is not refused outright
waits for the named lock it needs and then fails if it cannot get it, logging
`Waiting for the CA lock: another process on this host holds it` the first time
it is refused, so a command that pauses is distinguishable from one that has
hung.

### If you run two anyway

The damage is not limited to the stale caches above. `SameHostLocker` excludes
another process per lock *name*, and the inventory append takes no cluster lock
of its own — it is serialised by a process-local mutex. Two processes issuing
for **different** subjects therefore hold different `subject:<name>` locks, and
can still interleave an append with its integrity update, leaving an integrity
value covering an inventory that never existed — which the *next* start rejects.

That is not a tracked defect, because it describes a configuration that is not
supported rather than a bug in one that is. Note *why* it is not one, because
the distinction decides whether this paragraph is still worth reading: it is
closed by **scope**, not by mechanism. Nothing makes the interleave impossible —
the same-host locking work did not close it and was never going to — so the
rule, and the store lock that holds operators to it, are the whole of the
protection. Stop the server before issuing certificates from a second process.

A deployment that genuinely needs concurrent writers wants a structured backend,
where the entry and its integrity head are written in one step: SQL in one
transaction, redis in one atomic script, etcd in one transaction. On those
backends concurrent writers are the supported case, and this whole section is
moot.

---

## Server-side key generation and the uid

Server-side key generation keeps the key it generates in `<cadir>/private/`,
whatever the backend. [`POST /generate/{subject}`](api.md#server-side-key-generation)
always does; the offline
[`openvox-ca generate`](operator-cli.md#generate-minting-a-certificate-offline)
does unless `--key-out` names another file. `openvox-ca` creates that directory
`0750` and writes each key `0600`, and the umask cannot widen either, so only
the uid that created `private/` can add a key to it.

On a platform that chooses the uid the CA runs as, and may choose a different
one from one run to the next, sharing only the store's group with the uid before
it, **server-side key generation needs a stable uid**. OpenShift is one
example: there the security context constraint a pod runs under decides both its
uid and its `fsGroup`, so check what yours assigns against the `fsGroup`
paragraph below. The first run creates `private/`; once a later run is another
uid, every `/generate`, and every offline `generate` without `--key-out`, fails
on the key write. The offline command reports the permission error.
`/generate` answers `500 Internal Server Error`, and the server logs
`Generate failed` with an error beginning
`failed to save private key for <subject>`.
That failure comes after the certificate is signed: the certificate is deleted
again, but each failed attempt has used a serial and left an inventory entry.
Signing never writes to `private/`, so it is not affected by this —
whether the rest of the store is reachable by a later uid is a question for the
backend, and [the SQLite backend](#sqlite-backend) says what that one needs.
Managed certificates do not use `private/` either: each writes its key to its
own store, a Kubernetes Secret or files you name (see [managed
certificates](configuration.md#managed-certificates)).

Reading a key back has the same limit, since each key is `0600`: a later uid
cannot read one an earlier uid wrote. `openvox-ca` reads none back of its own
accord, but if `tls_key` names a key in `private/` — where [the
serving-certificate bootstrap](configuration.md#serving-certificate) leaves the
server's own — the server reads it at every start, and a later uid cannot. Pin
the uid, or give that key group read and never world access: in place, by the
uid that owns it or by root, which keeps it under the startup check on
`private/`; or as a copy outside `private/`, where nothing checks its mode.
Either has to be redone after every reissue, which writes the key `0600` again.
Group read lets every member of the group present the server's TLS identity, so
do it only where the group is the CA's own.

This only bites where nothing restores group access to the volume. Under a
Kubernetes `fsGroup` with the default `fsGroupChangePolicy: Always`, the kubelet
gives the volume to that group and ORs group access in at every mount — read and
write on files, and read, write, search and the setgid bit on directories — so
`private/` is group-writable again before the next uid starts. The Helm chart
pins the uid (`runAsUser: 1000`) and sets an `fsGroup` by default, so a chart
install is affected only where the uid has been unpinned and group access is not
restored. It is not restored with no `fsGroup`, with
`fsGroupChangePolicy: OnRootMismatch` (which leaves the volume alone once its
root matches, so a `private/` created after the first mount keeps `0750`), or on
a volume whose driver does not apply `fsGroup` at all — whatever the chart's own
values say.

Where it does bite, you have three options:

1. **Pin the uid.** Nothing else is needed. On a store that is already
   failing, pin it to the uid that owns `private/` (`stat -c %u
   <cadir>/private` on Linux) — unless that is root, in which case have root
   give `private/` to the CA's uid, or use option 2, rather than run the CA as
   root.
2. **Create `private/` yourself before the first start**, with the mode your
   platform needs and no world access: `2770`, owned by the store's group, for
   instance. `openvox-ca` never changes the mode of a directory that already
   exists, so it keeps that mode, but it does not check it either. A
   world-writable `private/` starts without a word and lets every local account
   add, replace or remove the files in it. A store that is already failing can
   be given that mode with a one-off `chmod`, run by the uid that owns
   `private/` or by root (in a pod, a one-off pod or Job running as that uid);
   the running uid cannot, since `chmod` needs ownership.

   In a pod the CA creates `private/` on its first start, so do it from an init
   container: with the Helm chart, one in `initContainers` that mounts the
   chart's `data` volume at `persistence.mountPath`. The chart's cadir is that
   mount point unless `config.cadir` narrows it to a directory below, so the
   directory to create is `<cadir>/private` for whichever applies, with the
   cadir itself created first if it does not exist yet. The init container runs
   on every start, as whatever uid that run is given, so it must create
   directories only when they are absent and never `chmod` one that exists: one
   that changes the mode fails with `EPERM` once the uid changes, and the pod
   does not start at all.

   Each key is still written `0600`, so this lets a later uid add keys, not read
   earlier ones (see above). It also lets every member of the group add,
   replace or remove the files in `private/`, though not read them, so do this
   only where the group is the CA's own. It is no help on a backend whose other
   files a later uid cannot reach anyway: the filesystem backend is one, and
   [the SQLite backend](#sqlite-backend) says what that one needs. On the
   filesystem backend `private/` also holds the inventory's integrity key and,
   in a cadir that keeps it there, the CA key (`private/ca_key.pem`), which
   group write would let the group replace or remove.
3. **For the offline command only, use `--key-out`.** It writes the key to the
   file you name and writes none into `private/`. `/generate` has no
   equivalent: it always keeps a copy.

---

## Filesystem backend (default)

All CA state lives under `--cadir`. The on-disk layout matches the OpenVox/Puppet
Server CA, so you can swap in `openvox-ca` without reorganising your SSL tree:

```text
<cadir>/
├── ca_crt.pem              CA certificate
├── ca_key.pem              CA private key (see note)          0600
├── ca_pub.pem              CA public key
├── ca_crl.pem              Certificate Revocation List (see note)
├── inventory.txt           Issued certificate log, in OpenVox Server's format
├── superseded.json         Certificates awaiting delayed
│                           revocation (see note)              0600
├── private/
│   └── <subject>_key.pem   server-generated private keys     0600
├── requests/
│   └── <subject>.pem       pending CSRs
├── signed/
│   └── <subject>.pem       issued certificates
└── locks/
    └── <hash>.lock         same-host lock files              0660
```

> **`ca_key.pem` is where OpenVox Server keeps its CA key**, so a cadir either
> implementation has used has the key where the other looks. If the key is in
> `private/ca_key.pem` instead, openvox-ca reads and writes it there. If both
> files exist with different contents, openvox-ca refuses to start and names
> both: either could be the key this CA signs with, and only you can say which.
> Remove the other one.
>
> **`superseded.json` is absent until the first supersession.** It appears only
> where [`superseded_cert_revoke_after_sec`](configuration.md#delayed-supersession)
> grants renewals an overlap window, and it holds the serials — with their
> subjects and due times — of certificates that have been replaced but not yet
> revoked. Deleting it does not revoke anything; it strands every certificate it
> named, each of which stays valid until it expires. If you must remove it, take
> the serials first and retire them with `openvox-ca-ctl revoke --serial <hex>`.
>
> **`ca_crl.pem` may hold more than one CRL.** Once a chain has been imported
> with `--crl-chain`, the blob is this CA's own CRL followed by its ancestors', so
> agents can do full-chain revocation checking. Every backend stores it as one
> logical value — a single file here, a single key elsewhere — so nothing below
> changes; only the number of PEM blocks inside it does. See
> [storage internals](development/storage-internals.md).

(The directory also holds small internal integrity files; leave them in place.)
File permissions are fixed: `0600` for `ca_key.pem`, `inventory.txt`, the
integrity files and `superseded.json`, and for anything under `private/`;
`0660` for the lock files under `locks/`, and `0770` for `locks/` itself;
`0644` for certificates, CSRs, `ca_crt.pem`, `ca_pub.pem`, `ca_crl.pem` and
`serial`. The CRL is world-readable because it is
public: it is served without authentication, and OpenVox Server writes it
`0644` too. The inventory is not, because it names every subject this CA has
signed. A file openvox-ca rewrites gets its mode, so a cleanup that drops
expired lines from an `inventory.txt` OpenVox Server created leaves it `0600`
where it was `0640`. The blob modes are set on each file as it is created and
your umask cannot widen them; the lock files and the directories are created at
these modes and a tighter umask narrows them further.

`openvox-ca` never changes the mode of a file it did not create, so anything
already on disk is left as you have it — but it does check its key material at
startup. That is `ca_key.pem`, every file under `private/` — the per-subject
`*_key.pem` keys and the inventory-integrity key alike, because that directory
holds secrets by construction — and a `ca_key_passphrase_file` you point it at.
A cadir that keeps its CA key in `private/ca_key.pem` has it checked there. A
file readable by every local account
makes it **refuse to start**, naming the file and the `chmod` that fixes it; one
readable only by its group is reported at `Info` and does not stop the CA.

Group access here is not something `openvox-ca` created. Every key it writes on
this backend is `0600`, so a group-readable key in a filesystem cadir came from
outside it — a Kubernetes `fsGroup` ORing group access into the mounted volume
at every mount, somebody's `chmod`, or the OpenVox Server that created the
cadir. It is
tolerated rather than expected, because those are legitimate deployments and the
CA cannot tell from the inside whether that group has members other than itself.
(On the SQLite backend the store genuinely is created group-accessible; that is
described [below](#sqlite-backend).)
`insecure_allow_world_readable_keys` downgrades the refusal to a loud warning if
you need the CA running in order to fix the thing it is refusing over.

There is a second refusal, and the opt-out does not cover it: a path holding key
material whose permissions could not be read **at all**. The CA names the path
and the underlying error and stops. The usual cause is a parent directory the CA
user cannot search. It is separate because it is a different condition with a
different remedy — `chmod o-rwx` clears nothing here — and the opt-out says "I
have weighed this risk", which nobody can have done for a mode nobody knows.

`locks/` holds lock files, not CA state — named after a hash of the lock rather
than anything readable. They are how a second process on the same host is kept
from writing behind a running server's back; see [Running a second process
against a live store](#running-a-second-process-against-a-live-store).

Two things to expect of them. There is one per distinct lock name, and that
**includes one per subject**, so on a large fleet the directory holds roughly as
many files as `signed/` and never shrinks — retiring a node with
`openvox-ca-ctl clean` removes its certificate, not its lock file.

And with one exception their contents tell you nothing: the per-name lock files
are empty whether the lock is held or not, and whether one is held is visible
only to `fuser`/`lsof`. The exception is the store-wide instance lock, which
records the process holding it — binary name, pid, host and the time it started
— so that a refused second instance can name it. A non-empty lock file is
therefore normal and is **not** a sign of corruption; the record may equally
well name a process that has since exited, because the file outlives every
holder and the kernel releases the lock without erasing it.

Do not delete them while anything may be using the store — see the deletion
hazard in [locking and concurrency](development/locking.md). Sweeping them while
everything is stopped is safe, and backing them up is harmless.

### Configuration

Default. Nothing to set.

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: filesystem   # optional; this is the default
cadir: /etc/puppetlabs/puppet/ssl/ca
```

### Sharing the cadir with OpenVox Server

A cadir works with either openvox-ca or OpenVox Server's own CA, as it stands.
openvox-ca keeps the CA key where OpenVox Server does, and writes each
`inventory.txt` line in OpenVox Server's format: a `0x` serial zero-padded to
four hex digits, and `/CN=<certname>`. It reads every line in that format and in
the one it used before (`<serial> ... /<certname>`), in the same file, and never
rewrites a line except to drop an expired one during cleanup.

That covers a cadir OpenVox Server created and one this version of openvox-ca
created. A cadir an earlier openvox-ca created keeps its key in
`private/ca_key.pem`, where openvox-ca goes on reading and writing it; OpenVox
Server looks for the key at the top of the cadir, so it cannot take that
directory as it stands.

- **To start openvox-ca on OpenVox Server's cadir**, stop OpenVox Server's CA
  and point `cadir` at the directory. There is no import step. The first start
  logs `No inventory HMAC found on an established CA` at `WARN`, once, as it
  establishes the integrity value over an inventory nothing has verified.
- **To go back to OpenVox Server**, stop openvox-ca (and disable its unit, or
  it starts again at the next boot) and start OpenVox Server's CA on the same
  directory. Nothing in it needs changing first. Keep a copy of `inventory.txt`
  somewhere outside it if you may come back: it is what lets you check, before
  returning, that OpenVox Server only appended. One thing does
  not carry over: a [delayed revocation](configuration.md#delayed-supersession)
  still pending in `superseded.json`. OpenVox Server ignores that file, so a
  certificate openvox-ca replaced within the last
  `superseded_cert_revoke_after_sec` stays valid until it expires, or until
  openvox-ca takes the directory back and its sweep resumes. To have those
  revocations in force under OpenVox Server, retire them first with
  `openvox-ca-ctl revoke --serial <hex>`, or let the sweep empty the file.
- **To return to openvox-ca after OpenVox Server has signed anything**, rebuild
  the inventory integrity value first. OpenVox Server appends to
  `inventory.txt` without updating `.inventory.hmac`, so openvox-ca will not
  start until you do; see
  [`rebuild-inventory-hmac`](operator-cli.md#rebuild-inventory-hmac-re-asserting-inventory-integrity).
  That is the only preparation.

Two conditions apply, and neither is about the directory's contents.

1. **Both must run as the same user.** openvox-ca cannot read a key OpenVox
   Server created group-readable for `puppet`, and the files openvox-ca creates
   are private to its own user, so OpenVox Server could not read them otherwise.
   This is already satisfied: OpenVox Server runs as `puppet`, and so does the
   shipped systemd unit, so no drop-in and no group change is needed. The
   configuration is `0640 root:puppet`, so `sudo -u puppet openvox-ca …` can
   read it as well. The cost is the one [sharing the `puppet`
   account](systemd.md#why-puppet-and-not-a-private-account) describes: OpenVox
   Server can read openvox-ca's `private/` files, including the inventory
   integrity key.
2. **The CA key must be a plain PEM file in the cadir**, because that is the
   only kind OpenVox Server can use. With `encrypt_ca_key`, `ca_key_file`
   pointing elsewhere, or the [OpenBao Transit](openbao-transit.md) key
   provider, the cadir does not hold a key OpenVox Server can sign with.

The other backends do not share a format with OpenVox Server. Moving to one is a
conversion, done by [`openvox-ca-ctl migrate`](#migrating-between-backends).

---

## etcd backend

Stores the CA in an etcd v3 cluster. Multiple `openvox-ca` replicas can point at
the same cluster (and the same `etcd_key_prefix`) to share one CA. `cadir` is
still required for per-subject generated keys and ancillary local state.

### Configuration

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: etcd
# still needed for per-subject keys and ancillary local state
cadir: /etc/puppetlabs/puppet/ssl/ca

etcd_endpoints:
  - https://etcd-0.example.com:2379
  - https://etcd-1.example.com:2379
  - https://etcd-2.example.com:2379
etcd_key_prefix: /puppet-ca               # default shown; override to
                                         # share a cluster between CAs
etcd_dial_timeout_sec: 5
etcd_request_timeout_sec: 5

# Optional authentication.
etcd_username: openvox-ca
etcd_password: "..."                     # prefer PUPPET_CA_ETCD_PASSWORD

# Optional mTLS to the etcd cluster.
etcd_tls_ca_file:   /etc/puppet-ca/etcd-ca.pem
etcd_tls_cert_file: /etc/puppet-ca/etcd-client.pem
etcd_tls_key_file:  /etc/puppet-ca/etcd-client-key.pem
```

### CLI flags

```text
--storage-backend etcd
--etcd-endpoints  https://etcd-0:2379,https://etcd-1:2379,https://etcd-2:2379
--etcd-key-prefix /puppet-ca
```

### Environment variables

| Config key | Env var |
| --- | --- |
| `storage_backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `etcd_endpoints` | `PUPPET_CA_ETCD_ENDPOINTS` (comma-separated) |
| `etcd_key_prefix` | `PUPPET_CA_ETCD_KEY_PREFIX` |
| `etcd_username` | `PUPPET_CA_ETCD_USERNAME` |
| `etcd_password` | `PUPPET_CA_ETCD_PASSWORD` |
| `etcd_dial_timeout_sec` | `PUPPET_CA_ETCD_DIAL_TIMEOUT_SEC` |
| `etcd_request_timeout_sec` | `PUPPET_CA_ETCD_REQUEST_TIMEOUT_SEC` |
| `etcd_tls_ca_file` | `PUPPET_CA_ETCD_TLS_CA_FILE` |
| `etcd_tls_cert_file` | `PUPPET_CA_ETCD_TLS_CERT_FILE` |
| `etcd_tls_key_file` | `PUPPET_CA_ETCD_TLS_KEY_FILE` |

### Operational notes

- **The CA private key lives in etcd by default.** That lets a new replica join
  without copying the key out of band, but it makes the etcd cluster part of the
  CA key's blast radius. Restrict etcd ACLs to the `openvox-ca` identity, enable
  [CA key encryption at rest](ca-key-security.md) (`encrypt_ca_key: true`), or
  pin the key to a local file with `ca_key_file` (see
  [CA cert/key as local files](#ca-certkey-as-local-files)).
- **`openvox-ca-ctl setup` / `import` work on the local filesystem only.** To
  import a CA into an etcd-backed cluster, run them against a scratch directory
  first, then point `openvox-ca` at a cadir containing the output.
- **The certificate inventory is stored as one etcd key per issued
  certificate**, not as a single ever-growing text blob, so signing cost does
  not grow with the size of the inventory and duplicate serial numbers are
  rejected atomically across all replicas (see
  [the inventory internals](development/inventory-store.md)). On first start
  after upgrading from a version that stored the inventory as a blob, the
  backend converts it in place automatically: the blob is first verified
  against its stored HMAC (a mismatch fails startup, exactly as it would have
  before the upgrade), and after the conversion the integrity value is
  re-established over the converted entries — the conversion window itself is
  the one moment tamper detection does not cover. An interrupted conversion
  resumes safely on the next start. **Upgrade all replicas together**: a
  not-yet-upgraded replica writing the old blob format while an upgraded one
  serves the converted inventory is not supported and is refused with an
  explicit error when detected.
- **The conversion is one-way; take a snapshot before the first upgraded
  start.** Downgrading to a release that predates it is not supported, and
  fails quietly rather than loudly: the old binary reads `inventory/data`,
  finds the empty marker the conversion left, and reports an *empty* inventory
  rather than an error — so it prunes nothing, and starts appending new
  issuances to the legacy blob. Upgrading again is then refused, because the
  blob and the decomposed entries no longer agree. Recovery is a restore from
  an etcd snapshot taken before the upgrade, so take one.
- **The etcd backend also maintains the certificate index**: `GET
  /certificate_statuses` (`puppetserver ca list`) is answered from the
  decomposed inventory entries instead of reading and parsing every stored
  certificate, with the same rebuildable-projection semantics as the SQL
  backends — after migrating from another backend the display fields are
  backfilled automatically on the next server start. Note the first start
  after an upgrade or migration therefore performs both the inventory
  conversion and a per-certificate projection backfill before serving; on a
  large fleet expect it to take a while (progress is logged).
- **Bulk inventory rewrites are batched.** Imports and prunes larger than one
  etcd transaction are split into multiple transactions; batch sizes stay
  well under etcd's default `--max-txn-ops` (128), so no cluster tuning is
  needed. Every *prune* transaction leaves the inventory and its integrity
  head consistent, and a single expired-certificate cleanup pass removes at
  most 900 entries so a large backlog drains over several runs rather than
  stalling signing. At the default daily cleanup interval that is 900
  entries/day: enabling cleanup for the first time on a large backlog, or
  running a fleet whose expiry churn exceeds it, calls for a shorter
  `expired_cert_cleanup_interval_sec` — the server logs every deferral, and
  escalates to a warning once the deferred backlog exceeds what a whole pass
  can remove, which is the point at which the backlog is growing rather than
  draining. An in-progress *conversion* is instead covered by the
  blob-stays-authoritative resume behaviour described above.
- **Legacy inventories with duplicate serial numbers** (possible, because the
  pre-conversion blob had no cluster-wide uniqueness guarantee) are imported
  verbatim with a startup warning naming the serials. The certificate index
  cannot track per-serial state for them, so their status in
  `certificate_statuses` output is derived from the signed CRL on each
  request (always correct, slightly slower) and their display fields come
  from the stored certificate. This resolves itself once the affected
  certificates expire and are cleaned up, or when they are revoked and
  reissued under fresh serials.

---

## Redis / Valkey backend

Stores the CA in a Redis instance, a Valkey instance (a wire-compatible fork of
Redis), or a Sentinel-managed primary. Multiple `openvox-ca` replicas can share
one instance (and the same `redis_key_prefix`). `redis` and `valkey` are
accepted as aliases. `cadir` is still required for per-subject keys and
ancillary local state.

Redis replication under Sentinel is asynchronous, so an in-flight failover
leaves a narrow window during which cross-replica coordination is weaker than
etcd's. For `openvox-ca`'s workloads that window is small and self-healing;
operators who need the strictest cross-node consistency should prefer `etcd`.

### Configuration — direct connection

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: redis                   # or "valkey"
# still needed for per-subject keys and ancillary local state
cadir: /etc/puppetlabs/puppet/ssl/ca

redis_addrs:
  - redis-0.example.com:6379             # first address is used in direct mode

redis_key_prefix: puppet-ca               # default shown; override to share
                                         # an instance between CAs
redis_db: 0                              # logical database (default 0)

redis_dial_timeout_sec: 5
redis_request_timeout_sec: 5
redis_lock_ttl_sec: 30

# Optional auth (ACL user + password; use PUPPET_CA_REDIS_PASSWORD for secrets).
redis_username: openvox-ca
redis_password: "..."

# Optional TLS to the Redis primary.
redis_tls_ca_file:   /etc/puppet-ca/redis-ca.pem
redis_tls_cert_file: /etc/puppet-ca/redis-client.pem
redis_tls_key_file:  /etc/puppet-ca/redis-client-key.pem
```

### Configuration — Sentinel-managed failover

Set `redis_sentinel_master_name` (and leave `redis_addrs` empty) to route
through Sentinels. The client discovers the current primary and follows
failovers automatically.

```yaml
storage_backend: redis
cadir: /etc/puppetlabs/puppet/ssl/ca

redis_sentinel_master_name: mymaster
redis_sentinel_addrs:
  - sentinel-0.example.com:26379
  - sentinel-1.example.com:26379
  - sentinel-2.example.com:26379

# Optional auth against the Sentinels themselves (distinct from Redis auth).
redis_sentinel_username: openvox-ca
redis_sentinel_password: "..."

# Auth / TLS against the primary — same fields as direct mode.
redis_username: openvox-ca
redis_password: "..."
redis_tls_ca_file:   /etc/puppet-ca/redis-ca.pem
redis_tls_cert_file: /etc/puppet-ca/redis-client.pem
redis_tls_key_file:  /etc/puppet-ca/redis-client-key.pem
```

### CLI flags

```text
--storage-backend           redis
--redis-addrs               redis-0:6379,redis-1:6379
--redis-sentinel-master-name mymaster
--redis-sentinel-addrs      sentinel-0:26379,sentinel-1:26379
--redis-key-prefix          puppet-ca
```

### Environment variables

| Config key | Env var |
| --- | --- |
| `storage_backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `redis_addrs` | `PUPPET_CA_REDIS_ADDRS` (comma-separated) |
| `redis_sentinel_master_name` | `PUPPET_CA_REDIS_SENTINEL_MASTER_NAME` |
| `redis_sentinel_addrs` | `PUPPET_CA_REDIS_SENTINEL_ADDRS` (comma-separated) |
| `redis_sentinel_username` | `PUPPET_CA_REDIS_SENTINEL_USERNAME` |
| `redis_sentinel_password` | `PUPPET_CA_REDIS_SENTINEL_PASSWORD` |
| `redis_db` | `PUPPET_CA_REDIS_DB` |
| `redis_username` | `PUPPET_CA_REDIS_USERNAME` |
| `redis_password` | `PUPPET_CA_REDIS_PASSWORD` |
| `redis_key_prefix` | `PUPPET_CA_REDIS_KEY_PREFIX` |
| `redis_dial_timeout_sec` | `PUPPET_CA_REDIS_DIAL_TIMEOUT_SEC` |
| `redis_request_timeout_sec` | `PUPPET_CA_REDIS_REQUEST_TIMEOUT_SEC` |
| `redis_lock_ttl_sec` | `PUPPET_CA_REDIS_LOCK_TTL_SEC` |
| `redis_tls_ca_file` | `PUPPET_CA_REDIS_TLS_CA_FILE` |
| `redis_tls_cert_file` | `PUPPET_CA_REDIS_TLS_CERT_FILE` |
| `redis_tls_key_file` | `PUPPET_CA_REDIS_TLS_KEY_FILE` |

### Operational notes

- **Persistence.** Make sure the instance is durable enough for CA state (RDB
  snapshots and/or AOF). A pure in-memory instance with no persistence loses the
  CA on restart.
- **The CA private key lives in Redis by default.** Restrict ACLs, enable
  `encrypt_ca_key`, or pin the key to a local file with `ca_key_file` (see
  [CA cert/key as local files](#ca-certkey-as-local-files)).
- **`openvox-ca-ctl setup` / `import` work on the local filesystem only.**
  Bootstrap/import against a scratch directory, then point `openvox-ca` at a
  cadir containing the output.
- **The certificate inventory is stored as one hash field per issued
  certificate**, not as a single ever-growing text value, so signing cost does
  not grow with the size of the inventory and duplicate serial numbers are
  rejected atomically across all replicas (see
  [the inventory internals](development/inventory-store.md)). On first start
  after upgrading from a version that stored the inventory as a blob, the
  backend converts it in place automatically: the blob is first verified
  against its stored HMAC (a mismatch fails startup, exactly as it would have
  before the upgrade), and after the conversion the integrity value is
  re-established over the converted entries — the conversion window itself is
  the one moment tamper detection does not cover. An interrupted conversion
  resumes safely on the next start. **Upgrade all replicas together**: a
  not-yet-upgraded replica writing the old blob format while an upgraded one
  serves the converted inventory is not supported and is refused with an
  explicit error when detected.
- **The conversion is one-way; take a snapshot before the first upgraded
  start.** Downgrading to a release that predates it is not supported, and
  fails quietly rather than loudly: the old binary reads `inventory:data`,
  finds the bare marker the conversion left, and reports an *empty* inventory
  rather than an error — so it prunes nothing, and starts appending new
  issuances to the legacy blob. Upgrading again is then refused, because the
  blob and the entries hash no longer agree. Recovery is a restore from a
  Redis snapshot (RDB/AOF) taken before the upgrade, so take one.
- **The Redis backend also maintains the certificate index**: `GET
  /certificate_statuses` (`puppetserver ca list`) is answered from the
  decomposed inventory entries instead of reading and parsing every stored
  certificate, with the same rebuildable-projection semantics as the SQL
  backends — after migrating from another backend the display fields are
  backfilled automatically on the next server start. Note the first start
  after an upgrade or migration therefore performs both the inventory
  conversion and a per-certificate projection backfill before serving; on a
  large fleet expect it to take a while (progress is logged).
- **Bulk inventory rewrites are bounded.** Redis executes a Lua script
  atomically, blocking every other client for its duration, so an inventory
  conversion is split into scripts of 512 records and a single
  expired-certificate cleanup pass removes at most 5000 entries. Each pass is
  atomic — the inventory and its integrity head are never observably out of
  step — and a large backlog simply drains over several runs rather than
  stalling signing. At the default daily cleanup interval that is 5000
  entries/day: enabling cleanup for the first time on a large backlog, or
  running a fleet whose expiry churn exceeds it, calls for a shorter
  `expired_cert_cleanup_interval_sec` — the server logs every deferral, and
  escalates to a warning once the deferred backlog exceeds what a whole pass
  can remove, which is the point at which the backlog is growing rather than
  draining.
- **Legacy inventories with duplicate serial numbers** (possible, because the
  pre-conversion blob had no cluster-wide uniqueness guarantee) are imported
  verbatim with a startup warning naming the serials. The certificate index
  cannot track per-serial state for them, so their status in
  `certificate_statuses` output is derived from the signed CRL on each
  request (always correct, slightly slower) and their display fields come
  from the stored certificate. This resolves itself once the affected
  certificates expire and are cleaned up, or when they are revoked and
  reissued under fresh serials.
- **Redis Cluster is not supported.** The backend dials a single primary,
  directly or through Sentinel. The inventory scripts span several keys, which
  Cluster would require to share a hash slot.

---

## SQL backends

The `sqlite`, `postgres` and `mysql` backends share one SQL implementation. The
backend creates and upgrades its own tables automatically on startup, so
multiple replicas can start against the same database safely. `cadir` is still
required for per-subject keys and ancillary local state.

> **Upgrading a PostgreSQL or MySQL deployment across this release.** The
> advisory-lock key derivation changed, so a server running either side of the
> change does not exclude one running the other side — for as long as both are
> up, nothing serialises CRL rewrites or bootstrap across the two generations.
> **Stop the old process before starting the new one** for this one upgrade:
> with the Helm chart set `strategy: {type: Recreate}` (an external-backend
> deployment otherwise derives `RollingUpdate`), or scale to zero and back. If
> you set the strategy, clear it again afterwards — a pin left in place keeps
> costing you a Recreate outage on every later upgrade.
>
> **One replica is not enough to be safe.** The derived `RollingUpdate` sets
> `maxUnavailable: 0`, so the new pod must become Ready before the old one is
> terminated, and the two overlap even at `replicaCount: 1`. What does exempt
> you is already being on `Recreate` (which `persistence.enabled: true`
> derives), or running a single process you stop and restart yourself. SQLite
> and the filesystem backend are unaffected either way: their same-host lock
> derives from `sha256(name).lock` and is unchanged. Background: rule 11 of
> [locking](development/locking.md).

SQL backends additionally maintain a certificate index (as do
[etcd](#etcd-backend) and [Redis](#redis--valkey-backend)): `GET
/certificate_statuses` (`puppetserver ca list`)
is answered from indexed columns instead of reading and parsing every stored
certificate, which matters for large fleets. The index is a rebuildable
projection of the stored certificates and the CRL — after migrating from
another backend it is backfilled automatically on the next server start.

### SQLite backend

Stores the entire CA in one SQLite database file — a convenient, dependency-free
alternative to the filesystem backend (one file to back up instead of a
directory tree). `sqlite` and `sqlite3` are accepted as aliases. It is
single-node, not a clustering option.

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: sqlite
cadir: /etc/puppetlabs/puppet/ssl/ca     # still needed for per-subject keys
# the SQLite database file path / URI
sql_dsn: "file:/etc/puppetlabs/puppet/ssl/ca/ca.db"

sql_request_timeout_sec: 10              # per-operation timeout (default 10)
sql_migration_timeout_sec: 600           # whole schema-migration run (default 600)
```

`openvox-ca` adds safe SQLite defaults to the DSN (WAL journal, immediate write
locking, a busy timeout) unless you set them yourself, so writers wait rather
than failing under contention.

A `file:` DSN is read as a URI, so its `%HH` escapes are decoded: `file:ca%20b.db`
names a database called `ca b.db`, and a path containing a literal `%` has to be
written `%25`. A DSN that cannot be read is refused at startup rather than left
unprotected — openvox-ca has to know which file the driver will open in order to
create it safely and to check its permissions later. There are two such
refusals, so you can search for whichever you see: `reading sqlite dsn ...` when
the DSN is not a URI at all, and `reading the database path out of sqlite dsn
...` when it is but its escapes cannot be decoded.

`mode=memory` is honoured only in the `file:` form, which is the only place
SQLite honours it. On a bare path (`/var/lib/puppet-ca/ca.db?mode=memory`) the
driver creates the file anyway, so openvox-ca protects and checks it like any
other database.

```text
--storage-backend sqlite
--sql-dsn         file:/etc/puppetlabs/puppet/ssl/ca/ca.db
```

**Operational notes.** The database file *is* the CA — back it up (with its WAL
sidecar) the way you would a cadir tree. The CA private key lives in the
database by default; enable `encrypt_ca_key` or pin it to a local file with
`ca_key_file`.

Because the key is in there, `openvox-ca` creates the database without any
access for users outside its owner and group, and the sidecars SQLite maintains
beside it (`-wal`, `-shm`, `-journal`) inherit that: SQLite takes their mode from
the database when it creates them. The sidecars matter as much as the database —
a committed page sits in the WAL until a checkpoint moves it, so which file holds
the key at a given moment is a matter of checkpoint timing.

Your umask still applies and can narrow it further: `0022` gives `0640`, `0077`
gives `0600`. What it cannot do is widen it, so the database is never created
world-readable however the process is launched.

Group access is deliberately allowed, so that a store owned by a Unix group is
reachable by that group without the CA widening anything afterwards — which it
will not do, since it never changes the mode of a file it did not create. If you
do not want it, set a umask: `0077` gives `0600` and nothing in the server
objects.

That group bit is not what makes a Kubernetes `fsGroup` volume work: the
kubelet ORs group access in at every mount whatever the file was created as, so
there the creation mode is irrelevant.

It is what lets a platform that assigns the pod a fresh uid per start, such as
OpenShift, reach a SQLite database and its locks that a previous uid created,
provided the uids share a group, the umask keeps group write, and the directory
holding the database is group-writable too (SQLite creates its sidecars there,
and `openvox-ca` creates the lock directory there). The same
restart has to reacquire the same-host locks, so those are created
group-accessible too: the files in `.<database>.locks/` at `0660` and the
directory at `0770`, narrowed by the umask the same way. The directory needs
group write because each subject's lock is a file of its own, created the first
time that subject is signed. Under the usual `0022` the database comes out
`0640` and the locks `0640` in a `0750` directory, which a second uid can
neither write nor create in, so on such a platform run `openvox-ca` under a
umask of `0002` or `0007` from the first start.

That covers the database and its locks, and nothing else. Every private key
`openvox-ca` writes as a file is created `0600` whatever the umask, in
directories without group write, so a second uid can neither read one an earlier
uid wrote nor add its own. On such a platform that rules out a CA key kept in a
file through `ca_key_file`, server-side key generation (`/generate`, which
writes into `<cadir>/private/` on every backend), and the filesystem backend
altogether. Keep the CA key in the database, or run with a stable uid.
[#523](https://github.com/voxpupuli/openvox-ca/issues/523) tracks server-side
generation.

Group read on the lock files has a cost of its own. `flock(2)` needs no write
access, so any member of the group can hold an existing lock, which can stop the
CA starting or stall signing and revocation. That is true under `0022` as well,
which leaves the lock files `0640`; only a umask that removes group read, such
as `0077`, prevents it.

**`openvox-ca` never changes the mode of a file it did not create.** Not the
database, not the sidecars, not the directory holding them. A store whose
permissions are wrong is yours to fix, and the server tells you rather than
quietly narrowing it.

What it does instead is refuse to start when key material is readable by every
local account:

```text
CA key material is world-accessible and readable by every local account
(/var/lib/puppet-ca/ca.db (mode -rw-r--r--), /var/lib/puppet-ca/ca.db-wal (mode
-rw-r--r--)); refusing to start -- fix with: chmod o-rwx -- /var/lib/puppet-ca/ca.db
/var/lib/puppet-ca/ca.db-wal, or set insecure_allow_world_readable_keys to start
anyway. A key that has been world-readable should be treated as exposed and
rotated
```

Every world-accessible file is named, not just the first, so one `chmod` clears
the condition instead of uncovering the next one on the following start. A key
every local account could read is one to treat as exposed, so the fix is `chmod
o-rwx` **and** deciding whether to rotate the CA key.

Group access is reported at `Info`, listing the files, and does not stop the CA.
On this backend it is the mode the store is created with, so a correct deployment
has it whether or not Kubernetes is involved. Where that group has
members other than the CA it is worth acting on, but that is not something the
server can tell from the inside, which is why it does not shout.

The check runs before the CA is initialised and before any child process is
forked, so a refusal happens before a key is written into a store that would
have been refused, and reaches you on the terminal even under `--daemon`.

Setting `insecure_allow_world_readable_keys` downgrades the refusal to a loud
warning. It exists so a world-readable store cannot lock you out of the CA you
need running in order to fix it, and it is named for what it is.

A DSN that is a symlink is resolved and works, including one planted before the
database exists — in that case the database is created at the link's target, not
at the link. Everything derived from the DSN — the sidecar names, and the
`.<database>.locks/` directory — comes from the resolved path, so two processes
reaching one database by different spellings still lock against each other.

Because creation follows the link, the directory holding the DSN path must not
be writable by untrusted users: whoever can plant a symlink there chooses where
the database is created. That is the same precondition the sidecars need, for
the same reason.

The directory holding the database is yours, and `openvox-ca` never changes its
mode. Anything that copies the database — a backup, a volume snapshot, a restored
tarball — has to preserve the modes, sidecars included.

`openvox-ca-ctl setup` / `import` work on the local filesystem
only; bootstrap against a scratch directory, then point a SQLite-backed
`openvox-ca` at a fresh database.

Alongside the database, `openvox-ca` keeps a hidden `.<database>.locks/`
directory — `.ca.db.locks/` for the DSN above — holding the lock files that stop
a second process on the host writing behind a running server's back, and the
store-wide lock that refuses a second instance outright. They are empty but for
that last one, which records its holder; see the note under [the filesystem
backend](#filesystem-backend-default).
The database file itself is never locked this way; SQLite locks that. See
[Running a second process against a live
store](#running-a-second-process-against-a-live-store).

### PostgreSQL backend

Stores the entire CA in a PostgreSQL database; multiple `openvox-ca` replicas
can share it. `postgres`, `postgresql` and `pg` are accepted as aliases.

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: postgres
cadir: /etc/puppetlabs/puppet/ssl/ca     # still needed for per-subject keys
sql_dsn: "postgres://puppetca:secret@db.example.com:5432/puppetca?sslmode=verify-full&sslrootcert=/etc/puppet-ca/pg-ca.pem"  # prefer PUPPET_CA_SQL_DSN or sql_dsn_file

sql_request_timeout_sec: 10              # per-operation timeout (default 10)
sql_migration_timeout_sec: 600           # whole schema-migration run (default 600)
sql_max_open_conns: 0                    # 0 = database/sql default; min 4 when set
sql_max_idle_conns: 0                    # 0 = database/sql default

# Alternatively, give the CA and a client certificate as files instead of
# the DSN's sslrootcert, sslcert and sslkey (not as well as them). The DSN's
# sslmode still decides what is checked; see below.
# sql_tls_ca_file:   /etc/puppet-ca/pg-ca.pem
# sql_tls_cert_file: /etc/puppet-ca/pg-client.pem
# sql_tls_key_file:  /etc/puppet-ca/pg-client-key.pem
```

TLS is driven either by the DSN's `sslmode` and `sslrootcert` parameters or by
the `sql_tls_*_file` options. In the DSN, use `sslmode=verify-full`: it encrypts
the connection, checks the server's certificate against `sslrootcert`, and
checks that the certificate names the host in the DSN. `sslmode=require`
encrypts the connection but does not verify the server's certificate at all,
and `verify-ca` checks the certificate without checking the host name; with
`sslrootcert` present, `require` behaves as `verify-ca`. PostgreSQL's
[SSL mode table](https://www.postgresql.org/docs/current/libpq-ssl.html#LIBPQ-SSL-SSLMODE-STATEMENTS)
sets out what each mode protects against.

The `sql_tls_*_file` options stand in for the DSN's `sslrootcert`, `sslcert`
and `sslkey`, and `sslmode` means the same with either:
`sql_tls_ca_file` with `sslmode=require` checks the certificate chain but not
the host name, exactly as `sslrootcert` with `sslmode=require` does. Without
`sql_tls_ca_file`, the server is checked against the system's trusted CAs.
`openvox-ca` refuses to open the database when the two ways conflict or the
files would go unused:

1. The DSN sets `sslrootcert`, `sslcert` or `sslkey` as well as an
   `sql_tls_*_file` option. Give each file one way only.
2. The DSN's `sslmode` is `disable`, `allow` or `prefer`, or is missing (which
   PostgreSQL treats as `prefer`). None of them verifies the server.
3. The DSN connects through a Unix socket, which PostgreSQL does not serve
   over TLS, or names several hosts.

Both `sslrootcert` and the `sql_tls_*_file` options are read once, when
`openvox-ca` opens the database. Connections already open keep working after the
database's CA is rotated, but new ones fail, so the connection pool runs down
gradually rather than all at once. Restart `openvox-ca` whenever the CA
changes; some operators issue database CAs that last only weeks or months.

On the command line, keep the password out of the arguments by putting the DSN
in a file (see [keeping the database password private](#keeping-the-database-password-private)):

```text
--storage-backend postgres
--sql-dsn-file    /etc/puppet-ca/sql-dsn   # contains postgres://puppetca:secret@db.example.com:5432/puppetca?sslmode=verify-full&sslrootcert=/etc/puppet-ca/pg-ca.pem
```

**Operational notes.** Back the database up with your normal PostgreSQL tooling.
The CA private key lives in the database by default; enable `encrypt_ca_key` or
pin it to a local file with `ca_key_file`. Grant the configured role rights to
create tables on first run (or pre-create the schema and grant DML).
`openvox-ca-ctl setup` / `import` work on the local filesystem only.

### MySQL / MariaDB backend

Stores the entire CA in a MySQL or MariaDB database; multiple `openvox-ca`
replicas can share it. `mysql` and `mariadb` are accepted as aliases.

```yaml
# /etc/puppet-ca/config.yaml
storage_backend: mysql                   # or "mariadb"
cadir: /etc/puppetlabs/puppet/ssl/ca     # still needed for per-subject keys
sql_dsn: "puppetca:secret@tcp(db.example.com:3306)/puppetca"  # prefer PUPPET_CA_SQL_DSN or sql_dsn_file

sql_request_timeout_sec: 10              # per-operation timeout (default 10)
sql_migration_timeout_sec: 600           # whole schema-migration run (default 600)

# Optional TLS to the server (registered with the driver automatically;
# no need to add tls= to the DSN).
sql_tls_ca_file:   /etc/puppet-ca/mysql-ca.pem
sql_tls_cert_file: /etc/puppet-ca/mysql-client.pem
sql_tls_key_file:  /etc/puppet-ca/mysql-client-key.pem
```

The DSN is the [go-sql-driver/mysql](https://github.com/go-sql-driver/mysql)
form (`user:pass@tcp(host:3306)/dbname`).

On the command line, as for PostgreSQL:

```text
--storage-backend mysql
--sql-dsn-file    /etc/puppet-ca/sql-dsn   # contains puppetca:secret@tcp(db.example.com:3306)/puppetca
```

**Operational notes.** The CA private key lives in the database by default;
enable `encrypt_ca_key` or pin it to a local file with `ca_key_file`.
`openvox-ca-ctl setup` / `import` work on the local filesystem only.

Do not point two independent `openvox-ca` deployments at one MySQL server, even
with separate databases. `GET_LOCK` names are scoped to the server instance
rather than to a schema, so both deployments take the same lock names and
serialise against each other. (Multiple replicas of *one* deployment sharing a
database is the supported arrangement and is exactly what those locks are for.)
PostgreSQL advisory locks are database-scoped, so the equivalent there is not to
share a *database* with another application that uses `pg_advisory_lock`.

### Keeping the database password private

A PostgreSQL or MySQL DSN usually carries the database password, and that
password fronts the store holding the CA's own key. Do not pass it with
`--sql-dsn`. Every local user can read a process's command line (`ps`,
`/proc/<pid>/cmdline`), and in Kubernetes anyone who can `get pods` can read it
too. In the default topology `openvox-ca` also re-executes itself for the
signer and the frontend with the same arguments, so the password is on show in
three processes. It logs a warning at startup when `--sql-dsn` carries one.

Use one of these instead:

- **`sql_dsn_file` / `--sql-dsn-file` / `PUPPET_CA_SQL_DSN_FILE`**: the path to
  a file whose first line is the DSN. Surrounding whitespace is trimmed. Make
  it readable by the account `openvox-ca` runs as and nobody else: under the
  shipped systemd unit that is `root:puppet` with mode `0640`, as
  [running under systemd](systemd.md) sets up the config file. In
  Kubernetes, mount the Secret as a file. The file is read when `openvox-ca`
  opens the database, not for each connection, so restart `openvox-ca` after
  changing the password.
- **`sql_dsn`** in the config file, which should then be readable by the
  same account only, as above.
- **`PUPPET_CA_SQL_DSN`**. A process's environment is readable only by its own
  user and root, but child processes inherit it.

`sql_dsn` and `sql_dsn_file` are mutually exclusive, whichever of the config
file, environment or command line each comes from. Setting both is refused at
startup rather than one silently overriding the other.

`openvox-ca-ctl migrate` reads `sql_dsn_file` from its `--source-config` and
`--dest-config` files in the same way.

### SQL environment variables

The SQL backends share one set of config keys and environment variables:

| Config key | Env var |
| --- | --- |
| `storage_backend` | `PUPPET_CA_STORAGE_BACKEND` |
| `sql_dsn` | `PUPPET_CA_SQL_DSN` |
| `sql_dsn_file` | `PUPPET_CA_SQL_DSN_FILE` |
| `sql_request_timeout_sec` | `PUPPET_CA_SQL_REQUEST_TIMEOUT_SEC` |
| `sql_max_open_conns` | `PUPPET_CA_SQL_MAX_OPEN_CONNS` |
| `sql_max_idle_conns` | `PUPPET_CA_SQL_MAX_IDLE_CONNS` |
| `sql_migration_timeout_sec` | `PUPPET_CA_SQL_MIGRATION_TIMEOUT_SEC` |
| `sql_tls_ca_file` | `PUPPET_CA_SQL_TLS_CA_FILE` |
| `sql_tls_cert_file` | `PUPPET_CA_SQL_TLS_CERT_FILE` |
| `sql_tls_key_file` | `PUPPET_CA_SQL_TLS_KEY_FILE` |

The pool-tuning and TLS settings apply only to the networked SQL dialects;
SQLite ignores them.

`sql_max_open_conns`, when set to a non-zero value below 4, is raised to 4 and
the effective value is logged at startup. The distributed locks are
session-scoped (PostgreSQL advisory locks and MySQL `GET_LOCK` both bind to
their connection), so each lock held occupies a connection for its lifetime
while the work under it needs another. A `migrate` run nests three deep — the
bootstrap lock, the migration lock inside it, and the migration's own
statements. A smaller pool would not merely be slow, it would deadlock, so the
floor is not negotiable. Leave the setting at 0 unless you have measured a
reason to cap it.

That floor covers `migrate`; it does not size a busy server. The requests that
retire a certificate — `Revoke`, `Clean`, and the renewal paths when they retire
the certificate they replaced — take `subject:<name>` and then, inside it, the
cluster-wide `crl` lock, so each one in flight wants three connections at once:
one per held lock, plus one for its own reads and writes. A plain sign or CSR
submission takes only `subject:<name>` and wants two.

Revocation joined that set in this release, and the cost shows up when
revocations overlap — several admin clients or an orchestration tool issuing
`PUT`/`DELETE /certificate_status/{subject}` for *distinct* subjects at once.
Throughput is unchanged, because they still queue one at a time on the single
`crl` lock; what changed is that each one now holds its own `subject:<name>`
connection for the whole of that wait instead of queueing without one. Size the
pool for the retirements you expect to overlap rather than for a single request.
Note that `PUT /clean` is not that case: it processes its certnames
sequentially, so a bulk clean holds one subject lock at a time and has always
paid this cost. See rule 8 in the
[locking notes](development/locking.md#rules-for-new-or-changed-code) for the
invariant behind this.

---

## CA cert/key as local files

Sometimes you want the benefits of a shared backend (agents, CSRs, signed
certs, CRL) without exposing the CA cert or private key in that backend.
Common scenarios:

- **Secret volume / HSM-adjacent.** The key is mounted from a Kubernetes
  secret, an encrypted tmpfs, or a path an HSM driver populates.
- **Operator-supplied cert.** The CA cert came from an offline ceremony and
  should never be rewritten by the server.

Set either or both of these options and the named asset is read/written
against the given local path instead of the selected backend. Everything
else (CSRs, signed certs, CRL, inventory, serial) still flows through the
configured backend.

### Configuration

```yaml
storage_backend: etcd
cadir: /etc/puppetlabs/puppet/ssl/ca
etcd_endpoints: [https://etcd:2379]

# Keep the CA cert and key out of etcd; mount them from the host.
ca_cert_file: /etc/puppet-ca/secrets/ca_crt.pem
ca_key_file:  /etc/puppet-ca/secrets/ca_key.pem
```

### CLI flags

```text
--ca-cert-file /etc/puppet-ca/secrets/ca_crt.pem
--ca-key-file  /etc/puppet-ca/secrets/ca_key.pem
```

### Environment variables

| Config key | Env var |
| --- | --- |
| `ca_cert_file` | `PUPPET_CA_CA_CERT_FILE` |
| `ca_key_file` | `PUPPET_CA_CA_KEY_FILE` |

### Behaviour

- On **first start** with no existing CA, `openvox-ca` bootstraps a new CA
  and writes the cert/key to the configured local paths (not the backend).
- A populated `ca_key_file` with **no** CA certificate is refused rather than
  bootstrapped over. That state is what `openvox-ca csr --create-key` leaves
  behind while a parent signs the request, and also what a partial restore or an
  interrupted bootstrap looks like; overwriting the key would orphan every
  certificate issued under it, and would destroy the key an outstanding signing
  request is bound to. The startup error names the three ways out: install the
  signed chain with `openvox-ca import-ca-cert`, restore the certificate, or
  remove the orphaned key. See
  [offline subcommands on the server binary](operator-cli.md#offline-subcommands-on-the-server-binary),
  and [removing an orphaned CA key](#removing-an-orphaned-ca-key) below for how
  to do the last of those on each backend.
- On subsequent starts, the cert and key are loaded from the local paths.
- `openvox-ca` writes the cert at mode `0644` and the key at mode `0600`
  atomically (temp-file + rename). If you supply pre-existing files, they are
  read as-is and never overwritten unless the server rotates the CA.
- A supplied `ca_key_file` is checked at startup on **every** backend, like any
  other file holding key material: world access refuses startup, group access is
  reported at `Info`. Where the path is a read-only mount — a Kubernetes Secret
  volume — `chmod` will not work and the fix belongs in the volume, as
  `defaultMode: 0600`.
- Existing protections still apply: `encrypt_ca_key` encrypts the key PEM
  before writing, and `ca_key_passphrase_file` is where its passphrase comes
  from. There is no default source: with `encrypt_ca_key` set and neither
  `ca_key_passphrase_file` nor `PUPPET_CA_KEY_PASSPHRASE` configured, the
  server refuses to start.

This override also works with the filesystem backend, e.g. to pull the CA
key out of the cadir tree and onto a separately-mounted volume.

---

### Removing an orphaned CA key

A CA key with no CA certificate makes the server refuse to start, deliberately —
see [Behaviour](#behaviour) above. If the key really is orphaned (no signing
request is outstanding and no certificate is coming), removing it lets the CA
bootstrap afresh. **This retires the CA:** every certificate already issued
stops verifying, and every agent must be re-enrolled. There is no
`openvox-ca-ctl` command for it precisely because it is not an operation to
perform casually. Take a backup and stop the CA first.

Where the key lives depends on the backend. Note the physical names differ from
the logical key `ca_key`:

| Backend | Where the key is | How to remove it |
| --- | --- | --- |
| `filesystem` (default) | `ca_key.pem` under the cadir (or `private/ca_key.pem`, if that is where it is) | `rm` the file |
| `ca_key_file` overlay | the configured path | `rm` the file |
| `sqlite`, `postgres`, `mysql` | table `puppet_ca_blobs`, column `blob_key`, value `ca_key` | `DELETE FROM puppet_ca_blobs WHERE blob_key = 'ca_key';` |
| `etcd` | `<prefix>/ca/key` | `etcdctl del <prefix>/ca/key` |
| `redis` / `valkey` | `<prefix>:ca:key` | `redis-cli DEL <prefix>:ca:key` |

The column is `blob_key` rather than `key` because `KEY` is reserved in
MySQL/MariaDB. The etcd and Redis paths are `ca/key` and `ca:key`, not `ca_key` —
and both `etcdctl del` and `redis-cli DEL` exit successfully having deleted
nothing when the name is wrong, so check the reported count. A zero means you
have the wrong name, not that the problem is solved. Do not reach for
`del --prefix` to compensate: that removes the whole CA.

#### With the CA key at a provider

`ca_key_provider: openbao` puts the key in a Transit engine rather than a
storage backend, and `HasCAKey` asks the provider directly — so a populated
Transit slot counts as present however empty the backend is. Three routes exist
for abandoning a half-finished sub-CA, and only the first two are cheap:

1. **Finish the round trip.** Have the parent sign the outstanding request and
   install it with `openvox-ca import-ca-cert`. This is the intended path and
   costs nothing.
2. **Have any CA you control sign the outstanding request.** `openvox-ca csr`
   emits a PKCS#10 request bound to the Transit key; a throwaway root made with
   `openssl` or `bao pki` can sign it, and `import-ca-cert` accepts the result
   (a lone self-signed CA is a valid bundle). This satisfies the startup check
   without touching the key. Note that *self*-signing a certificate for a
   non-exportable Transit key is not one of the options: it would mean signing a
   TBSCertificate with the Transit key and assembling the DER by hand, and
   neither `openvox-ca` nor `openvox-ca-ctl` will do that.
3. **Delete the Transit key**, which requires `deletion_allowed` on it, and let
   the CA bootstrap afresh. Irreversible, and it retires the CA as above.

Deleting the *CA certificate* and keeping the key is **not** a route: that is
exactly the state the startup refusal exists for, so the server will not
bootstrap over it. It leaves you with less to recover from and no closer to a
working CA.

## Migrating between backends

`openvox-ca-ctl migrate` copies an entire CA from one backend to another. Any
pair can be combined:

- import an existing filesystem CA into a database (`filesystem` → `postgres`),
- move between databases or stores (`redis`/`valkey` → `postgres`, `etcd` →
  `sqlite`, …),
- export a database back to a plain directory of files (`postgres` →
  `filesystem`), e.g. for an offline backup or to revert to a single-node setup.

Both ends are described by ordinary `openvox-ca` config files — the same YAML the
server reads. `--source-config` is read from; `--dest-config` is written to.

```bash
# Import a filesystem CA into PostgreSQL.
openvox-ca-ctl migrate \
  --source-config /etc/puppet-ca/filesystem.yaml \
  --dest-config   /etc/puppet-ca/postgres.yaml

# Export it back out to a directory of files.
openvox-ca-ctl migrate \
  --source-config /etc/puppet-ca/postgres.yaml \
  --dest-config   /etc/puppet-ca/filesystem.yaml
```

Each config file needs only the storage fields (plus `cadir`); for example a
minimal SQLite target:

```yaml
# sqlite.yaml
storage_backend: sqlite
cadir: /etc/puppetlabs/puppet/ssl/ca
sql_dsn: file:/etc/puppetlabs/puppet/ssl/ca/ca.db
```

The migration copies the whole CA — certificate, keys, CRL, serial, the
inventory (its integrity value is recomputed under the destination's own
scheme, so tamper detection continues to work there), every pending CSR and
every signed certificate. The inventory's lines are converted when exactly one end is
the filesystem backend: into a database they are read in either form and stored
in the canonical one, and onto the filesystem they are written in OpenVox
Server's format, so the result can be [shared with OpenVox
Server](#sharing-the-cadir-with-openvox-server). Between two backends of the
same kind they are copied unchanged. Per-subject generated private keys are **not** copied: they
always live on the local filesystem under `cadir`, so on a remote backend they
stay put across a migration. The `ca_cert_file` / `ca_key_file` overrides are
honoured on both ends.

Notes:

- **Stop the server first**, on both ends. Run `migrate` while no `openvox-ca`
  is serving either backend, so the copy sees a consistent snapshot. It does not
  race one that is, and it no longer waits for one either: on a backend that
  supports a single running instance it is refused at once, naming the process
  holding the store, for the source as well as the destination — reading a live
  store still copies an inventory the server is appending to. Pointing
  `--source-config` and `--dest-config` at the same store is refused for the
  same reason, rather than waiting for ever on a lock it has already taken
  itself. See [running a second process against a live
  store](#running-a-second-process-against-a-live-store).
- **Overwrite protection.** `migrate` refuses to write into a destination that
  already holds a CA certificate. Pass `--force` to overwrite it.
- **The source inventory is verified first.** Because the destination's
  integrity value is recomputed over whatever is copied, a mismatch present
  before the copy would not survive it, so `migrate` checks the source against
  its own stored value before touching the destination. It refuses a source
  that does not verify: one whose inventory does not match the value, one with
  an HMAC key but no value or a value but no key, one whose key is the wrong
  length, and an etcd or Redis store whose legacy inventory has not yet been
  decomposed. Run [`openvox-ca
  rebuild-inventory-hmac`](operator-cli.md#rebuild-inventory-hmac-re-asserting-inventory-integrity)
  with the source's configuration to see its state, or pass
  `--allow-unverified-source` to migrate it as it stands, which makes the
  destination vouch for it. A source that never recorded an integrity value at
  all — no HMAC key and no value, such as a cadir written by OpenVox Server — is
  migrated without the flag, since there is nothing to verify it against. Either
  way `migrate` prints a warning saying the source was not verified. A source
  with no HMAC key gives the destination none either, unless it already had
  one, so its first start then logs `No inventory HMAC found on an established
  CA` at `WARN`, once, as it establishes the value.
- **Re-runnable.** The copy is idempotent per item; an interrupted run can be
  repeated (with `--force` if a partial CA already landed).
- Use `--verbose` to log each item as it is copied.

---

## Choosing a backend

| | `filesystem` | `sqlite` | `postgres` / `mysql` | `etcd` | `redis` / `valkey` |
| --- | --- | --- | --- | --- | --- |
| Replicas | one active | one active | many (active/active) | many (active/active) | many (active/active) |
| Operational dependencies | none | none (single file) | SQL server | healthy etcd cluster | Redis/Valkey primary (+ Sentinel) |
| CA key exposure | local file | in DB unless `ca_key_file` set | in DB unless `ca_key_file` set | in etcd unless `ca_key_file` set | in Redis unless `ca_key_file` set |
| Backup/restore | tar `<cadir>/` | copy `.db` (+ WAL) + local dirs | DB dump + local dirs | etcd snapshot + local dirs | RDB/AOF + local dirs |
| Cross-node consistency | single node | single node | strong | strongest | strong (narrow failover window) |
| Second instance, same store | refused (`flock`) | refused (`flock`) | supported | supported | supported |
| Drop-in for OpenVox/Puppet Server CA | yes | no (key paths change) | no (key paths change) | no (key paths change) | no (key paths change) |

> **If you publish an upstream CRL chain**, note that `openvox-ca-ctl import`
> writes to a local filesystem directory only. On every backend except
> `filesystem` — and on any backend under `encrypt_ca_key` or
> `ca_key_provider: openbao` —
> [`crl_chain_file`](configuration.md#publishing-an-upstream-crl-chain) is not
> merely the better way to keep ancestor CRLs current, it is the only one that
> does not require stopping the CA. On a non-`filesystem` backend there is a
> `migrate` round trip if you cannot deliver a file to the pod — see
> [re-importing a chain](migrating-from-puppet-server.md#refreshing-ancestor-crls)
> for it, and for the limits. Under `encrypt_ca_key` or
> `ca_key_provider: openbao` there is **no** fallback: `import` cannot parse an
> encrypted key, feeding it the plaintext one silently replaces your encrypted
> key with a plaintext one, and under OpenBao there is no exportable key at all.

Use `filesystem` for single-node installs or migrating from an OpenVox/Puppet
Server CA. Use `sqlite` for a single-node install that prefers one database file
over a cadir tree (e.g. simpler backups). Use `postgres` or `mysql` when you
want multiple `openvox-ca` replicas backed by a database you already operate.
Use `etcd` when you need multiple replicas and want the strongest cross-node
guarantees. Use `redis`/`valkey` when you already run Redis/Valkey and are
willing to accept the narrower failover window in exchange for reusing existing
infrastructure.

---

## Internals

The on-disk / in-store key layout for each backend, the cross-node coordination
mechanisms, the SQL schema, and the inventory integrity design are documented in
[storage internals](development/storage-internals.md) and
[the inventory store](development/inventory-store.md) — reference material for
contributors, not needed to deploy.
