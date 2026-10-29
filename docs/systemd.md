# Running under systemd

`openvox-ca` speaks the systemd notification protocol ([`sd_notify(3)`](https://www.freedesktop.org/software/systemd/man/sd_notify.html)), so a unit can be `Type=notify` rather than `Type=simple`. That gives you four things:

- **`systemctl start` blocks until the CA is actually serving** — storage reachable, CA loaded (bootstrapped on a first run), listener accepting. Units ordered `After=openvox-ca.service` no longer race a cold start.
- **`systemctl status` says what the CA is doing**, both during startup and while it runs.
- **`systemctl reload` re-reads the TLS keypair and the admin allow list** without dropping connections.
- **An optional watchdog** restarts a CA that has stopped making progress.

None of it needs configuration. The protocol is driven entirely by `$NOTIFY_SOCKET`, which systemd sets; without it every notification is a no-op, so the same binary behaves normally under a shell, another supervisor, or in a container.

## Installing the unit

A ready-to-use unit ships in every [release tarball](../README.md#release-tarballs), alongside the two binaries.

The copy in the repository, [`packaging/systemd/openvox-ca.service`](https://github.com/voxpupuli/openvox-ca/blob/main/packaging/systemd/openvox-ca.service), is a **template** rather than an installable file: its `ExecStart` carries a placeholder that is substituted per channel, because a tarball is extracted by hand into `/usr/local` and a package owns `/usr/bin`. Building from source? `mage build:unit /usr/local/bin` renders it to `dist/openvox-ca.service`; `mage build:all` still puts the binaries in `bin/`.

Download, verify and extract a tarball as the README describes, then, from the extracted directory:

```console
$ getent group puppet >/dev/null || sudo groupadd --system puppet
$ getent passwd puppet >/dev/null || sudo useradd --system --gid puppet --home-dir /etc/puppetlabs/puppet --shell /usr/sbin/nologin puppet
$ sudo install -m 0755 openvox-ca openvox-ca-ctl /usr/local/bin/
$ sudo install -m 0644 openvox-ca.service /etc/systemd/system/
$ sudo install -d -m 0755 /etc/openvox-ca
$ sudoedit /etc/openvox-ca/config.yaml   # your own file; see configuration.md
$ sudo chown root:puppet /etc/openvox-ca/config.yaml && sudo chmod 0640 /etc/openvox-ca/config.yaml
$ sudo install -d -o puppet -g puppet -m 0770 /etc/puppetlabs/puppet/ssl/ca
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now openvox-ca.service
```

The first two lines create the `puppet` account only where it does not exist yet, so they are safe on a host where OpenVox Server — or an earlier run of this recipe — already created it.

The configuration file is yours to write — it is not in the tarball — and [configuring the server](configuration.md#config-file) has a worked example. Make it **0640 root:puppet**, because it can hold credentials — `etcd_password`, `redis_password`, `redis_sentinel_password`, or a `sql_dsn` with a password in it — and the service only needs to read it. The server auto-detects that path, so the unit passes no `--config` and `OPENVOX_CA_CONFIG` still works in a drop-in.

The unit as rendered for a tarball expects the binary at `/usr/local/bin/openvox-ca` (the packages' copy names `/usr/bin`) and its configuration at `/etc/openvox-ca/config.yaml`. See [configuring the server](configuration.md). It also reads `/etc/sysconfig/openvox-ca` if that exists; nothing creates it on a tarball install, but a variable set there outranks the same variable set with `Environment=` in a drop-in (see [the environment file on EL](#the-environment-file-on-el)).

**Set `cadir` to `/etc/puppetlabs/puppet/ssl/ca`**, which is the one writable path the unit grants (`ReadWritePaths=`), or the CA will not be able to write: `ProtectSystem=strict` makes the rest of the filesystem read-only, and a filesystem-backend CA has to write a signed certificate, a serial and a CRL. It is also the Clojure CA's own layout, so a CA migrated from OpenVox/Puppet Server is already there. To use a different directory, make it writable too — see [using a different CA directory](#using-a-different-ca-directory). If OpenVox Server's CA may take that directory back, openvox-ca must run as OpenVox Server's user, which the shipped unit already does (`User=puppet`); see [sharing the cadir with OpenVox Server](storage-backends.md#sharing-the-cadir-with-openvox-server).

### Using a different CA directory

`cadir` and the writable paths the units grant must always cover the same place. Grant a new one with a **drop-in**, not by editing a unit file:

```console
$ sudo systemctl edit openvox-ca
$ sudo systemctl edit openvox-ca-first-boot   # packaged installs only
```

and in each, add:

```ini
[Service]
ReadWritePaths=/srv/openvox-ca
```

A drop-in survives an upgrade; an edit does not. The packages install their units under `/usr/lib/systemd/system`, and every package upgrade replaces those files — so an edited `ReadWritePaths=` is reverted, the upgrade restarts the running CA, and it comes back unable to write its own store, with the upgrade itself reporting success. The same applies to a tarball's unit the next time you install a newer one over it. `ReadWritePaths=` in a drop-in adds to the unit's own rather than replacing it, so nothing else needs restating.

On a packaged install it is **both** units: the provisioning oneshot writes into `cadir` as well, under its own `ProtectSystem=strict`.

### Why `puppet` and not a private account

OpenVox Server creates `puppet:puppet` in its own `preinst` and chowns `/etc/puppetlabs/puppet/ssl` to it, so the tree openvox-ca needs to write is already expected to be owned by that account: running as it fits rather than intrudes. openvox-agent creates no account at all and runs as root.

openvox-ca does not assume either is installed. The packages create the account themselves, and the recipe above does it by hand, because the CA has to work on a host running neither. Divergence is tolerable in one direction only: Server's `preinst` runs `usermod` over an account it finds, so installing Server afterwards repairs the home directory and shell to its own values rather than creating a second account.

**What sharing the account costs, stated plainly.** On a host that also runs OpenVox Server, the CA's private key is now readable by Server's own uid — the two are the same account. Anything running as `puppet` can read the key that signs every certificate in the estate, so a compromise of Server is a compromise of the CA on that host, without a privilege boundary in between.

It can run the other way too, which is why **the package does not take the ssl root on a host where something else already keeps files in it.** Owning a directory is owning the right to rename what is in it, and renaming an entry within one directory needs write permission on that directory alone. So an account that owns `/etc/puppetlabs/puppet/ssl` can move a root-owned `certs/` aside, create its own, and supply the `certs/ca.pem` a root-running agent trusts — without ever being able to write inside the original. Leaving `certs/` itself root-owned protects nothing while its parent changes hands.

So the install always gives `puppet` the CA directory, `ssl/ca`, and gives it the ssl root only when everything already there is `puppet`'s: a fresh host, a host where this CA has already provisioned, or a host where OpenVox Server's own install has already handed the tree over. On a host where an agent created that tree as root, the root is left alone, and the install says so.

That does not make sharing a host with a root-running agent free. If provisioning there needs to write in the ssl tree, it stops and prints the `chown` that would let it — and that `chown` grants exactly what the install declined to: anything running as `puppet` could then choose which CA that agent believes in. It is your decision to take, knowing that.

**It is not only the CA key.** Anything the service reads as `puppet` is readable by everything else running as `puppet`: the configuration file and any credentials in it — `etcd_password`, the OpenBao AppRole `role_id` and `secret_id` files — and, on a filesystem backend, the whole cadir.

**Encrypting the CA key at rest does not reduce this.** [Encryption at rest](ca-key-security.md) protects a key that leaves the host — in a backup, a snapshot, a stolen disk — because whoever holds the file does not hold the passphrase. It does nothing against an attacker who *is* the `puppet` uid, because that account reads whatever decrypts the key as readily as the key itself: the server has to read its passphrase unattended in order to sign, so wherever it reads it from — a `ca_key_passphrase_file`, or `OPENVOX_CA_KEY_PASSPHRASE` in its environment — that account can read it too.

That is the price of fitting the layout Server already establishes, and it is worth knowing rather than discovering. What actually removes it is not sharing the host: a CA that matters should not live beside the server it issues for, and a dedicated CA host has no `puppet` account but its own, so the question does not arise.

A private `puppet-ca` account was the alternative and was rejected deliberately: it leaves `/etc/puppetlabs/puppet/ssl` owned by one account and written by another, which is a permissions problem an operator has to solve on every upgrade of either package.

### The two settings you must not drop

```ini
Type=notify
NotifyAccess=all
```

`NotifyAccess=all` is required, not optional hardening slack. In the default deployment `openvox-ca` runs as three processes — a launcher supervising an isolated signer that holds the CA key, and a frontend that serves the API (`--single-process` collapses them; see [CA key security](ca-key-security.md#process-isolation)) — and readiness is reported by the **frontend child**, because only it knows when the listener is accepting. systemd's default (`NotifyAccess=main`) accepts notifications only from the launcher, silently discards the frontend's, and the start job then fails on `TimeoutStartSec`.

The notification socket is withheld from the signer process, so it never notifies in normal operation. Treat that as hygiene rather than as an access control: `NotifyAccess=all` authorises every process in the unit's cgroup, and the socket path is well known, so the isolation is defence in depth — the residual cost of the multi-process design.

Running with `--single-process` collapses this to one process and `NotifyAccess=main` is then sufficient — but the shipped unit keeps `all` so it works either way.

### `--daemon` is for something else

Do not add `--daemon` to `ExecStart`. It forks and exits, which under `Type=notify` looks exactly like the service dying the moment it started. The CA logs a warning if you try. Running in the foreground is what a service manager wants; journald captures stderr.

## What the status text shows

During startup, each phase reports what it is waiting on — which is usually all you need to diagnose a start that hangs:

```console
$ systemctl status openvox-ca
     Active: activating (start) since Sat 2026-08-01 21:02:38 BST; 3s ago
     Status: "Waiting for the signer process to initialise the CA"
```

Once serving, the status summarises the listener, the CA certificate and the CRL:

```text
Status: "Serving HTTPS on 0.0.0.0:8140 | CA \"Puppet CA: puppet.example.com\" expires in 1824d | CRL #7 (3 revoked) expires in 29d"
```

It is refreshed on a timer, so the countdowns stay true. An elapsed deadline is spelled in capitals, so an expired CA certificate or a lapsed CRL is visible at a glance:

```text
Status: "Serving HTTPS on 0.0.0.0:8140 | CA \"Puppet CA: puppet.example.com\" expires in 1824d | CRL #7 (3 revoked) EXPIRED 2d ago"
```

Everything in the line is read from memory. Certificate counts are deliberately absent: that means listing the inventory in the storage backend, which is scrape-weight work and belongs in the [Prometheus exporter](metrics.md), not in a status line refreshed on a timer (every minute with no watchdog, or half `WatchdogSec=` when one is set — 45 seconds for the shipped unit).

## Reloading

`systemctl reload openvox-ca` re-reads the two file-backed inputs that can be swapped safely under live traffic:

| Input | Why it changes |
| --- | --- |
| `--tls-cert` / `--tls-key` | The CA's own server certificate expires like any other and has to be renewed |
| `--puppet-server-file` | A compile server is added, or a decommissioned one must stop being an admin |

`--puppet-server` itself is frozen at startup — reload re-reads only the file — and a certificate carrying `pp_cli_auth` stays an admin whatever the allow list says, so decommissioning a host means revoking its certificate too. See [admin credential resolution](api.md#admin-credential-resolution).

Connections in flight keep the certificate they negotiated with; the next TLS handshake picks up the new one. The allow list is swapped atomically with respect to in-flight requests: each request sees either the whole old list or the whole new one, and any CN that gained or lost admin rights is named in the log so the change is auditable.

Everything else — the listen address, the storage backend, CA key custody, CA properties, and which autosign configuration is in use — needs a restart. Those are bound to state established at startup, and re-reading them behind your back would be worse than telling you to restart. (The autosign allowlist or script, and the OpenBao AppRole credential files, are read live on every use and need neither a reload nor a restart.)

A CA that issues its own serving certificate — [`serving_cert`](configuration.md#the-cas-own-serving-certificate), which is the only way to have that certificate renewed unattended once the CA key is held at a provider — needs no reload for it either. The reconcile loop renews the certificate and installs it on the listener, so `systemctl reload` is a no-op for that certificate and the row above applies only to an operator-supplied `tls_cert` / `tls_key` pair. The two are mutually exclusive.

A reload that fails (a half-written certificate, a deleted allow-list file) leaves the previous configuration in place and the CA serving. The failure is logged and stays in the status text until a reload succeeds:

```text
Status: "Serving HTTPS on 0.0.0.0:8140 | ... | last reload FAILED, see the logs"
```

Check for that line after rotating a certificate. `systemctl reload` itself reports success either way — the notification protocol has no way to fail a reload without hanging the job.

### systemd 253 and later

The shipped unit uses `ExecReload=/bin/kill -HUP $MAINPID`, which works everywhere. On systemd 253+ you can instead drop `ExecReload` and use:

```ini
Type=notify-reload
```

systemd then sends `SIGHUP` itself and — because the CA stamps its reload acknowledgement with `MONOTONIC_USEC` — waits for the new configuration to be in effect before `systemctl reload` returns.

## Watchdog

```ini
WatchdogSec=90s
Restart=on-failure
```

The shipped unit uses 90 seconds, not 60: composing the status text takes the CA's read lock, and a storage operation holding the write lock is bounded by a 60-second cluster-lock timeout. An equal budget would leave no headroom between a slow backend and a kill.

The keep-alive is sent by the frontend process on a timer at half the configured interval — not by the launcher, which would only ever prove the supervisor was alive.

Be clear about what this does and does not catch. It stops arriving if the frontend dies outright, if the Go runtime deadlocks, or if the heartbeat goroutine itself stalls — which includes a storage operation wedged while holding the CA's write lock, since composing the status text takes the matching read lock. It keeps arriving quite happily if the API is unresponsive for a reason that leaves that goroutine scheduling normally, such as request handlers blocked on a read-only backend call. For genuine end-to-end liveness, point a probe at `/healthz/ready` as well; the watchdog is a backstop, not a health check.

Remove `WatchdogSec=` to disable it. Note that a watchdog restart is a hard kill: it does not drain in-flight requests, and a `WatchdogSec=` under 200ms is logged as too short to feed reliably. It is still fed at half the deadline down to 20ms. Below that the CA stops shortening the ticker at 10ms, which first costs the twice-per-interval margin `sd_watchdog_enabled(3)` recommends and, below about 10ms, stops beating the deadline at all — at which point the service manager kills the CA. That is the deliberate trade against spinning on a value nobody sets on purpose.

## Shutdown

On `SIGTERM` the CA reports `STOPPING=1` before draining, so a graceful shutdown is not mistaken for a crash, and the status names the budget:

```text
Status: "Shutting down: draining connections (up to 25s)"
```

`TimeoutStopSec` must exceed the drain budget (`shutdown_timeout_sec`, 25 seconds by default) plus the supervisor's 3-second headroom, or systemd will `SIGKILL` the CA part-way through the drain it asked for. The shipped unit uses 35 seconds. If you raise `shutdown_timeout_sec`, raise `TimeoutStopSec` with it — see [graceful shutdown](configuration.md#graceful-shutdown).

## Memory budget

`openvox-ca` runs as three processes under this unit, and `GOMEMLIMIT` is a
per-process knob, so the launcher treats one budget as belonging to the **whole
tree** and divides it between itself, the isolated signer and the frontend. A
`GOMEMLIMIT` set in the unit environment therefore caps the tree, not each
process.

With no `GOMEMLIMIT`, the launcher reads this unit's own cgroup v2 memory
ceiling, so a `MemoryMax=` in a drop-in is honoured:

```ini
[Service]
MemoryMax=512M
```

It claims 90% of that by default (`memory_budget_percent`), leaving headroom for
the memory the Go runtime does not account for. The shipped unit sets no
`MemoryMax=`, so out of the box nothing is derived and the runtimes are
unlimited, which is the right default for a host that is not memory-constrained.

The launcher and signer take fixed shares (`memory_reserve_launcher`,
`memory_reserve_signer`) and the frontend takes the remainder. The signer's share
does not grow with the ceiling, and it carries the Go runtime's own footprint
before any inventory, so a fleet beyond roughly 40,000 certificates should raise
`memory_reserve_signer` — raising `MemoryMax=` alone will not reach it. A
`MemoryMax=` set on a parent slice rather than on this unit is not derived
either, and `MemoryHigh=` is not read at all — only `memory.max` is consulted.
Set `MemoryMax=` on the unit itself, or set `GOMEMLIMIT` explicitly.

See [configuration](configuration.md#memory-budget).

## Hardening

The shipped unit runs the CA as the `puppet` user with `ProtectSystem=strict`, an empty capability set (the API port — 8140 by default, 8141 in the packages — and the exporter's 9140 are all unprivileged), and a `@system-service` syscall filter. `RestrictAddressFamilies` includes `AF_UNIX`, which is needed for both the notification socket and the launcher's socketpair to the isolated signer.

`LimitCORE=0` is deliberate and worth keeping: the signer holds the decrypted CA private key in memory for its whole life, so a core dump would write that key to `/var/lib/systemd/coredump` — undoing [key encryption at rest](ca-key-security.md) for anything that ships crash dumps off the host.

The service also sets `MemoryDenyWriteExecute=yes` and `UMask=0077`, and on a packaged install so does the first-boot oneshot. The first changes nothing you can observe, because Go needs no memory that is both writable and executable. The second masks group and world bits from the mode anything is created with. The files in [file permissions](configuration.md#file-permissions) keep their modes, because most get theirs set after creation, where a umask does not reach, and the rest are `0600` already. What changes is the directories `openvox-ca` creates under the CA directory, `0700` rather than `0750`, and an SQLite database with its sidecars, `0600` rather than the `0640` systemd's default umask gives. The CA directory itself exists before the service starts — the package or you created it — and keeps its mode. `openvox-ca-ctl` and the offline subcommands you run yourself are outside the unit, under your shell's umask; the oneshot's own `openvox-ca-ctl setup` and `openvox-ca generate` run under its `UMask=0077`.

`ProcSubset=pid` is left off; it is in the unit, commented out. Hiding the system-wide part of `/proc` would cost two things. Go sizes a listener's backlog from `/proc/sys/net/core/somaxconn`, and without it the API and exporter sockets get 128 rather than the host's setting (4096 by default). And the exporter's `process_start_time_seconds` needs the boot time from `/proc/stat`, so that series would disappear without an error.

`ProtectSystem=strict` is the directive most likely to bite: see [installing the unit](#installing-the-unit) for the `cadir` / `ReadWritePaths=` choice it forces. The same applies to `--logfile`, though logging to stderr and letting journald handle it is simpler.

It applies a third time, and there the consequence is worse. A [`serving_cert`](configuration.md#the-cas-own-serving-certificate) file store always needs the same `ReadWritePaths=` drop-in: it must sit outside the `cadir`, which the CA reserves against every file store, and the CA directory is the only path the unit makes writable. An unwritable serving store is **fatal** — the CA refuses to start rather than logging and retrying, because the listener has nothing to present. A managed certificate in the same position is merely retried on the next pass.

Check your changes with:

```console
$ systemd-analyze security openvox-ca.service
```

## Installing from a package

**Where the packages come from, first.** They are not published as release assets yet — `release.yml` has no packaging job, and adding one is [#266](https://github.com/voxpupuli/openvox-ca/pull/266). Until it lands, build them from a checkout:

```console
$ mage build:distVariant linux_amd64
$ mage build:distVariant linux_arm64
$ mage build:packages      # reads those tarballs; builds no binaries
```

Both variants, because `build:packages` builds the packages for every variant
marked packaged. It checks all of their tarballs before writing anything, so a
missing one fails with nothing in `dist/` rather than leaving a partial set.

`mage build:dist` produces both in one command and also works — but it builds
all four release tarballs including the two FIPS ones, which need a cgo cross
toolchain the packages never use. That is why the per-variant pair leads here.

They land in `dist/`, one `.deb` and one `.rpm` per non-FIPS architecture. A FIPS deployment uses the `_fips` tarball and the unit it ships; the packages carry the pure-Go build only.

Then install. The two packages differ here on purpose, each following its own distribution's convention:

```console
$ sudo apt install ./openvox-ca_<version>-1_amd64.deb   # Debian, Ubuntu: installs and starts
$ sudo dnf install ./openvox-ca-<version>-1.x86_64.rpm  # RHEL, Rocky, Fedora: installs only
$ sudo systemctl enable --now openvox-ca                # EL: creates the CA and starts it
```

**On Debian, installing starts the CA**, as installing a daemon does there. The postinst enables `openvox-ca.service` and starts it, which pulls in provisioning, so the CA is serving when `apt install` returns. The start goes through `deb-systemd-invoke`, which honours `policy-rc.d`: a chroot, a container or an image build that forbids starting daemons gets the package installed and enabled but not started, and the install still succeeds. The official Debian container images ship such a `policy-rc.d`. Because the unit is enabled, a machine booted from such an image creates its CA at its first boot.

**It does not start on a takeover.** A first install onto a host that already holds a CA — a `ca_crt.pem` in `/etc/puppetlabs/puppet/ssl/ca`, in the CA directory `config.yaml` names, or in OpenVox Server 6+'s `/etc/puppetlabs/puppetserver/ca` — or that has OpenVox Server installed, running or not, leaves the unit neither enabled nor started, and says so. Starting could make it a second writer to Server's live CA directory, which [the filesystem backend does not allow](#one-instance-per-ca-directory). Disable Server's CA first, as the [migration guide](migrating-from-puppet-server.md) describes, then `systemctl enable --now openvox-ca`. An upgrade, or a reinstall after `apt remove`, finds the package's own CA and starts as usual. A reinstall after an `apt purge` that kept the CA's data does not: dpkg has forgotten the package by then, and nothing on disk says whose the CA is, so it is treated as a takeover too, and `systemctl enable --now openvox-ca` is all it needs.

The deb may also ask one question first, the name to issue this host's certificate under; see [the debconf question and /etc/default on Debian](#the-debconf-question-and-etcdefault-on-debian).

**On EL, `enable --now`, not `start`.** The rpm deliberately leaves `openvox-ca.service` disabled — an install is not consent to create a certificate authority — so `start` alone gives you a running CA that does not come back after a reboot. Enabling is the step that says yes.

On EL the rpm applies the systemd preset for `openvox-ca.service` on its first install, as an rpm built with `%systemd_post` would. The distribution's default policy disables a third-party unit, so on most hosts this changes nothing; a site or image whose own preset enables `openvox-ca.service` gets it enabled, which is what presets are for. It is not applied again on upgrade, so an enable or disable you make yourself stands. The first install also prints the command above, where to find this page, and `journalctl -u openvox-ca-first-boot` for a start that fails.

The `.deb` and `.rpm` install the same unit, rendered for `/usr/bin`, and add a second one: `openvox-ca-first-boot.service`, a `Type=oneshot` that provisions the CA the first time you start the service. They also install this documentation tree at `/usr/share/doc/openvox-ca`, which is where the shipped configuration file points you when it says to read the full reference — so the answers are on the host rather than only in the repository.

It is pulled in by `openvox-ca.service` and runs nowhere else. There is no `WantedBy=multi-user.target` on it, so the oneshot is never what provisions on its own: a CA is created the first time `openvox-ca` starts. On Debian that is the install's own start, or the next boot where `policy-rc.d` declined it, because the unit is enabled. On EL it is your `systemctl enable --now`, or the next boot on a host whose own systemd preset enables `openvox-ca.service`, because the rpm applies presets. It is ordered `Before=openvox-ca.service` and is required by it, so provisioning that fails stops the service rather than letting it start against a half-provisioned directory.

**You do not have to write a configuration file first.** The package ships `/etc/openvox-ca/config.yaml` already set up: the CA directory, the serving certificate and key, and the port. Review it if you like — it is marked as a configuration file, so your edits survive upgrades — but a default install needs no edit to start.

Every step it takes is guarded on absence, so it **adopts rather than replaces**: nothing already on disk is overwritten, moved or re-signed. Running it twice does nothing the second time, and on a host that already has a CA it leaves that CA alone — but it does still fill in whatever is missing around it, which is what makes such an install produce a service that starts:

1. Create the `certs/`, `private_keys/` and `public_keys/` directories under `/etc/puppetlabs/puppet/ssl` if they are absent.
2. Bootstrap a CA in `/etc/puppetlabs/puppet/ssl/ca` unless one is already there.
3. Adopt this host's node certificate if `certs/$NAME.pem` and `private_keys/$NAME.pem` both exist **and the CA was already there before this run**; otherwise mint one. A credential that is already present when this run has just created the CA did not come from that CA, so adopting it would serve a certificate no agent's new trust anchor verifies — provisioning stops instead, and says which two ways out there are.
4. Create `certs/ca.pem` and `crl.pem` in the ssl tree as symlinks pointing into the CA directory (`../ca/ca_crt.pem` and `ca/ca_crl.pem`), as Puppet's own layout does, if nothing is there already.
5. Link the serving credential the shipped configuration names — `certs/openvox-ca-server.pem` and `private_keys/openvox-ca-server.pem` — to the certificate step 3 produced.

Step 5 is what makes the service able to start at all: it binds `0.0.0.0` and refuses plain HTTP on a non-loopback address, so it needs `tls_cert` and `tls_key`. Those name fixed paths because a file shipped in a package cannot know this host's certificate name, and provisioning points them at the credential it just adopted or minted. Re-minting under a corrected name is then a matter of replacing those two links rather than editing configuration — except where an environment file records the name, `/etc/sysconfig/openvox-ca` on [EL](#the-environment-file-on-el) or `/etc/default/openvox-ca` on [Debian](#the-debconf-question-and-etcdefault-on-debian), where it has to change too. Like every other step it is guarded on absence, so pointing `tls_cert` at your own certificate keeps it.

Step 3 is the one that can stop rather than warn, and it does so in three cases. If **one half of a credential** is present — a certificate with no key, or the reverse — it refuses to guess and says which file to move aside. If the binary has **no `generate` subcommand** it stops too, because a build that cannot mint leaves the service with no certificate to serve and `openvox-ca` refuses to start without TLS on a non-loopback address; failing here names the cause, where failing at the service would only report that TLS is not configured.

The third is the one that bites a host you are adding a CA to rather than building from nothing: **a complete credential for `$NAME` already exists, but this run created the CA**. That is the ordinary state of a machine already enrolled with an estate's CA — an agent certificate under `certs/`, signed by a CA elsewhere, and no local CA directory. Serving it from a CA that did not issue it would fail verification for every client, so provisioning stops and offers the choice it cannot make for you: point `cadir` at the estate's existing CA (and [grant that directory to both units](#using-a-different-ca-directory)), or move the credential aside and let this new CA mint its own.

In all three cases the CA itself is bootstrapped and intact, and the message says so.

`$NAME` is resolved first-usable-wins: `OPENVOX_CA_CERTNAME` from the environment file ([EL](#the-environment-file-on-el), [Debian](#the-debconf-question-and-etcdefault-on-debian)) or a systemd drop-in (the file wins over a drop-in's `Environment=` where both set it; a drop-in's own `EnvironmentFile=` is read after it and wins), then `certname` from `/etc/puppetlabs/puppet/puppet.conf`, then `hostname -f` if it is dotted and not a localhost form, then the short hostname, then `localhost`. Every source is also checked against an allow-list of characters that cannot express a path, because the name is joined to one.

**Two names are reserved and provisioning refuses them: `ca` and `openvox-ca-server`.** Both are basenames this script maintains as aliases under `certs/` — `certs/ca.pem` is where every agent on this host looks for the CA certificate — so a node certificate written under either would take the alias's place and hold the wrong thing, with nothing to say so. `ca` is worth knowing about because it is not contrived: it is what the short-hostname tier yields for a host called `ca.example.com`. If this host is genuinely named that, set an explicit `certname` — the fully qualified name is the right answer where there is one. **The last two resolution tiers — the short hostname and `localhost` — are failure states that still produce a running CA**; both warn, naming what will not work and how to re-mint. (The two reserved names above are not among them: those stop provisioning outright, and because the oneshot is required by the service, the service does not start.) The `localhost` case also writes `/etc/puppetlabs/puppet/ssl/openvox-ca-certname-unresolved`, because a CA nothing can reach still looks healthy in `systemctl status` — but only when that run created the CA. On a takeover the marker would be describing a CA this run did not issue, and its recovery steps begin by deleting one.

A oneshot rather than a maintainer script because it runs under the same hardening directives as the service — apart from `ReadWritePaths=`, which covers the whole ssl tree rather than the CA directory alone, because it links `certs/ca.pem` and `crl.pem` above the CA directory, and, on EL, one `ExecStartPost=+` step that records [the environment file](#the-environment-file-on-el) as root — and because it fails visibly in `systemctl status` rather than in package-manager output nobody keeps.

It re-runs after the CA directory is wiped **on the next boot, or on an explicit `systemctl restart openvox-ca-first-boot`** — not on a restart of `openvox-ca` alone. `RemainAfterExit=yes` leaves it active once it has succeeded, and a requirement on an already-active unit does nothing.

**That `Requires=` edge runs both ways.** Stopping or restarting the oneshot stops or restarts `openvox-ca` with it, so `systemctl stop openvox-ca-first-boot` on a unit that has visibly finished its job takes the CA down.

**The mint step prints a warning, and on a first boot it is expected.** `openvox-ca generate` reports that the `filesystem` backend coordinates no writes across processes and says to stop the server before running it. That is the right warning in general and it is why this unit is ordered `Before=openvox-ca.service`: at the moment it runs there is no server to stop. Seeing it in `journalctl -u openvox-ca-first-boot` after a first boot is not a fault. Seeing it after starting the oneshot by hand on a **running** CA is — stop the service first.

**Installing takes ownership of the CA directory, and of the ssl root only when nothing else lives there.** The postinstall always gives `puppet:puppet` the CA directory `ssl/ca`. It gives it the ssl root `/etc/puppetlabs/puppet/ssl` only when every entry already in it is owned by `puppet` — and otherwise leaves the root as it is and prints a warning naming what it found. Never recursively, and never following symlinks.

**It never takes `certs/`, `private_keys/` or `public_keys/`,** and on a host where openvox-agent created that tree as root it does not take the root above them either: owning the parent would hand `puppet` the agent's `certs/ca.pem` just as surely as owning `certs/` would (see [Why `puppet` and not a private account](#why-puppet-and-not-a-private-account)).

If provisioning needs to write in a directory it cannot, it stops and tells you so by name, with the exact `chown` to run and what running it grants. That is a decision for you to take while looking at it.

**On the rpm, the CA directory is declared `puppet`-owned in the package itself,** and the package creates the account before it unpacks anything. rpm re-applies a packaged directory's owner on every upgrade, so a root-owned declaration would take the CA directory away from the running service from the moment an upgrade unpacked until its postinstall ran. dpkg leaves an existing directory's owner alone on upgrade, so the deb does not need this.

**The ssl root is the exception on the rpm: "leaves the root as it is" means as the unpack left it.** The ssl root stays declared root-owned, because declaring it `puppet`'s would hand an agent's trust anchor to `puppet` at unpack, unconditionally. So every rpm install and upgrade resets `/etc/puppetlabs/puppet/ssl` to `root:root`, mode `0771`, before the postinstall runs. On this CA's own host, and on one where everything in the root is `puppet`'s, the postinstall hands it back. On a host where the root was `puppet`'s — OpenVox Server gives it the whole tree — but something in it is not, the postinstall leaves it with `root:root`, and `puppet` can no longer create entries at the top of the ssl tree. Directories it already owns below the root are not affected. The deb has no such step: dpkg leaves an existing directory's owner and mode alone.

### The packages listen on 8141

The binary's own default is 8140, and the packages ship `/etc/openvox-ca/config.yaml` setting `port: 8141`. The reason is collision, not preference: 8140 is right for a release tarball, a container and a host running nothing but the CA, but a *package* is what gets installed alongside OpenVox Server, and Server binds 8140 itself. So agents talking to a packaged CA are configured with `ca_port = 8141`.

The release tarballs are unaffected and stay on 8140 — they ship no configuration file at all.

It is set in the configuration file rather than as `--port` in the unit or `OPENVOX_CA_PORT` in the environment, and that is deliberate: the server resolves the port as **file, then environment, then flag**, so a value in either of those would outrank the file and silently ignore an operator who edited it. A default has to sit at the layer an operator can override. Edit the file, and neither `apt upgrade` nor `dnf update` will overwrite you — it is marked as a configuration file in both formats.

### The environment file on EL

Both units read `/etc/sysconfig/openvox-ca` if it exists (`EnvironmentFile=-`, so a host without one starts as before). On EL, provisioning writes it for you, once:

```sh
OPENVOX_CA_CERTNAME=ca.example.com
OPENVOX_CA_PUPPET_SERVER=ca.example.com
```

`OPENVOX_CA_PUPPET_SERVER` is the admin allow-list, so this host's own certificate — the one provisioning just minted or adopted — can sign, revoke and clean through the API without further setup. `OPENVOX_CA_CERTNAME` is the first tier of the name provisioning resolves, so a later re-provision mints under the same name even if the host's name has changed since.

**It is written once per host, and never again.** A step on the oneshot writes it on the first run that links the serving credential (step 5 above), then records at `/var/lib/openvox-ca/environment-recorded` that it has done so. From then on it writes nothing: not on later boots, not on a re-mint or CA rebuild, and not after you delete the file. Edit it and the edit stands; delete it and that stays deleted too, so the admin list goes back to `puppet_server` in `config.yaml` and the name to `puppet.conf` and then the host's own name. To have provisioning write a fresh one, delete the file, the record and the two serving-credential links (`certs/openvox-ca-server.pem` and `private_keys/openvox-ca-server.pem`), then `systemctl restart openvox-ca-first-boot openvox-ca`; or write the two lines yourself, which comes to the same thing. Neither is part of the package, so rpm never compares them, the file never produces an `.rpmnew`, and `dnf remove` leaves both. That is the point of the design: install-time values have to live somewhere, and if the package wrote them into `config.yaml`, rpm would stop updating that file on every later upgrade, because the installed copy would no longer match the packaged one.

The file is root-owned and mode `0600`. systemd reads it as root before starting either unit as `puppet`, so nothing else needs to read it — and it is the natural place on EL for credentials the server reads from its environment, such as `OPENVOX_CA_SQL_DSN`. Keep it that way if you add any.

**It outranks `config.yaml`, and `Environment=` in any drop-in.** The environment takes precedence over the configuration file, and `OPENVOX_CA_PUPPET_SERVER` *replaces* `puppet_server` rather than adding to it. So while that line is in the file, a `puppet_server` list in `config.yaml` is ignored; the shipped `config.yaml` says so at `puppet_server`. systemd also lets a value from `EnvironmentFile=` override the same variable set with `Environment=`, wherever that line sits, so once the file sets a variable, an `Environment=` line in a drop-in cannot change it. Edit the file instead. (A drop-in's own `EnvironmentFile=` is read after this one, so that does override it.) An edit takes effect on `systemctl restart openvox-ca`; `systemctl reload` does not re-read the environment.

**It does not override what you have already set.** If, when it comes to write the file, `config.yaml` sets `puppet_server` or `puppet_server_file`, or a drop-in for `openvox-ca.service` sets `OPENVOX_CA_PUPPET_SERVER`, `OPENVOX_CA_PUPPET_SERVER_FILE` or `OPENVOX_CA_CONFIG` (a configuration file whose admin list it cannot see), the file is written without `OPENVOX_CA_PUPPET_SERVER`; so does a host where it cannot ask systemd, rather than grant administration on a guess. If a drop-in for `openvox-ca-first-boot.service` already sets `OPENVOX_CA_CERTNAME`, it is written without that line. If both, nothing is written, and that counts as its one decision. So an admin list you set in `config.yaml` before the first start is the one that applies. Only those routes are checked: a drop-in `EnvironmentFile=` for `openvox-ca.service`, or an `ExecStart=` override passing `--config`, `--puppet-server` or `--puppet-server-file`, is not seen. If you choose the admin list or the configuration file that way, delete `OPENVOX_CA_PUPPET_SERVER` from `/etc/sysconfig/openvox-ca` after the first start, or create the file yourself before it. Creating `/etc/sysconfig/openvox-ca` yourself beforehand, even empty, opts out altogether: a file already there is yours, and is left alone.

It is written by a small root-privileged step, `/usr/libexec/openvox-ca/record-environment`, run as the oneshot's `ExecStartPost=+` after provisioning succeeds. It needs root because `/etc/sysconfig` is root's, and because a file that grants CA administration must not be writable by `puppet`, the account it grants it to. Provisioning itself stays confined as `puppet`. From the tree `puppet` writes, the step reads only that provisioning's marker exists and the text of the serving link, never a file's content. It applies provisioning's own allow-list to that text, so `puppet` can influence which well-formed name is recorded but cannot write anything else into the file. It never fails the unit: where it cannot write, it warns in `journalctl -u openvox-ca-first-boot` and the CA serves without the file.

**It is not written for a fallback name.** If the name came from the short hostname or fell back to `localhost`, the file is left unwritten and nothing is recorded, so the run that follows your fix can still write it. Both are failure states whose warnings tell you to set the right name in `puppet.conf`, and a recorded `OPENVOX_CA_CERTNAME` would outrank that fix. Nor is it written on Debian, where the package renders the same values from debconf instead (see [the debconf question and /etc/default on Debian](#the-debconf-question-and-etcdefault-on-debian)), or when something already occupies `certs/openvox-ca-server.pem` — your own certificate placed there, say. Pointing `tls_cert` at a different path does *not* prevent it: provisioning still links the alias, so the file is still written, and its `OPENVOX_CA_PUPPET_SERVER` still applies. Delete that line, or create the file first, if that is not what you want.

**To re-mint under a different name** on a host that has the file, set both `OPENVOX_CA_CERTNAME` and `OPENVOX_CA_PUPPET_SERVER` in it to the new name first. (Deleting the lines instead also works for the name, but then the new certificate is an admin only if `puppet_server` in `config.yaml` names it.) Then remove `certs/<old>.pem`, `private_keys/<old>.pem` and the two serving-credential links, and run `systemctl restart openvox-ca-first-boot openvox-ca`. The file is not rewritten, so without the first step provisioning mints under the recorded name again, or the new certificate is not an admin.

### The debconf question and /etc/default on Debian

The deb's counterpart of [the environment file on EL](#the-environment-file-on-el) holds the same two variables, `OPENVOX_CA_CERTNAME` and `OPENVOX_CA_PUPPET_SERVER`, in `/etc/default/openvox-ca`. It gets there differently, because Debian packages may ask: the value comes from a debconf question, and the package renders the file at install time and hands it to `ucf`.

**The question is `openvox-ca/ca-name`**, the name this host's certificate is issued under. Its default is what provisioning would choose anyway: `certname` from `puppet.conf`, else `hostname -f`. If that default is a usable fully qualified name, the question is asked at medium priority, below debconf's default threshold, so an ordinary install is silent and takes it. If it is not — a short hostname, a `localhost` form — it is asked at high priority, because the alternative is a certificate no agent will accept and only you know the right name. An answer is checked against the same rules provisioning applies, and an unusable one is asked again. To set it unattended, preseed it:

```console
$ echo 'openvox-ca openvox-ca/ca-name string ca.example.com' | sudo debconf-set-selections
```

A non-interactive install with no usable default records no name, and provisioning falls back to its own chain, as on EL. So does an image build: with no running systemd, or inside a chroot, the question gets no default at all, because the name it would find is the builder's and every machine booted from the image would mint under it. Each instance then resolves its own name at first boot. Unlike EL, where `record-environment` writes that name into the environment file, nothing on Debian records it: `/etc/default/openvox-ca` is rendered only at configure time, from the answer, so **an empty answer — an image build's included — writes no admin line**, and the instance's own certificate is not a CA administrator until `puppet_server` in `config.yaml` names it or `dpkg-reconfigure openvox-ca` is run on the instance. Preseed the question to give an image one name, and one admin, on purpose.

**`ucf` owns `/etc/default/openvox-ca`, not dpkg.** The postinst renders it on every configure and hands that to `ucf`, which keeps your edits: if the rendering changes too, it asks what to do — keep yours, take the new one, or merge the two (it keeps the previous rendering, so the merge is three-way) — and a non-interactive upgrade keeps yours and leaves the new rendering beside it as `/etc/default/openvox-ca.ucf-dist`. It is root-only (`0600`) when created, and keeps whatever mode you give it. It is not a dpkg conffile — `dpkg-query -W -f='${Conffiles}' openvox-ca` lists only `/etc/openvox-ca/config.yaml` — so the two are never managed twice. To change the name, run `dpkg-reconfigure openvox-ca`. As on EL, the new name takes effect at the next provisioning, which means removing the old certificate and the serving-credential links (see the re-mint steps under [the environment file on EL](#the-environment-file-on-el)). Note that `dpkg-reconfigure` also restarts the CA, and that `ucf` replaces a file you have not edited without asking, so the new `OPENVOX_CA_PUPPET_SERVER` applies at once while the CA still serves the old name's certificate, which is then no longer an admin: follow it with the re-mint straight away.

**It leaves out what you have already chosen, more cautiously than EL.** The rendering omits `OPENVOX_CA_PUPPET_SERVER` when `config.yaml` sets `puppet_server` or `puppet_server_file`, and when any drop-in for `openvox-ca.service` — its own directory, a prefix directory such as `openvox-.service.d`, or `service.d`, under `/etc`, `/run` or `/usr/lib` — mentions `OPENVOX_CA_PUPPET_SERVER`, `OPENVOX_CA_PUPPET_SERVER_FILE` or `OPENVOX_CA_CONFIG` anywhere outside a comment. It omits `OPENVOX_CA_CERTNAME` when a drop-in for the oneshot mentions that. A mention, not a parsed setting, because the check reads the files directly — it runs before systemd has reloaded, and in image builds with no systemd to ask — and any parser of systemd's syntax here would be one more place to disagree with it; so, unlike EL, an `EnvironmentFile=` drop-in counts too, provided it names the variable. It re-checks at every configure, so moving the admin list into `config.yaml` removes the line at the next upgrade. To drop the admin line yourself, delete it: `ucf` keeps your edit. To opt out of both values, leave `openvox-ca/ca-name` empty (`dpkg-reconfigure openvox-ca`, or a preseed); the file is then rendered with no assignments.

Its precedence is EL's for a drop-in named the usual way. It outranks `config.yaml` and `Environment=` in any drop-in, and a drop-in's own `EnvironmentFile=` outranks it provided the drop-in's name sorts after `00-debian.conf`, the name of the deb's: systemd reads drop-ins in filename order and a later `EnvironmentFile=` wins. `systemctl edit`'s `override.conf` and a `50-*.conf` both sort after it; a `00-a*.conf` or a `0-*.conf` does not, and `/etc/default/openvox-ca` would then win over it — which matters when that file holds the admin list under a name the check above cannot see.

The units find it through vendor drop-ins the deb ships, `/usr/lib/systemd/system/openvox-ca.service.d/00-debian.conf` and its counterpart for the oneshot. The oneshot's also clears `ExecStartPost=`, so `record-environment`, which the deb does not ship, never runs on Debian.

### What removing the package does not do

Neither `apt remove` nor `dnf remove` deletes **the CA private key, anything else under `/etc/puppetlabs/puppet/ssl`, the `puppet` account, `/etc/sysconfig/openvox-ca`, or the record that it was written.** On EL the service is stopped and disabled; on Debian it is stopped and masked, as `dh_installsystemd` does, and its enablement is kept, so a reinstall enables and starts it again while a disable you made yourself still holds. The shipped files go, and the CA's material stays exactly where it was.

That is deliberate. `/etc/puppetlabs/puppet/ssl` holds the key that signs every certificate in the estate, and the account may be shared with openvox-agent or OpenVox Server, so removing either could take an estate's trust root — or another product's account — with it on what an operator meant as an uninstall. `apt purge` asks before changing this; see below.

The consequence worth knowing is the other one: **removing the package does not decommission the CA.** Reinstalling adopts the existing directory rather than provisioning a new one, and the key remains on disk and readable by anything running as `puppet` until someone deletes it. To actually retire a CA, remove `/etc/puppetlabs/puppet/ssl/ca` yourself, having first understood that every certificate it issued stops being verifiable.

**On Debian, `apt purge` asks whether to remove the CA's data**, at high priority and defaulting to no: `openvox-ca/purge_ca_data`, the shape `mariadb-server` uses for its databases. The data is irreplaceable and the package cannot know whether you mean it, so a purge nobody answers — non-interactive, or with nothing preseeded — keeps it. Answer yes, or preseed `openvox-ca openvox-ca/purge_ca_data boolean true`, and the purge removes `/etc/puppetlabs/puppet/ssl/ca` and the links provisioning made to it — `certs/ca.pem`, `crl.pem` and the two `openvox-ca-server.pem` serving-credential links, each only if it is still the link provisioning would have made — and the unresolved-certname marker. It removes nothing else from the ssl tree, which may belong to openvox-agent or OpenVox Server, and it removes the default CA directory only: by the time a purge asks, dpkg has already removed the `config.yaml` that could have named another. Either way a purge removes `/etc/default/openvox-ca` and the debconf answers. Because it also makes dpkg forget the package, a later install onto a CA the purge kept is [treated as a takeover](#installing-from-a-package) and needs `systemctl enable --now openvox-ca`. The EL package never offers this; on EL, removing a CA is always the command above.

**An upgrade restarts a running CA**, so the new binary is the one serving
rather than the old process continuing on the superseded image — an upgrade
that silently does not take effect is the wrong default for a service whose
fixes are certificate-handling ones. On EL the postinstall issues `systemctl
try-restart openvox-ca.service`: a CA you have deliberately left stopped stays
stopped. On Debian it is `deb-systemd-invoke restart`, as `dh_installsystemd`
generates, which honours `policy-rc.d`. That restarts a running CA and also
starts one that is enabled but stopped; a disabled, stopped CA stays as it is.

The one file an upgrade will not overwrite is `/etc/openvox-ca/config.yaml`: it is marked as a configuration file in both formats, so your edits survive and a changed default arrives beside it as `.dpkg-dist` or `.rpmnew`.

### One instance per CA directory

The packages configure the `filesystem` storage backend, and first-boot provisioning **supports that backend only** — see [configuring another backend](#configuring-another-backend) below. It coordinates no writes between hosts and cannot append to its inventory atomically. **Exactly one `openvox-ca` may run against a given CA directory.** Running two — on one host or two — can leave an integrity record covering a state that never existed, after which the server refuses to start.

That is also why provisioning is ordered before the service rather than beside it: the oneshot writes to storage directly, and doing so while a server is running would make it the second writer. Only a backend that reports distributed locking may run more than one instance; see [configuring the server](configuration.md).

### Configuring another backend

[The storage backends](storage-backends.md) are configured in the same `/etc/openvox-ca/config.yaml` the packages ship, so its examples apply to a packaged install — **except that provisioning refuses to run against any of them.** `openvox-ca-ctl setup` is filesystem-only, while `openvox-ca generate` mints through whatever backend the configuration names, so bootstrapping here would write one CA to disk while the service reads another from the store, and then point `certs/ca.pem` — where every agent on this host reads the CA certificate — at the wrong one.

Because `openvox-ca-first-boot.service` is `RequiredBy=openvox-ca.service`, that refusal stops the service as well. Moving a packaged install to another backend therefore means provisioning the CA yourself:

```console
$ sudo systemctl disable --now openvox-ca-first-boot
$ sudo openvox-ca-ctl setup       # against your configured backend
```

and supplying the credential the shipped configuration names — `certs/openvox-ca-server.pem` and `private_keys/openvox-ca-server.pem` — or pointing `tls_cert` and `tls_key` at your own. Leaving the oneshot enabled blocks the service at the next boot.

Every spelling of the filesystem backend that `openvox-ca` itself accepts — `filesystem`, `file`, `fs`, `disk`, `local` — is accepted here too, in any case.

### The first-boot enable, and making a disable stick

Installing the package enables `openvox-ca-first-boot.service`. That is symlink work on disk only: the unit has no `WantedBy=multi-user.target`, so nothing is provisioned by the install or by the next reboot, and it still runs at nothing but the first start of `openvox-ca` — which is the install's own start on Debian, or the next boot where `policy-rc.d` declined it, and on an EL host whose own preset enables `openvox-ca.service` is the next boot (see [installing from a package](#installing-from-a-package)).

The enable happens **once**, and the package records that it happened at `/var/lib/openvox-ca/first-boot-enabled`. So a later `systemctl disable openvox-ca-first-boot` is not undone by the next upgrade — the marker is what tells the upgrade its enable is already done. Removing the package deletes the marker, and the directory if nothing else is in it, so a subsequent reinstall enables again. On EL the directory usually also holds `environment-recorded`, which is left on purpose: see [the environment file on EL](#the-environment-file-on-el).

That directory is the only state the packages keep outside `/etc`. If the postinstall cannot write the marker it says so and carries on, and creating the file by hand is enough to make a disable stick.

## Verifying

```console
$ systemctl show openvox-ca -p Type,NotifyAccess,StatusText,WatchdogUSec,NRestarts
```

`StatusText` empty while the service is `active (running)` means notifications are not arriving — nearly always `NotifyAccess` left at its default. systemd logs a warning in that case:

```text
Got notification message from PID 1234, but reception only permitted for main PID
```
