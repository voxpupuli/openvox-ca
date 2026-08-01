# Running under systemd

`openvox-ca` speaks the systemd notification protocol ([`sd_notify(3)`](https://www.freedesktop.org/software/systemd/man/sd_notify.html)), so a unit can be `Type=notify` rather than `Type=simple`. That gives you four things:

- **`systemctl start` blocks until the CA is actually serving** — storage reachable, CA loaded (bootstrapped on a first run), listener accepting. Units ordered `After=openvox-ca.service` no longer race a cold start.
- **`systemctl status` says what the CA is doing**, both during startup and while it runs.
- **`systemctl reload` re-reads the TLS keypair and the admin allow list** without dropping connections.
- **An optional watchdog** restarts a CA that has stopped making progress.

None of it needs configuration. The protocol is driven entirely by `$NOTIFY_SOCKET`, which systemd sets; without it every notification is a no-op, so the same binary behaves normally under a shell, another supervisor, or in a container.

## Installing the unit

A ready-to-use unit ships in [`packaging/systemd/openvox-ca.service`](../packaging/systemd/openvox-ca.service) (and in the release tarballs):

```console
$ sudo useradd --system --home-dir /var/lib/puppet-ca --shell /usr/sbin/nologin puppet-ca
$ sudo install -m 0644 openvox-ca.service /etc/systemd/system/
$ sudo systemctl daemon-reload
$ sudo systemctl enable --now openvox-ca.service
```

The unit expects the binary at `/usr/local/bin/openvox-ca` and its configuration at `/etc/puppet-ca/config.yaml`. See [configuring the server](configuration.md).

### The two settings you must not drop

```ini
Type=notify
NotifyAccess=all
```

`NotifyAccess=all` is required, not optional hardening slack. In the default deployment `openvox-ca` runs as three processes — a launcher supervising an isolated signer that holds the CA key, and a frontend that serves the API (see [CA key security](ca-key-security.md)) — and readiness is reported by the **frontend child**, because only it knows when the listener is accepting. systemd's default (`NotifyAccess=main`) accepts notifications only from the launcher, silently discards the frontend's, and the start job then fails on `TimeoutStartSec`.

The notification socket is withheld from the signer process, so even under `NotifyAccess=all` only the launcher and the frontend can notify.

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

Everything in the line is read from memory. Certificate counts are deliberately absent: that means listing the inventory in the storage backend, which is scrape-weight work and belongs in the [Prometheus exporter](metrics.md), not in a status line refreshed every minute.

## Reloading

`systemctl reload openvox-ca` re-reads the two file-backed inputs that can be swapped safely under live traffic:

| Input | Why it changes |
| --- | --- |
| `--tls-cert` / `--tls-key` | The CA's own server certificate expires like any other and has to be renewed |
| `--puppet-server-file` | A compile server is added, or a decommissioned one must stop being an admin |

Connections in flight keep the certificate they negotiated with; the next TLS handshake picks up the new one. The allow list is swapped atomically with respect to in-flight requests: each request sees either the whole old list or the whole new one.

Everything else — listen address, storage backend, CA key custody, CA properties, autosign configuration — needs a restart. Those are bound to state established at startup, and re-reading them behind your back would be worse than telling you to restart.

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
WatchdogSec=60s
Restart=on-failure
```

The keep-alive is sent by the frontend process on a timer at half the configured interval, so it stops arriving if the process serving the API wedges — on an unresponsive storage backend, say — and systemd restarts the service. A launcher-side ping would only ever prove the supervisor was alive, which it always is.

Remove `WatchdogSec=` to disable it. Note that a watchdog restart is a hard kill: it does not drain in-flight requests.

## Shutdown

On `SIGTERM` the CA reports `STOPPING=1` before draining, so a graceful shutdown is not mistaken for a crash, and the status names the budget:

```text
Status: "Shutting down: draining connections (up to 25s)"
```

`TimeoutStopSec` must exceed the drain budget (`shutdown_timeout_sec`, 25 seconds by default) plus the supervisor's 3-second headroom, or systemd will `SIGKILL` the CA part-way through the drain it asked for. The shipped unit uses 35 seconds. If you raise `shutdown_timeout_sec`, raise `TimeoutStopSec` with it — see [graceful shutdown](configuration.md#graceful-shutdown).

## Hardening

The shipped unit runs the CA as a dedicated `puppet-ca` user with `ProtectSystem=strict`, an empty capability set (the API's port 8140 and the exporter's 9140 are both unprivileged), and a `@system-service` syscall filter. `RestrictAddressFamilies` includes `AF_UNIX`, which is needed for both the notification socket and the launcher's socketpair to the isolated signer.

If you point `cadir` somewhere other than the `StateDirectory=puppet-ca` the unit creates, add that path to `ReadWritePaths=`. The same applies to `--logfile`, though logging to stderr and letting journald handle it is simpler.

Check your changes with:

```console
$ systemd-analyze security openvox-ca.service
```

## Verifying

```console
$ systemctl show openvox-ca -p Type,NotifyAccess,StatusText,WatchdogUSec,NRestarts
```

`StatusText` empty while the service is `active (running)` means notifications are not arriving — nearly always `NotifyAccess` left at its default. systemd logs a warning in that case:

```text
Got notification message from PID 1234, but reception only permitted for main PID
```
