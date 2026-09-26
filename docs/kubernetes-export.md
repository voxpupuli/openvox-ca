# Kubernetes export

openvox-ca can optionally publish the **CA certificate** and/or the **CRL** into
one or more Kubernetes **Secrets** and **ConfigMaps**, so that other workloads in
the cluster can mount them directly (e.g. as a trust bundle or for CRL
distribution) instead of fetching them over the HTTP API or sharing a storage
volume.

- Any number of targets, each a Secret **or** a ConfigMap.
- Each target may carry the **CA cert**, the **CRL**, or **both** (PEM only for now).
- The data keys, name, namespace, labels, annotations, and a Secret's `type`
  field are all configurable.
- CRL-bearing targets are **re-exported whenever the CRL changes** (revoke,
  reissue, background refresh, expired-cert cleanup). All targets are also
  reconciled **once at startup**.

The feature is **disabled by default**; it activates only when at least one
target is configured.

## How it works

The exporter runs inside the openvox-ca pod and talks to the Kubernetes API
using the pod's **in-cluster ServiceAccount** credentials. It is therefore only
available when openvox-ca itself runs inside a Kubernetes cluster.

Objects are reconciled with **server-side apply** (field manager `openvox-ca` by
default), which makes every export an idempotent create-or-update and lets the CA
co-exist with other managers of the same object. Apply uses `force`, so fields
owned by the exporter are reclaimed if something else overwrites them.

Every managed object carries the label `app.kubernetes.io/managed-by:
openvox-ca` so you can find the objects openvox-ca owns. **It does not
distinguish them from a [managed certificate](configuration.md#managed-certificates)
Secret**, which carries the same label and holds a component's only private key
— so this is a safe selector to list with and not to delete with:

```sh
kubectl get secret,configmap -A -l app.kubernetes.io/managed-by=openvox-ca
```

Each replica runs its own exporter; because writes go through server-side apply,
concurrent exports from multiple replicas are safe.

## Configuration

Kubernetes export is **YAML-file only** — its nested structure (a list of
targets, each with labels and annotations) does not map cleanly onto flags or
environment variables. Add a `kubernetes_export` block to the config file:

```yaml
kubernetes_export:
  # Server-side apply field manager. Optional; default "openvox-ca".
  field_manager: openvox-ca

  targets:
    # A Secret holding both the CA cert and the CRL.
    - kind: Secret              # "Secret" or "ConfigMap" (required; case-insensitive)
      metadata:
        name: openvox-ca-trust  # required
        namespace: puppet       # optional; defaults to the pod's own namespace
        labels:
          app.kubernetes.io/part-of: puppet
        annotations:
          example.com/owner: platform-team
      type: Opaque              # Secret only; optional (see "Secret type" below)
      cert: true                # include the CA certificate (default false)
      crl: true                 # include the CRL (default false)
      cert_key: ca.crt          # data key for the cert; default "ca.crt"
      crl_key: ca.crl           # data key for the CRL; default "ca.crl"
      cert_scope: chain         # "chain" (default), "self" or "root"
      crl_scope: chain          # "chain" (default) or "self"

    # A ConfigMap holding only the CRL, in a namespace of its own.
    - kind: ConfigMap
      metadata:
        name: openvox-ca-crl
        namespace: monitoring
      crl: true
      crl_key: ca_crl.pem
```

### Target fields

| Field | Applies to | Default | Notes |
| --- | --- | --- | --- |
| `kind` | both | — | `Secret` or `ConfigMap` (required; matched case-insensitively) |
| `metadata.name` | both | — | Object name (required) |
| `metadata.namespace` | both | pod's namespace | Resolved from the ServiceAccount mount when empty |
| `metadata.labels` | both | — | Merged with the mandatory `managed-by` label |
| `metadata.annotations` | both | — | Applied verbatim |
| `cert` | both | `false` | Include the CA certificate |
| `crl` | both | `false` | Include the CRL (at least one of `cert`/`crl` must be true) |
| `cert_key` | both | `ca.crt` | Data key for the cert |
| `crl_key` | both | `ca.crl` | Data key for the CRL (must differ from `cert_key`) |
| `cert_scope` | both | `chain` | `chain`, `self` or `root` — see below |
| `crl_scope` | both | `chain` | `chain` or `self` |
| `type` | Secret | unmanaged | Secret `type` field; unset means the exporter does not own it (see below); rejected on ConfigMaps |

### Scopes

Once the CA certificate and the CRL can both be chains, a target has to say how
much of one it wants:

| Scope | Publishes |
| --- | --- |
| `chain` (default) | The stored bundle or CRL chain verbatim |
| `self` | Only this CA's own certificate or CRL |
| `root` | The last certificate in the bundle — the trust anchor. Certificates only |

`root` publishes the last certificate in the stored bundle without inspecting
it, so it is only a *trust anchor* if the bundle you imported was a complete
chain ending at a self-signed root. Nothing enforces that today —
`openvox-ca-ctl import` accepts a partial bundle — so `root` on a bundle that
stops at an intermediate publishes that intermediate. It fails closed rather
than open (an intermediate grants strictly less trust than the real root, and
consumers trusting it simply fail to verify), but it fails, so import the whole
chain. For a Puppet agent that failure is not subtle and is not confined to
revocation: with `certificate_revocation = chain`, OpenSSL will not end a path
at a non-self-signed anchor at all, so the agent stops connecting rather than
checking less — see the note under
[Offline subcommands on the server binary](operator-cli.md#offline-subcommands-on-the-server-binary)
for the test that establishes it. There is no `root` for CRLs, because a chain has no single anchor CRL —
the root's own is simply one of its members.

The default is `chain` so that upgrading changes nothing: before these fields
existed, every target published the stored blobs verbatim, and that is what an
unset scope still publishes. Narrowing is something you opt into, per target.

Opt in where a consumer wants exactly one block — a trust bundle that should
carry this CA alone, or a CRL a consumer expects to parse as a single list. The
two scopes are applied independently, to different material, so the number of
certificates in the bundle governs `cert_scope` and tells you nothing about
`crl_scope`: a CA that issued its own root has one certificate in its bundle,
where `cert_scope` is a no-op, and can still hold a multi-block CRL blob from
`import --crl-chain` or from `crl_chain_file`, where `crl_scope` is not.

Setting `crl_scope: self` on a target that feeds agents doing full-chain
revocation checking drops every ancestor CRL from what they receive, which is
the material `crl_chain_file` exists to distribute. Under `chain` the value is a
multi-block PEM, which a consumer expecting exactly one CRL has to handle; that
trade-off is the reason `self` exists.

Exports and the HTTP endpoints therefore agree by default: `/certificate/ca` and
`/certificate_revocation_list/ca` always serve the full chain, because Puppet
agents need it, and an export target publishes the same thing until you narrow
it.

### Secret type

When `type` is set, the exporter owns the Secret's `type` field. When it is
**omitted**, the exporter does not manage `type` at all: the API server defaults
a newly-created Secret to `Opaque`, and the type of an existing Secret is left
untouched. This lets openvox-ca **co-maintain** a Secret owned by another tool —
for example a `kubernetes.io/tls` Secret whose `tls.crt`/`tls.key` are pushed by
Flux — by applying only the CRL (or cert) into a data key of its own and leaving
the type, and the other manager's keys, alone. Do not set `type:
kubernetes.io/tls` on a target that only carries the CA cert/CRL: such a Secret
must also contain `tls.crt` and `tls.key`, so the API server would reject the
apply.

Secret data is written under `data` (base64-encoded by the client), and
ConfigMap data as plain text under `data`. Using `data` rather than the
write-only `stringData` keeps each server-side apply idempotent, so re-exporting
unchanged material is a genuine no-op.

## RBAC

The pod's ServiceAccount needs permission to create and server-side-apply the
target objects in each target namespace. The exporter only ever creates or
applies objects — it never reads them — so `create` and `patch` are the only
verbs required (server-side apply is a `patch`):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: openvox-ca-export
  namespace: puppet
rules:
  - apiGroups: [""]
    resources: ["secrets", "configmaps"]
    verbs: ["create", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: openvox-ca-export
  namespace: puppet
subjects:
  - kind: ServiceAccount
    name: openvox-ca           # the SA your CA pod runs as
    namespace: puppet
roleRef:
  kind: Role
  name: openvox-ca-export
  apiGroup: rbac.authorization.k8s.io
```

Create a `Role`/`RoleBinding` pair in **each** namespace you export into, or use
a `ClusterRole` with per-namespace `RoleBinding`s. Restrict the verbs and
resources to the minimum above.

## Behaviour and failure handling

- The export is **auxiliary**: if the Kubernetes client cannot be constructed
  (e.g. openvox-ca is not running in a cluster, or the namespace cannot be
  resolved), the error is logged and the CA continues serving normally. **This
  is true of the export alone.** A
  [managed certificate](configuration.md#managed-certificates) with a
  `store.secret` makes the same failure fatal at startup, because a component
  is waiting on a certificate that would never be issued — so a CA configured
  for both exports and Secret-stored managed certificates refuses to start
  where it cannot build a client, rather than logging and carrying on.
- A failure applying one target is logged and does not prevent the other targets
  from being applied.
- A cert or CRL that cannot be read from storage fails only the targets that
  asked for that material: a CRL-only target is still applied when the CA
  certificate read fails, and vice versa. Every target still gets a result
  recorded either way, which is what the alerting below depends on.
- A cycle in which any target failed is retried two minutes later, and keeps
  being retried until one succeeds completely. Without that, the next attempt
  would wait for the next CRL update, which on a low-churn CA can be weeks —
  long enough for a momentary storage blip to leave every target holding a stale
  CA certificate or CRL. The interval is fixed and not configurable.
- Because two minutes sits inside the mixin's fifteen-minute alert debounce, a
  failure that clears on the first retry or two never pages; one that takes
  longer than the debounce to clear still does. The deliberate gap is a target
  that fails its first attempt but succeeds on retry *every* cycle — it never
  pages, because `last_success` always overtakes `last_error` within two
  minutes. Watch `puppetca_k8s_export_applies_total{result="error"}`, which
  counts every failed attempt whether or not a retry rescued it; see
  [metrics](metrics.md) for the query.
- Configuration is validated at startup; an invalid `kubernetes_export` block
  (bad `kind`, a `type` on a ConfigMap, neither `cert` nor `crl`, colliding
  keys, …) stops the server with a clear error.

## Metrics

When the [Prometheus exporter](metrics.md) is enabled, each apply attempt is
counted in `puppetca_k8s_export_applies_total{kind,namespace,name,result}`, and
per-target `last_success` / `last_error` timestamp gauges record the most
recent outcomes. Because export failures are only logged, alerting on these
series is the recommended way to catch a target that persistently fails; the
[monitoring mixin](../mixin/) ships a `PuppetCAKubernetesExportFailing` alert
that fires while a target's most recent apply attempt failed.

That alert matches on the `last_error` gauge, so it can only report on a target
the CA has recorded a result for. The mixin pairs it with
`PuppetCAKubernetesExportNotRunning`, which fires when a configured target's
`applies_total` has stayed at zero for thirty minutes — the export job wedged
before attempting anything, or never started at all.

"Never started" is covered because the CA publishes those counters at zero even
when it gives up on the export: if the in-cluster client cannot be built, or the
pod namespace cannot be resolved, the CA logs the error, carries on serving, and
still exports the zeroed counters. That case is otherwise entirely silent —
readiness stays green and the exported objects simply stop being updated — so
without the zeroed series neither alert could report it. Deploy both.

When the export never started, a target that relies on the pod namespace shows
a blank namespace in that alert. That is not a glitch, and it does tell you
something — but less than it looks. The implication runs one way only: a blank
means the export never started, because a running exporter always resolves a
real namespace before it publishes anything. A target wedged *after* starting
shows its resolved namespace like any other, so a namespace you did not
configure appearing here is the wedged case, not this one. It does *not*
say which startup failure occurred: the placeholder is used for both, including
the case where the client could not be built and the namespace file was never
read. RBAC and the API server are ruled out, since nothing was attempted; to
tell the remaining causes apart, read the `Kubernetes export disabled: failed
to initialise client` line in the CA log, which names the actual error.

## Limitations

- In-cluster ServiceAccount authentication only (no external kubeconfig).
- PEM encoding only (no DER).
- Objects are not deleted when a target is removed from the config; delete them
  manually. They carry the `app.kubernetes.io/managed-by=openvox-ca` label — but
  **that label alone is not a safe delete selector**: a
  [managed certificate](configuration.md#managed-certificates) Secret carries
  the identical label and holds a component's only private key. Name the
  exported objects, or give them a label of your own under
  `metadata.labels` and select on that. See
  [uninstalling](helm-chart.md#uninstalling).
