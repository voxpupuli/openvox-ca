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
openvox-ca` so you can find and select the objects openvox-ca owns:

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
    - kind: secret              # "secret" or "configmap" (required)
      name: openvox-ca-trust    # required
      namespace: puppet         # optional; defaults to the pod's own namespace
      type: Opaque              # secret only; default "Opaque"
      cert: true                # include the CA certificate (default false)
      crl: true                 # include the CRL (default false)
      cert_key: ca.crt          # data key for the cert; default "ca.crt"
      crl_key: ca.crl           # data key for the CRL; default "ca.crl"
      labels:
        app.kubernetes.io/part-of: puppet
      annotations:
        example.com/owner: platform-team

    # A ConfigMap holding only the CRL, in a namespace of its own.
    - kind: configmap
      name: openvox-ca-crl
      namespace: monitoring
      crl: true
      crl_key: ca_crl.pem
```

### Target fields

| Field | Applies to | Default | Notes |
|-------|-----------|---------|-------|
| `kind` | both | — | `secret` or `configmap` (required) |
| `name` | both | — | Object name (required) |
| `namespace` | both | pod's namespace | Resolved from the ServiceAccount mount when empty |
| `cert` | both | `false` | Include the CA certificate |
| `crl` | both | `false` | Include the CRL (at least one of `cert`/`crl` must be true) |
| `cert_key` | both | `ca.crt` | Data key for the cert |
| `crl_key` | both | `ca.crl` | Data key for the CRL (must differ from `cert_key`) |
| `type` | secret | `Opaque` | Secret `type` field; rejected on ConfigMaps |
| `labels` | both | — | Merged with the mandatory `managed-by` label |
| `annotations` | both | — | Applied verbatim |

Secret data is written via `stringData` (PEM is text); the API server stores it
base64-encoded under `data`. ConfigMap data is written as plain text under
`data`.

## RBAC

The pod's ServiceAccount needs permission to create and server-side-apply the
target objects in each target namespace. Server-side apply is a `patch`, so
`patch` is required in addition to `get` and `create`:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: openvox-ca-export
  namespace: puppet
rules:
  - apiGroups: [""]
    resources: ["secrets", "configmaps"]
    verbs: ["get", "create", "patch"]
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
  resolved), the error is logged and the CA continues serving normally.
- A failure applying one target is logged and does not prevent the other targets
  from being applied. Transient failures are retried on the next CRL update, or
  on the next restart.
- Configuration is validated at startup; an invalid `kubernetes_export` block
  (bad `kind`, a `type` on a ConfigMap, neither `cert` nor `crl`, colliding
  keys, …) stops the server with a clear error.

## Limitations

- In-cluster ServiceAccount authentication only (no external kubeconfig).
- PEM encoding only (no DER).
- Objects are not deleted when a target is removed from the config; delete them
  manually (they carry the `app.kubernetes.io/managed-by=openvox-ca` label).
