# upliftos-admission

A tiny Kubernetes **validating admission webhook** that UpliftOS Private Cloud
installs into a customer's own cluster to *contain* the permissions of the
UpliftOS deployer service account.

It is published as a public image because a customer cluster pulls it during the
connect flow, before any UpliftOS-supplied pull credentials exist in the
namespace:

```
ghcr.io/upliftos/upliftos-admission:v1
```

## What it enforces

When the `upliftos-deployer` service account creates a `RoleBinding`, the
Kubernetes API server calls this webhook, which admits the request **only** when
both hold:

- `roleRef` is the `upliftos-app-manager` ClusterRole, and
- the target namespace is `upliftos-system` or `upos-*`.

Anything else — most importantly binding `upliftos-app-manager` into
`kube-system` — is denied. Every other principal's RoleBindings are ignored
(the webhook is scoped to the deployer SA via `matchConditions`).

## Why it exists

The deployer holds a cluster-wide `rolebindings: create` grant so it can grant
itself workload access in each new `upos-*` app namespace at deploy time. RBAC
alone cannot express "only in these namespaces" — that decision needs the
request's contents, which is the *admission* phase.

- On **Kubernetes 1.30+**, UpliftOS does this with a `ValidatingAdmissionPolicy`
  (admission enforced inside the API server, no separate process).
- On **1.28–1.29**, before that feature was GA, this webhook enforces the
  **identical** rule out-of-process.

It is installed by the UpliftOS connect bootstrap manifest and is not intended
to be run standalone.

## Design

- Single static Go binary, **standard library only** (no third-party deps).
- Distroless base, runs as a non-root user (uid 65532).
- Two subcommands:
  - `serve` — the HTTPS webhook (`POST /validate`, `/healthz`). Makes **no**
    Kubernetes API calls and holds no credentials; it only answers admission
    requests the API server sends it.
  - `certgen` — mints a self-signed serving certificate into a shared volume for
    the install Job's `kubectl` step. Cert material via `crypto/x509`; no
    third-party dependency.
- `fail-closed`: if the webhook is unreachable, the deployer's RoleBinding
  creates are denied (deploys pause), never silently allowed.

## Build & test

```sh
go vet ./...
go test ./...
docker build -t upliftos-admission .
```

## Publishing

The image is published by `.github/workflows/publish.yml`:

- push / pull request → `go test` + a multi-arch build (no push);
- manual **Run workflow** (tag input, default `v1`) → build **and push**
  `ghcr.io/<owner>/upliftos-admission:<tag>` (+ a `sha-` tag).

Tags are immutable per release; the UpliftOS bootstrap manifest pins the tag.
