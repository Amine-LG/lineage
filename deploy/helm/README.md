# Lineage Helm Chart

This chart installs Lineage on OpenShift from the prebuilt image:

```text
ghcr.io/amine-lg/lineage:latest
```

It does not build inside the cluster. The intended install path is one
`helm install` by a cluster-admin user.

## What The Chart Creates

- `ServiceAccount`: the identity used by the Lineage pod.
- `ClusterRole`: read-only access to the OpenShift and Kubernetes resources
  Lineage inventories.
- `ClusterRoleBinding`: binds the read-only `ClusterRole` to the
  `ServiceAccount`.
- `Deployment`: runs one Lineage pod on port `8080`.
- `Service`: exposes the pod inside the cluster on port `8080`.
- `Route`: exposes Lineage through OpenShift with edge TLS.

The chart does not create a `Namespace` object. Use Helm's
`--create-namespace` flag.

## Install

Default install from the local checkout, with no Secret access:

```bash
helm install lineage deploy/helm \
  --namespace lineage \
  --create-namespace
```

HTPasswd-enabled install from the local checkout:

```bash
helm install lineage deploy/helm \
  --namespace lineage \
  --create-namespace \
  --set htpasswd.enabled=true
```

Default install after the chart is published to GHCR as an OCI artifact:

```bash
helm install lineage oci://ghcr.io/amine-lg/charts/lineage \
  --namespace lineage \
  --create-namespace
```

HTPasswd-enabled install from the published OCI chart:

```bash
helm install lineage oci://ghcr.io/amine-lg/charts/lineage \
  --namespace lineage \
  --create-namespace \
  --set htpasswd.enabled=true
```

Get the Route:

```bash
oc get route lineage -n lineage
```

Open:

```text
https://<route-host>
```

## Install With Parameters

Use a specific image tag:

```bash
helm install lineage deploy/helm \
  --namespace lineage \
  --create-namespace \
  --set image.tag=d1f0ffa
```

Use a custom Route host:

```bash
helm install lineage deploy/helm \
  --namespace lineage \
  --create-namespace \
  --set route.host=lineage.example.com
```

Use a different namespace:

```bash
helm install lineage deploy/helm \
  --namespace lineage-prod \
  --create-namespace \
  --set namespace.name=lineage-prod
```

Adjust CPU or memory:

```bash
helm install lineage deploy/helm \
  --namespace lineage \
  --create-namespace \
  --set resources.requests.cpu=500m \
  --set resources.limits.cpu=1 \
  --set resources.limits.memory=512Mi
```

Increase the OpenShift Route timeout:

```bash
helm install lineage deploy/helm \
  --namespace lineage \
  --create-namespace \
  --set route.timeout=120s
```

## Upgrade

```bash
helm upgrade lineage deploy/helm \
  --namespace lineage
```

For the OCI chart after publication:

```bash
helm upgrade lineage oci://ghcr.io/amine-lg/charts/lineage \
  --namespace lineage
```

## Uninstall

```bash
helm uninstall lineage -n lineage
oc delete namespace lineage
```

If you used a different release name, delete the matching cluster-scoped RBAC
objects if Helm did not remove them:

```bash
oc get clusterrole | grep lineage
oc get clusterrolebinding | grep lineage
```

## Security Model

Lineage is read-only against inspected cluster resources.

The `ClusterRole` grants only `get` and `list` for inventory resources:

- users, identities, groups
- namespaces and projects
- ServiceAccounts and pods
- Roles, RoleBindings, ClusterRoles, ClusterRoleBindings
- OAuth and ClusterVersion metadata
- Jobs and CronJobs
- SCCs
- ImageStreams

The only `create` permission is for the Kubernetes self-review API:

- `selfsubjectaccessreviews`

That is used by `oc auth can-i` style checks. It does not create or mutate
application resources.

## HTPasswd Secret Access

The Helm chart does not grant Secret access by default.

If `/setup` reports HTPasswd signals as unavailable, that is expected unless
you intentionally grant exact-name read access to the HTPasswd Secret. This
keeps the default chart free of Secret permissions.

For clusters that need HTPasswd-backed signals, enable the optional exact-name
Secret reader:

```bash
helm install lineage deploy/helm \
  --namespace lineage \
  --create-namespace \
  --set htpasswd.enabled=true
```

If your HTPasswd Secret has a different name:

```bash
helm install lineage deploy/helm \
  --namespace lineage \
  --create-namespace \
  --set htpasswd.enabled=true \
  --set htpasswd.secretNames='{engineering-htpasswd}'
```

Keep this scoped to the specific Secret names referenced by `oauth/cluster`;
do not grant broad Secret list access.

## Why There Is No NetworkPolicy

The chart intentionally does not install a `NetworkPolicy`.

The earlier draft had a NetworkPolicy value, but the policy allowed ingress on
port `8080` from anywhere so the OpenShift Route could work. That did not add
meaningful isolation, and it made the chart more complicated. NetworkPolicy is
better handled by the cluster or namespace owner if they have a specific
network isolation policy.

## Performance Notes

The chart must include cluster-wide read access for `jobs` and `cronjobs`.
Without those permissions, Lineage falls back to per-namespace reads, which is
much slower.

Current tested defaults:

```yaml
resources:
  requests:
    cpu: 500m
    memory: 128Mi
  limits:
    cpu: "1"
    memory: 512Mi
```

The Route timeout defaults to `120s` so the first cold inventory request has
enough time on larger clusters. Warm requests should be much faster.
