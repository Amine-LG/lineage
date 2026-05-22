# OpenShift Deployment

These manifests run Lineage in-cluster as a single Deployment with a
dedicated read-only ServiceAccount.

The recommended path builds the image inside OpenShift from your local
source tree, then deploys from the internal ImageStream.

The build uses the root [Containerfile](../../Containerfile). OpenShift pulls
`quay.io/openshift/origin-cli:4.19` to copy the `oc` binary and
`python:3.11-slim-bookworm` as the runtime base, then publishes the finished image to
the internal `lineage:latest` ImageStreamTag.

## Files

| File | Purpose |
| --- | --- |
| `00-namespace.yaml` | creates `lineage-incluster` |
| `10-rbac.yaml` | ServiceAccount, read-only ClusterRole, binding |
| `15-build.yaml` | ImageStream and binary BuildConfig |
| `20-htpasswd-rbac.yaml` | optional exact-name HTPasswd Secret read |
| `30-deployment.yaml` | Deployment and Service |
| `40-route.yaml` | optional Route |

## Install

```bash
oc apply -f deploy/openshift/00-namespace.yaml
oc apply -f deploy/openshift/10-rbac.yaml
oc apply -f deploy/openshift/15-build.yaml

oc start-build lineage --from-dir=. --follow -n lineage-incluster

oc apply -f deploy/openshift/20-htpasswd-rbac.yaml   # optional, HTPasswd only
oc apply -f deploy/openshift/30-deployment.yaml
oc rollout status deploy/lineage -n lineage-incluster
```

Open it locally:

```bash
oc port-forward svc/lineage 8080:8080 -n lineage-incluster
```

Then browse to <http://127.0.0.1:8080>.

## Optional Route

Port-forward is the safest default. If you need a cluster Route:

```bash
oc apply -f deploy/openshift/40-route.yaml
oc get route lineage -n lineage-incluster -o jsonpath='{.spec.host}{"\n"}'
```

Lineage does not include authentication. Only expose the Route where
trusted reviewers can reach it.

## HTPasswd Signals

`20-htpasswd-rbac.yaml` is optional. It grants `get` on the exact Secret
name `htpass-secret` in `openshift-config`.

Apply it only if your cluster uses HTPasswd and you want latent,
phantom, and htpasswd-backed user signals. If your HTPasswd Secret has a
different name, edit `resourceNames` before applying.

## Verify

```bash
POD=$(oc get pod -n lineage-incluster \
  -l app.kubernetes.io/name=lineage \
  -o jsonpath='{.items[0].metadata.name}')

oc exec -n lineage-incluster "$POD" -- oc whoami
# system:serviceaccount:lineage-incluster:lineage
```

Then check `/setup` in the UI.

## Update

```bash
oc start-build lineage --from-dir=. --follow -n lineage-incluster
oc rollout restart deploy/lineage -n lineage-incluster
```

## Remove

```bash
oc delete -f deploy/openshift/40-route.yaml --ignore-not-found
oc delete -f deploy/openshift/30-deployment.yaml --ignore-not-found
oc delete -f deploy/openshift/15-build.yaml --ignore-not-found
oc delete builds -l buildconfig=lineage -n lineage-incluster --ignore-not-found
oc delete -f deploy/openshift/20-htpasswd-rbac.yaml --ignore-not-found
oc delete -f deploy/openshift/10-rbac.yaml --ignore-not-found
oc delete -f deploy/openshift/00-namespace.yaml --ignore-not-found
```
