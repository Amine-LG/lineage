# In-Cluster Mode

In-cluster mode runs Lineage as a Deployment in OpenShift. The Pod uses
its own ServiceAccount and the normal mounted token. No kubeconfig is
generated.

The bundled BuildConfig builds from this repo using the root
[Containerfile](../Containerfile). That Containerfile is intentionally small:

- first stage: `quay.io/openshift/origin-cli:4.19`, used only to copy the
  `oc` binary into the final image;
- final stage: `python:3.11-slim-bookworm`, used to install Lineage and run
  `python run.py`;
- runtime: `oc` uses the Pod ServiceAccount token mounted by OpenShift.

During the build, the cluster must be able to pull those two external base
images. The finished Lineage image is written to the internal
`lineage:latest` ImageStreamTag in `lineage-incluster`.

## Install

```bash
oc apply -f deploy/openshift/00-namespace.yaml
oc apply -f deploy/openshift/10-rbac.yaml
oc apply -f deploy/openshift/15-build.yaml

oc start-build lineage --from-dir=. --follow -n lineage-incluster

oc apply -f deploy/openshift/20-htpasswd-rbac.yaml   # optional, HTPasswd only
oc apply -f deploy/openshift/30-deployment.yaml
oc rollout status deploy/lineage -n lineage-incluster

oc port-forward svc/lineage 8080:8080 -n lineage-incluster
```

Open <http://127.0.0.1:8080>.

The optional HTPasswd RBAC grants `get` on one Secret name in
`openshift-config`. Leave it unapplied if your cluster does not use
HTPasswd or you do not want that signal.

The build step is a binary build:

```bash
oc start-build lineage --from-dir=. --follow -n lineage-incluster
```

That uploads your local source tree to OpenShift and lets the cluster build
the image. It does not require a public Git URL or a local registry push.

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

Manifest reference: [../deploy/openshift/README.md](../deploy/openshift/README.md).
