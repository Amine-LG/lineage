# Quickstart

Run Lineage locally with mock data, or against the OpenShift cluster your
`oc` command is already logged into.

## Requirements

- Python 3.11 for local modes
- `oc` on your `PATH` for real-cluster mode

In-cluster mode builds and runs inside OpenShift, so your local Python
version is not used at runtime.

## Install For Local Modes

```bash
git clone https://github.com/Amine-LG/lineage
cd lineage
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Both local modes serve `http://127.0.0.1:8080` by default.

## Mock Mode

No cluster required.

```bash
LINEAGE_MOCK=1 python run.py
```

## Real-Cluster Mode

Uses your current `oc login` session.

```bash
oc whoami  # must work first; in CRC use: eval "$(crc oc-env)"
python run.py
```

Cluster-admin gives the fullest view. Lower-permission users still get
honest partial results, and `/setup` shows which reads failed.

## In-Cluster Mode

Run Lineage as a Pod with a dedicated ServiceAccount:

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

Skip `20-htpasswd-rbac.yaml` if your cluster does not use HTPasswd or you do
not want latent/phantom user signals.

More detail: [in-cluster.md](in-cluster.md).

## Useful Env Vars

| Variable | Default | Purpose |
| --- | --- | --- |
| `LINEAGE_MOCK` | unset | `1` uses bundled mock data |
| `LINEAGE_HOST` | `127.0.0.1` | Flask bind address |
| `LINEAGE_PORT` | `8080` | Flask port |
| `LINEAGE_DEBUG` | unset | `1` enables Flask debug mode |
| `LINEAGE_SECRET_KEY` | random | session key used by `/refresh` |

Health check:

```bash
curl http://127.0.0.1:8080/healthz
# ok
```
