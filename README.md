<h1 align="center">
  <img src="docs/img/logo.svg" alt="" width="64" height="80" align="absmiddle"/>
  <span>Lineage</span>
</h1>

<p align="center">
  <strong>Who has access to what, and why.</strong><br/>
  <em>Early-v1, read-only OpenShift access lineage explainer.</em>
</p>

<p align="center">
  <a href="https://github.com/Amine-LG/lineage/actions/workflows/test.yml">
    <img src="https://github.com/Amine-LG/lineage/actions/workflows/test.yml/badge.svg" alt="Tests"/>
  </a>
</p>

<p align="center">
  <a href="https://amine-lg.github.io/lineage-demo/demo/"><strong>Try it →</strong></a>
</p>

<p align="center">
  <a href="https://amine-lg.github.io/lineage-demo/video/overview.mp4">
    <img src="https://raw.githubusercontent.com/Amine-LG/lineage-demo/main/video/overview-readme.webp" alt="Lineage overview showing the dashboard and review pages" width="100%"/>
  </a>
</p>

---

## Contents

- [What Lineage Does](#what-lineage-does)
- [Access That Can Come Back](#access-that-can-come-back)
- [Quick Start](#quick-start)
  - [Local Setup](#local-setup)
  - [Local Mock Data](#local-mock-data)
  - [Local Real Cluster](#local-real-cluster)
  - [Helm Install](#helm-install)
  - [OpenShift Build Install](#openshift-build-install)
- [Questions Lineage Answers](#questions-lineage-answers)
- [Global Search](#global-search)
- [How To Read Findings](#how-to-read-findings)
- [Why It Is Useful](#why-it-is-useful)
- [What It Is Not](#what-it-is-not)
- [Is It Safe To Run?](#is-it-safe-to-run)
- [Status](#status)
- [Docs](#docs)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)

## What Lineage Does

Lineage turns OpenShift access objects into explainable paths. Instead of
checking Users, Identities, Groups, ServiceAccounts, RBAC, SCCs, namespaces,
workloads, ImageStreams, and images one at a time, you see the chain that
connects them.

For example, to explain why `alice` can read secrets in `payments-prod`,
Lineage shows the full path:

`alice` -> `engineers` -> `RoleBinding/secret-readers` -> `Role/read-secrets`
-> `get/list secrets in payments-prod`

The same view also surfaces SCC use, cross-namespace ServiceAccount grants,
image relationships, identity anomalies, stale references, and degraded
visibility.

## Access That Can Come Back

One reason Lineage exists is that deleted OpenShift objects do not always
remove the access relationships that named them.

Examples Lineage calls out:

- **Resurrectable ServiceAccount access**: a RoleBinding,
  ClusterRoleBinding, or SCC user entry still names
  `system:serviceaccount:<namespace>:<name>`. If the namespace or
  ServiceAccount is recreated later, the grant can become live again.
- **Resurrectable SCC namespace access**: an SCC grant names
  `system:serviceaccounts:<namespace>`. If that namespace is recreated,
  ServiceAccounts in it may inherit that SCC access.
- **Future SCC target access**: RBAC grants `use` on
  `securitycontextconstraints/<name>` even though the SCC does not exist
  yet. If an SCC with that name is created later, the grant has a target.

Lineage separates these from ordinary live access and marks platform
baseline rows separately when it has enough context.

A step-by-step reproduction of the ClusterRoleBinding case on a non-prod
cluster is in
[docs/access-can-come-back.md](docs/access-can-come-back.md).

<p align="center">
  <a href="https://amine-lg.github.io/lineage-demo/video/dev-to-admin.mp4">
    <img src="https://raw.githubusercontent.com/Amine-LG/lineage-demo/main/video/dev-to-admin-readme.webp" alt="Lineage walkthrough showing access that can come back" width="100%"/>
  </a>
</p>

## Quick Start

Lineage has four common runtime modes. Local modes require Python 3.11.
In-cluster modes run on OpenShift with a dedicated ServiceAccount, so local
Python is not used at runtime.

### Local Setup

```bash
git clone https://github.com/Amine-LG/lineage
cd lineage
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Then choose one mode. Local modes serve `http://127.0.0.1:8080` by default.

### Local Mock Data

Use this to explore the UI without a cluster.

```bash
LINEAGE_MOCK=1 python run.py
```

### Local Real Cluster

Uses your current `oc login` session.

```bash
oc whoami  # must work first; in CRC use: eval "$(crc oc-env)"
python run.py
```

Cluster-admin gives the fullest view. Lower-permission accounts still render
what they can and show degraded visibility on `/setup`.

### Helm Install

Uses the prebuilt GHCR image and is the fastest in-cluster path. Requires a
cluster-admin session because the chart installs read-only cluster RBAC.

```bash
oc whoami  # should be a cluster-admin user, for example kubeadmin

helm install lineage deploy/helm \
  --namespace lineage \
  --create-namespace
```

Add `--set htpasswd.enabled=true` only if your cluster uses HTPasswd and you
want `/setup` to include those optional signals. Full Helm notes:
[deploy/helm/README.md](deploy/helm/README.md).

### OpenShift Build Install

Builds the image inside OpenShift from this local checkout, then deploys from
the internal ImageStream.

```bash
oc apply -f deploy/openshift/00-namespace.yaml \
  -f deploy/openshift/10-rbac.yaml \
  -f deploy/openshift/15-build.yaml
oc start-build lineage --from-dir=. --follow -n lineage-incluster
oc apply -f deploy/openshift/30-deployment.yaml
```

Port-forward, optional Route, optional HTPasswd RBAC, update, and cleanup
steps are documented in [deploy/openshift/README.md](deploy/openshift/README.md).

## Questions Lineage Answers

Lineage is built for questions that usually require jumping across several
OpenShift pages and commands:

- Starting from a User, Group, or ServiceAccount, what can it do, where, and
  through which binding and role?
- Starting from a namespace or workload, which subjects have access there and
  why?
- Did access come from a direct binding, group membership, virtual OpenShift
  group, aggregated role, image-puller grant, or SCC grant?
- Which SCC grants are live now, dormant until an SCC exists, or able to come
  back if a namespace is recreated?
- Which ServiceAccounts can pull or push images across namespace boundaries?
- Which workloads are running mutable image tags, and do their digests drift?
- Which rows are application-owned, unclassified, or platform baseline?
- Which “missing” subjects are harmless platform residue, and which are real
  review findings?
- What could Lineage not read, and how should that change trust in the result?

## Global Search

A search box in the top navigation lets you jump to any object by name —
press <kbd>/</kbd> from anywhere to focus it. It covers Users, Groups,
ServiceAccounts (by short name or full `system:serviceaccount:` principal),
Identities, Namespaces, Roles, ClusterRoles, RoleBindings,
ClusterRoleBindings, SCCs, Workloads (Deployments / DaemonSets / Jobs / …),
Images, and ImageStreams.

Search is intentionally navigation-only — it is not `who-can`, not access
analysis, and not a natural-language query. The full design (lazy loading,
allowlisted fields, what is and isn't indexed) is documented in
[docs/search.md](docs/search.md).

## How To Read Findings

The three "can come back" labels are explained in
[Access That Can Come Back](#access-that-can-come-back). Alongside those,
Lineage uses these identity and reference labels:

- **Ghost**: a binding names a User, Group, or ServiceAccount that does not exist.
- **Latent**: an HTPasswd entry exists, but no OpenShift User exists yet.
- **Phantom**: a User and Identity exist, but the HTPasswd entry is gone.
- **Stranded**: a User exists without an Identity.
- **Orphan identity**: an Identity points to a missing User.

These are review signals, not automatic incidents. Lineage separates
actionable rows from platform baseline rows where it has enough context.

## Why It Is Useful

OpenShift access is rarely in one place. A subject can get access through a
direct binding, a team group, a virtual system group, an aggregated role, an
SCC grant, or an image-puller relationship. Some grants are live now; others
only become dangerous when a namespace, ServiceAccount, User, Group, or SCC is
created later.

Lineage helps reviewers and learners see those paths together:

- Platform and security teams can explain access with the exact binding,
  role, subject, and scope behind it.
- Application teams can see which ServiceAccounts, image pullers, workloads,
  and namespaces are connected.
- Reviewers can separate user-created findings from OpenShift baseline noise.
- Cleanup work can focus on stale, ghost, dormant, and resurrectable paths
  instead of raw object counts.
- Learners can study how OpenShift RBAC, SCCs, identities, virtual groups, and
  images interact in a real cluster shape.

## What It Is Not

- Not an enforcement tool.
- Not a policy engine.
- Not a vulnerability scanner.
- Not real-time; live data is cached for 5 minutes unless refreshed.
- Not Kubernetes-generic in v1; it is intentionally OpenShift-shaped.

## Is It Safe To Run?

Lineage is read-only:

- uses `get`, `list`, and `oc auth can-i`;
- does not run `create`, `patch`, `apply`, `delete`, or `edit` against the
  inspected cluster;
- does not inventory cluster-wide Secrets;
- reads the optional HTPasswd Secret by exact name only;
- does not inventory ServiceAccount-token Secrets;
- shows limited visibility as degraded, not as clean.

See [docs/permissions.md](docs/permissions.md).

## Status

Early-v1 release state.

- Tested on CRC / OpenShift 4.19.8 and 4.21.8.
- Tested in local mock, local real-cluster, and in-cluster ServiceAccount modes.
- Current validation scope is OpenShift-focused; large production clusters
  and plain Kubernetes need separate validation.

## Docs

| Topic | File |
| --- | --- |
| Quickstart | [docs/quickstart.md](docs/quickstart.md) |
| In-cluster install | [docs/in-cluster.md](docs/in-cluster.md) |
| Helm chart | [deploy/helm/README.md](deploy/helm/README.md) |
| OpenShift manifests | [deploy/openshift/README.md](deploy/openshift/README.md) |
| Permissions | [docs/permissions.md](docs/permissions.md) |
| How it works | [docs/how-lineage-works.md](docs/how-lineage-works.md) |
| Access that can come back | [docs/access-can-come-back.md](docs/access-can-come-back.md) |
| Image-puller grants | [docs/image-pullers.md](docs/image-pullers.md) |
| CLI and tests | [docs/cli-and-tests.md](docs/cli-and-tests.md) |
| Global search | [docs/search.md](docs/search.md) |
| Tuning | [docs/tuning.md](docs/tuning.md) |
| Performance | [docs/performance.md](docs/performance.md) |

## Roadmap

V1 is focused on clear read-only explanation. Likely next areas:

- UI/UX improvements for faster reviews;
- deeper relationship coverage across RBAC, SCCs, identities, and images;
- broader OpenShift version and scale testing;
- better refresh behavior for larger clusters;
- exportable review reports;
- Kubernetes support after the OpenShift model is stronger.

## Contributing

Issues, careful bug reports, and focused pull requests are welcome. Please
keep v1 changes small, read-only, and OpenShift-focused; include tests for
behavior changes and avoid hiding risky custom access as platform baseline.

## Acknowledgments

Lineage is designed, maintained, tested, and release-reviewed by the
maintainer. OpenAI and Anthropic models helped implement code, refactor
changes, write tests, and draft documentation.

## License

MIT. See [LICENSE](LICENSE).
