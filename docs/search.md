# Global search

A jump-to box in the top navigation. Type, hit Enter, land on the page.

## How to use

- Click the box, or press <kbd>/</kbd> from anywhere on a Lineage page.
- Two-character minimum — one character shows the examples hint.
- <kbd>↑</kbd>/<kbd>↓</kbd> navigate, <kbd>Enter</kbd> opens, <kbd>Esc</kbd> closes.

## What it indexes

**Primary** — Users, Groups (real and virtual like `system:authenticated`),
ServiceAccounts (by short name, namespace, or full
`system:serviceaccount:<ns>:<name>` principal), Identities, Namespaces,
ClusterRoles, Roles, ClusterRoleBindings, RoleBindings, SCCs.

**Secondary** (still searchable, ranked below primary on tied scores) —
Workloads (Deployments, DaemonSets, StatefulSets, Jobs, CronJobs, derived
from pod owner references with ReplicaSet hash suffixes stripped to
recover the Deployment name), Images, ImageStreams.

Deliberately excluded: individual pods (search the workload instead),
HTPasswd entries (covered by the User entry), OAuth providers (no own
page), capability queries (use `/who-can`).

## Match order

Exact display → exact token → display prefix → token prefix → display
substring → token substring. Primary kinds outrank secondary on tied
scores. Top 30 matches shown.

## The `/` shortcut detail worth knowing

Pressing <kbd>/</kbd> on an *empty* search box re-focuses it rather than
typing a literal slash. Without that, `/` would match every image ref
and every `<ns>/<name>` row and flood the dropdown. Mid-content slashes
still type normally — `docker.io/library` works fine.

## Performance and scope

- A normal page load does **not** fetch the search index. Only a small
  client script (~10 KB raw, ~3 KB gzipped) ships with every page.
- The first focus or <kbd>/</kbd> press fetches `/search-index.json`
  once. All subsequent matching is client-side.
- The endpoint reuses Lineage's normal 300 s cache. It never triggers
  a refresh just for search.
- Each item exposes only seven fields: `id`, `kind`, `display`,
  `namespace`, `description`, `url`, `tokens`. Raw Kubernetes objects,
  annotations, labels, rules, roleRefs, subjects, and Secret data are
  never indexed.

Search is navigation only — not access analysis, not natural language,
not fuzzy matching. If JavaScript is disabled, the rest of Lineage
works normally; only the search dropdown is unavailable.
