# How Lineage Works

Lineage builds one in-memory view of the cluster, then renders pages and
CLI output from that view.

```text
Flask route / CLI
  -> lineage.engine.index()
  -> lineage.data
  -> mock data or oc-backed cluster reads
```

Mock mode uses `lineage/mock_data.py`. Real modes shell out through
`lineage/cluster.py` and use the current `oc` identity.

## Main Relationships

- **Subject -> rule**: User, Group, or ServiceAccount to Binding to Role
  or ClusterRole to API rules.
- **Group expansion**: real OpenShift Groups plus virtual groups such as
  `system:authenticated` and `system:serviceaccounts:<namespace>`.
- **SCC access**: direct `scc.users` / `scc.groups` plus RBAC `use` grants.
- **Resurrectables**: stale ServiceAccount and implicit-SCC-group grants
  that can become active again if a namespace or subject is recreated.
- **Future SCC targets**: RBAC grants to an SCC name that does not exist yet.
- **Images**: pod images, ImageStreams, registries, and mutable-tag drift.

## Cache And Visibility

Live cluster reads are cached in process for 5 minutes. The **Refresh**
button clears the cache.

If a read fails, the error is kept in the index and shown in the UI.
Limited visibility is treated as degraded, not as proof that nothing
exists.

## Main Files

| File | Purpose |
| --- | --- |
| `lineage/cluster.py` | `oc` reads and cache |
| `lineage/openshift/` | OpenShift object reshaping |
| `lineage/data.py` | mock/live data switch |
| `lineage/engine/` | relationship logic |
| `lineage/classifier.py` | baseline/project/unclassified rules |
| `lineage/main.py` | Flask routes |
| `lineage/ui/pages/` | route view models |
| `lineage/ui/` | template filters and bucket helpers |
| `lineage/cli.py` | CLI audit output |

`lineage/ui/` contains Python view-model helpers; Jinja templates and browser
assets stay in `lineage/templates/` and `lineage/static/` to match Flask's
default layout.
