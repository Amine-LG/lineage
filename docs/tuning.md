# Tuning

Most users should not need tuning. These knobs are here for local runs,
demos, and clusters with unusual naming rules.

## Environment

| Variable | Default | Effect |
| --- | --- | --- |
| `LINEAGE_MOCK` | unset | `1` uses mock data |
| `LINEAGE_HOST` | `127.0.0.1` | bind address |
| `LINEAGE_PORT` | `8080` | port |
| `LINEAGE_DEBUG` | unset | `1` enables Flask debug mode |
| `LINEAGE_SECRET_KEY` | random | session key for `/refresh` |

## Cache

The live index cache is 5 minutes:

```text
lineage/cluster.py: CACHE_TTL_SECONDS = 300
```

The **Refresh** button invalidates it immediately.

## Classification

Namespace and image classification lives in `lineage/classifier.py`.

Important buckets:

- `project`: user-created OpenShift Project;
- `openshift` / `system`: platform namespaces;
- `unclassified`: not platform, but no strong project signal;
- image categories such as `internal`, `redhat`, `quay-openshift`, and
  `public`.

Do not tune baseline rules just to hide risky custom access. It is better
for Lineage to show a review-worthy object than to silently classify it
away.

## Severity

Severity and privileged role hints live mostly in `lineage/engine/`.
If you change them, add focused tests. Small wording changes are safer
than changing what counts as actionable.
