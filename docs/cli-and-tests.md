# CLI And Tests

## Tests

Use Python 3.11:

```bash
python3.11 -m pip install -r requirements-dev.txt
python3.11 -m pytest
```

Current release suite:

```text
480 passed
```

The tests cover the mock dataset, relationship engine, UI routes, CLI
output, degraded views, identity anomalies, SCC relationships, image
views, and resurrectable access cases.

## CLI Audit

The CLI audit uses the same current `oc` session as local real-cluster mode.
It is useful when you want a terminal-friendly review summary or JSON output
for a release check.

```bash
python3.11 -m lineage audit
python3.11 -m lineage audit --json --fail-on=none
python3.11 -m lineage audit --fail-on=any
```

The text output is meant for humans. It summarizes identity anomalies,
resurrectable ServiceAccounts, SCC resurrection/future-target grants,
bound ghosts, stranded users, orphan identities, privileged grants, duplicate
bindings, and degraded visibility warnings.

The JSON output is meant for `jq`, CI logs, or archived review evidence.

Exit-code modes:

| Mode | Meaning |
| --- | --- |
| `--fail-on=real` | default; exits non-zero for actionable findings |
| `--fail-on=any` | exits non-zero for any finding, including baseline |
| `--fail-on=none` | always exits zero; informational output only |

The CLI is read-only. It uses Lineage's normal cluster reads and does not
apply, patch, delete, or mutate inspected cluster objects.
