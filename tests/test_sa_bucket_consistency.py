"""Bucket consistency for ServiceAccount classifications across views.

Found on live CRC during the SA+SCC+RBAC validation cycle: a missing SA
in a deleted namespace classified differently across views.

  - /subjects (all_subjects):  ['ghost','resurrectable']  → Yours bucket
  - /who-can (who_can):        ['ghost','unknown']        → Unclassified bucket

Root cause: is_unknown_subject for ServiceAccount delegated to
is_unknown_namespace, which blanket-classifies any *missing* namespace as
unknown. The all_subjects path uses is_unknown_absent_sa, which says
"absent namespace → not unknown". The fix aligns is_unknown_subject with
the absent-SA semantics so every view classifies the same SA the same way.
"""

from lineage import engine
from .conftest import make_index


def _idx_with_resurrectable_in_deleted_ns():
    return make_index(
        cluster_roles=[{"name": "view", "labels": {}, "annotations": {},
                         "aggregationRule": None,
                         "rules": [{"apiGroups": [""],
                                    "resources": ["configmaps"],
                                    "verbs": ["get"]}],
                         "creationTimestamp": "2025-01-01T00:00:00Z"}],
        crbs=[{"name": "gone-sa-view",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "gone-sa",
                              "namespace": "val-gone"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )


def test_deleted_namespace_sa_not_unknown_in_who_can():
    """A resurrectable SA in a DELETED namespace must NOT inherit
    `unknown` in who-can. The namespace is gone, we can't claim a
    classification, so the matching all_subjects model is 'Yours'."""
    idx = _idx_with_resurrectable_in_deleted_ns()
    matches = engine.who_can("get", "configmaps", "anywhere", idx)
    gone = next((m for m in matches
                 if m["subject"].get("kind") == "ServiceAccount"
                 and m["subject"].get("name") == "gone-sa"), None)
    assert gone is not None
    assert gone["ghost"] is True
    # The headline fix:
    assert gone["unknown"] is False
    assert gone["baseline"] is False


def test_deleted_namespace_sa_not_unknown_in_all_subjects():
    """Sanity: /subjects view of the same SA is also Yours (ghost +
    resurrectable, but neither baseline nor unknown)."""
    idx = _idx_with_resurrectable_in_deleted_ns()
    subs = engine.all_subjects(idx)
    gone = next((s for s in subs
                 if s.get("kind") == "ServiceAccount"
                 and s.get("name") == "gone-sa"), None)
    assert gone is not None
    assert gone["ghost"] is True
    assert gone["unknown"] is False
    assert gone["baseline"] is False
    assert gone.get("resurrectable") is True


def test_present_unclassified_namespace_sa_still_unknown():
    """Regression guard: an SA in an Unclassified namespace that
    PRESENTLY exists (oc create namespace, no requester) DOES remain
    unknown — the consistency fix must not collapse that signal."""
    idx = make_index(
        namespaces=[{"name": "val-raw", "labels": {}, "annotations": {}}],
        sas=[{"name": "raw-runner", "namespace": "val-raw",
              "labels": {},
              "creationTimestamp": "2025-01-01T00:00:00Z"}],
        cluster_roles=[{"name": "view", "labels": {}, "annotations": {},
                         "aggregationRule": None,
                         "rules": [{"apiGroups": [""],
                                    "resources": ["configmaps"],
                                    "verbs": ["get"]}],
                         "creationTimestamp": "2025-01-01T00:00:00Z"}],
        crbs=[{"name": "raw-view",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "raw-runner",
                              "namespace": "val-raw"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    matches = engine.who_can("get", "configmaps", "val-raw", idx)
    raw = next((m for m in matches
                if m["subject"].get("kind") == "ServiceAccount"
                and m["subject"].get("name") == "raw-runner"), None)
    assert raw is not None
    assert raw["unknown"] is True
    assert raw["baseline"] is False


def test_baseline_namespace_sa_still_baseline():
    """Regression guard: SA in a baseline ns (kube-system) is still baseline."""
    idx = make_index(
        namespaces=[{"name": "kube-system", "labels": {}, "annotations": {}}],
        sas=[{"name": "default", "namespace": "kube-system", "labels": {},
              "creationTimestamp": "2025-01-01T00:00:00Z"}],
        cluster_roles=[{"name": "view", "labels": {}, "annotations": {},
                         "aggregationRule": None,
                         "rules": [{"apiGroups": [""],
                                    "resources": ["configmaps"],
                                    "verbs": ["get"]}],
                         "creationTimestamp": "2025-01-01T00:00:00Z"}],
        crbs=[{"name": "ks-view",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "default",
                              "namespace": "kube-system"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    matches = engine.who_can("get", "configmaps", "kube-system", idx)
    row = next((m for m in matches
                if m["subject"].get("kind") == "ServiceAccount"
                and m["subject"].get("namespace") == "kube-system"), None)
    assert row is not None
    assert row["baseline"] is True
    assert row["unknown"] is False
