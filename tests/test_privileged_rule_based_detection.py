"""Privileged classification must consider role *rules*, not just role *name*.

A custom ClusterRole with `verbs:["*"]` on `resources:["*"]` in `apiGroups:["*"]`
is functionally cluster-admin even if its name is not in `PRIVILEGED_ROLES`.
Subjects bound to such a role must appear on `/privileged`.
"""

from .conftest import make_index

from lineage import engine
from lineage.engine._resurrectable import (
    _is_privileged_role_name,
    _role_has_star_grant,
)


STAR_RULE = {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}


def _build(*, cluster_roles, crbs):
    idx = make_index(cluster_roles=cluster_roles, crbs=crbs)
    idx["is_admin"] = True
    idx["fetch_error_kinds"] = set()
    return idx


def _bind(user, role_name, binding_name):
    return {
        "name": binding_name,
        "subjects": [{"kind": "User", "name": user,
                      "apiGroup": "rbac.authorization.k8s.io"}],
        "roleRef": {"kind": "ClusterRole", "name": role_name,
                    "apiGroup": "rbac.authorization.k8s.io"},
    }


def test_builtin_privileged_role_names_still_classified():
    """The original name-based check must not regress."""
    idx = _build(cluster_roles=[], crbs=[])
    assert _is_privileged_role_name("cluster-admin", idx) is True
    assert _is_privileged_role_name("admin", idx) is True
    assert _is_privileged_role_name("system:masters", idx) is True


def test_custom_star_on_star_role_classified_as_privileged():
    """The bug fix: a custom ClusterRole with *-on-* rules is privileged
    regardless of name."""
    custom = {"name": "monitoring-controller", "aggregationRule": None,
              "rules": [STAR_RULE]}
    crb = _bind("monitoring-svc", "monitoring-controller", "monitoring-bind")
    idx = _build(cluster_roles=[custom], crbs=[crb])

    assert _role_has_star_grant("monitoring-controller", idx) is True
    assert _is_privileged_role_name("monitoring-controller", idx) is True

    privileged = engine.privileged_subjects(idx)
    subjects = [p["subject"].get("name") for p in privileged]
    assert "monitoring-svc" in subjects


def test_misleading_role_name_with_view_only_rules_is_NOT_privileged():
    """Negative control: a role whose name resembles 'admin' but whose
    rules are read-only must NOT be flagged as privileged."""
    ro = {"name": "cluster-admin-readonly", "aggregationRule": None,
          "rules": [{"apiGroups": [""], "resources": ["pods"],
                     "verbs": ["get", "list"]}]}
    crb = _bind("ro-svc", "cluster-admin-readonly", "ro-bind")
    idx = _build(cluster_roles=[ro], crbs=[crb])

    assert _role_has_star_grant("cluster-admin-readonly", idx) is False
    assert _is_privileged_role_name("cluster-admin-readonly", idx) is False

    privileged = engine.privileged_subjects(idx)
    subjects = [p["subject"].get("name") for p in privileged]
    assert "ro-svc" not in subjects


def test_aggregator_inheriting_star_via_components_is_privileged():
    """If an aggregator has empty inline rules but its component roles
    contribute a *-on-* rule, the aggregator's *expanded* rules contain
    *-on-* and the role must be classified as privileged."""
    component = {
        "name": "star-component",
        "labels": {"lineage-test/star": "true"},
        "rules": [STAR_RULE],
        "aggregationRule": None,
    }
    aggregator = {
        "name": "meta-admin",
        "aggregationRule": {
            "clusterRoleSelectors": [
                {"matchLabels": {"lineage-test/star": "true"}}
            ]
        },
        "rules": [],
    }
    crb = _bind("meta-svc", "meta-admin", "meta-bind")
    idx = _build(cluster_roles=[component, aggregator], crbs=[crb])

    assert _role_has_star_grant("meta-admin", idx) is True
    assert _is_privileged_role_name("meta-admin", idx) is True

    privileged = engine.privileged_subjects(idx)
    subjects = [p["subject"].get("name") for p in privileged]
    assert "meta-svc" in subjects


def test_partial_star_does_not_qualify():
    """Only literal `verbs:["*"] AND resources:["*"] AND apiGroups:["*"]`
    qualifies. Roles that star only ONE dimension are powerful but not
    cluster-admin-equivalent and should not be auto-flagged here."""
    partial_cases = [
        # verbs:[*] resources:[*] apiGroups:[""] — all core resources only
        {"apiGroups": [""], "resources": ["*"], "verbs": ["*"]},
        # verbs:[*] resources:[secrets] apiGroups:[""] — only secrets
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["*"]},
        # verbs:[create,delete] resources:[*] apiGroups:[*] — destructive,
        # but not literal star verb (separate severity tier)
        {"apiGroups": ["*"], "resources": ["*"],
         "verbs": ["create", "delete", "patch", "update"]},
    ]
    for i, rule in enumerate(partial_cases):
        role = {"name": f"partial-{i}", "aggregationRule": None, "rules": [rule]}
        crb = _bind(f"svc-{i}", f"partial-{i}", f"bind-{i}")
        idx = _build(cluster_roles=[role], crbs=[crb])
        assert _role_has_star_grant(f"partial-{i}", idx) is False, (
            f"partial-{i} with rule {rule} was incorrectly flagged as star grant")


def test_role_lookup_failure_returns_false():
    """When the role can't be found in the index (e.g. binding references a
    deleted/non-existent ClusterRole), the rule check must not crash."""
    idx = _build(cluster_roles=[], crbs=[])
    assert _role_has_star_grant("does-not-exist", idx) is False
    assert _role_has_star_grant("", idx) is False
    assert _role_has_star_grant(None, idx) is False


def test_idx_none_returns_false():
    """No index means we can't look up rules; must not crash."""
    assert _role_has_star_grant("cluster-admin", None) is False
