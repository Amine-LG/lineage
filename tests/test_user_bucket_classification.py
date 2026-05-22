"""Subject-bucket classification — User vs Group vs ServiceAccount.

Reproduces the live-cluster bug where human Users bound by a RoleBinding
in an Unclassified namespace (CRC `hello` was created with `kubectl
apply`, no `openshift.io/requester`) appeared as `unknown=True` in
/who-can. The fix makes the row's bucket subject-driven: User and Group
classification follows their identity/provenance state, not the binding
namespace.
"""

from lineage import engine
from lineage.main import app
from .conftest import make_index


def _hello_idx(extras=None):
    """`hello` is Unclassified (no requester annotation, no name match).
    Bind a few User subjects there via a custom RoleBinding."""
    crs = [{"name": "secret-reader", "labels": {}, "annotations": {},
            "aggregationRule": None,
            "rules": [{"apiGroups": [""], "resources": ["secrets"],
                       "verbs": ["get", "list"]}],
            "creationTimestamp": "2025-01-01T00:00:00Z"}]
    base = {
        "users": [
            {"name": "tom"},
            {"name": "stranded-lineage-user"},
        ],
        "identities": [
            {"name": "cool:tom", "user": {"name": "tom"},
             "providerName": "cool"},
        ],
        "namespaces": [
            {"name": "hello", "labels": {}, "annotations": {}},  # Unclassified
        ],
        "cluster_roles": crs,
        "rbs": [
            {"name": "admin-tom", "namespace": "hello",
             "subjects": [{"kind": "User", "name": "tom"}],
             "roleRef": {"kind": "ClusterRole", "name": "secret-reader"}},
            {"name": "admin-stranded", "namespace": "hello",
             "subjects": [{"kind": "User", "name": "stranded-lineage-user"}],
             "roleRef": {"kind": "ClusterRole", "name": "secret-reader"}},
            {"name": "admin-ghost", "namespace": "hello",
             "subjects": [{"kind": "User", "name": "ghost-user"}],
             "roleRef": {"kind": "ClusterRole", "name": "secret-reader"}},
        ],
    }
    if extras:
        for k, v in extras.items():
            if k in base and isinstance(base[k], list):
                base[k] = base[k] + list(v)
            else:
                base[k] = v
    return make_index(**base)


def _who_can_row(idx, kind, name, namespace="hello"):
    matches = engine.who_can("get", "secrets", namespace, idx)
    for m in matches:
        s = m.get("subject") or {}
        if s.get("kind") == kind and s.get("name") == name:
            return m
    return None


# ---------- User classification in unclassified-namespace binding ---------- #

def test_human_user_with_identity_not_unknown_in_unclassified_binding():
    """The reported bug: tom has a normal Identity, is bound by a
    RoleBinding in `hello` (Unclassified). who_can must NOT label him
    unknown."""
    idx = _hello_idx()
    row = _who_can_row(idx, "User", "tom")
    assert row is not None
    assert row["unknown"] is False
    assert row["baseline"] is False
    # tom isn't a ghost either — User object exists.
    assert row["ghost"] is False


def test_stranded_user_not_unknown_in_unclassified_binding():
    """A User without Identity should classify as stranded/yours, not
    blindly inherit the binding namespace's Unclassified bucket."""
    idx = _hello_idx()
    row = _who_can_row(idx, "User", "stranded-lineage-user")
    assert row is not None
    assert row["unknown"] is False
    assert row["ghost"] is False
    # The User exists in users_by_name but has no identities → stranded
    # is reflected via engine.subject_identity_markers (used elsewhere);
    # who_can rows don't carry that marker, but the row must not be
    # falsely 'unknown'.


def test_missing_user_in_unclassified_binding_still_ghost():
    """ghost-user has no User object — should still appear as a ghost
    row. The fix removed binding-ns inheritance, NOT ghost detection."""
    idx = _hello_idx()
    row = _who_can_row(idx, "User", "ghost-user")
    assert row is not None
    assert row["ghost"] is True
    # And not falsely unknown.
    assert row["unknown"] is False


def test_missing_user_in_default_is_real_actionable_ghost():
    """Pinning the post-fix behavior: a user-named RoleBinding in
    `default` (or any baseline-named ns) bound to a nonexistent User
    is NOT baseline. The prior 'ns is baseline → binding is baseline'
    shortcut hid the `oc adm policy add-role-to-user edit editor`
    (no `-n`) misconfiguration."""
    idx = make_index(
        namespaces=[{"name": "default", "labels": {}, "annotations": {}}],
        cluster_roles=[{"name": "view", "labels": {}, "annotations": {},
                         "aggregationRule": None,
                         "rules": [{"apiGroups": [""],
                                    "resources": ["secrets"],
                                    "verbs": ["get"]}],
                         "creationTimestamp": "2025-01-01T00:00:00Z"}],
        rbs=[{"name": "default-ghost", "namespace": "default",
              "subjects": [{"kind": "User", "name": "ghost-user"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    row = _who_can_row(idx, "User", "ghost-user", namespace="default")
    assert row is not None
    assert row["ghost"] is True
    assert row["baseline"] is False
    assert row["unknown"] is False


# ---------- Group classification — system:serviceaccounts:<ns> ---------- #

def test_group_system_serviceaccounts_in_unclassified_namespace_unknown():
    """system:serviceaccounts:<ns> means every SA in <ns>. Its bucket
    must follow that namespace, not blanket-baseline the system: prefix."""
    idx = _hello_idx(extras={
        "rbs": [{"name": "sa-group-binding", "namespace": "hello",
                 "subjects": [{"kind": "Group",
                                "name": "system:serviceaccounts:hello"}],
                 "roleRef": {"kind": "ClusterRole",
                              "name": "secret-reader"}}],
    })
    row = _who_can_row(idx, "Group", "system:serviceaccounts:hello")
    assert row is not None
    assert row["baseline"] is False
    assert row["unknown"] is True


def test_group_system_serviceaccounts_in_baseline_namespace_is_baseline():
    """system:serviceaccounts:kube-system — baseline ns — stays baseline."""
    idx = make_index(
        namespaces=[
            {"name": "kube-system", "labels": {}, "annotations": {}},
            {"name": "hello", "labels": {}, "annotations": {}},
        ],
        cluster_roles=[{"name": "secret-reader", "labels": {},
                         "annotations": {}, "aggregationRule": None,
                         "rules": [{"apiGroups": [""],
                                    "resources": ["secrets"],
                                    "verbs": ["get"]}],
                         "creationTimestamp": "2025-01-01T00:00:00Z"}],
        rbs=[{"name": "all-sas-in-kube-system", "namespace": "hello",
              "subjects": [{"kind": "Group",
                             "name": "system:serviceaccounts:kube-system"}],
              "roleRef": {"kind": "ClusterRole", "name": "secret-reader"}}],
    )
    row = _who_can_row(idx, "Group", "system:serviceaccounts:kube-system")
    assert row is not None
    assert row["baseline"] is True
    assert row["unknown"] is False


def test_group_non_sa_pattern_not_unknown_in_unclassified_binding():
    """A regular Group bound in an Unclassified namespace must NOT
    become Unclassified — Group bucket logic is provenance-driven, not
    binding-ns-driven (same principle as Users)."""
    idx = _hello_idx(extras={
        "groups": [{"name": "engineers", "users": ["tom"],
                    "creationTimestamp": "2025-01-01T00:00:00Z"}],
        "rbs": [{"name": "engineers-binding", "namespace": "hello",
                 "subjects": [{"kind": "Group", "name": "engineers"}],
                 "roleRef": {"kind": "ClusterRole",
                              "name": "secret-reader"}}],
    })
    row = _who_can_row(idx, "Group", "engineers")
    assert row is not None
    assert row["unknown"] is False
    assert row["baseline"] is False


# ---------- ServiceAccount classification unchanged ---------- #

def test_sa_in_unknown_namespace_still_unknown():
    """An SA living in an Unclassified namespace is correctly Unclassified
    because the unknown comes from the SA's OWN namespace (not binding ns)."""
    idx = make_index(
        namespaces=[
            {"name": "tom-sandbox", "labels": {}, "annotations": {}},
        ],
        sas=[{"name": "runner", "namespace": "tom-sandbox", "labels": {},
              "creationTimestamp": "2025-01-01T00:00:00Z"}],
        cluster_roles=[{"name": "secret-reader", "labels": {},
                         "annotations": {}, "aggregationRule": None,
                         "rules": [{"apiGroups": [""],
                                    "resources": ["secrets"],
                                    "verbs": ["get"]}],
                         "creationTimestamp": "2025-01-01T00:00:00Z"}],
        rbs=[{"name": "runner-binding", "namespace": "tom-sandbox",
              "subjects": [{"kind": "ServiceAccount", "name": "runner",
                             "namespace": "tom-sandbox"}],
              "roleRef": {"kind": "ClusterRole", "name": "secret-reader"}}],
    )
    matches = engine.who_can("get", "secrets", "tom-sandbox", idx)
    sa_row = next((m for m in matches
                   if m["subject"].get("kind") == "ServiceAccount"
                   and m["subject"].get("name") == "runner"), None)
    assert sa_row is not None
    assert sa_row["unknown"] is True
    assert sa_row["baseline"] is False


# ---------- /who-can rendered output ---------- #

def test_who_can_page_does_not_render_unclassified_badge_on_normal_user(
        monkeypatch):
    """End-to-end render check: tom should not have an unclassified
    badge on /who-can when bound by a RoleBinding in an Unclassified ns."""
    idx = _hello_idx()
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as client:
        body = client.get(
            "/who-can?verb=get&resource=secrets&namespace=hello"
        ).data.decode()
    # Locate tom's row and check no unclassified badge near it.
    i = body.find(">tom<")
    assert i >= 0, "tom row missing from /who-can render"
    excerpt = body[max(0, i - 200):i + 600]
    assert "unclassified" not in excerpt.lower()
