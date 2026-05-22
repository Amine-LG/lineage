"""Regressions for the three relationship issues:

1. Aggregation — `audit['bound_ghosts']` shows ONE row per missing
   principal even when the same name is bound by N bindings, but each
   row carries `grants=[…]` and `grant_count`.
2. SCC ghost subjects — `oc adm policy add-scc-to-group anyuid
   crazy-anyuid-group` (group doesn't exist) must surface under the
   SCC resurrectable family, not only under bound-ghosts.
3. Virtual reach for ghosts — `/subject/User/<ghost>` must NOT show
   `system:authenticated[:oauth]` paths because the principal cannot
   authenticate.
"""
from lineage import engine
from lineage.main import app
from .conftest import make_index, scc_use_clusterrole as _scc_use_clusterrole


def _edit_role():
    return {
        "name": "edit", "labels": {}, "annotations": {},
        "aggregationRule": None,
        "rules": [{"apiGroups": ["*"], "resources": ["deployments"],
                   "verbs": ["*"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }


def _scc(name, **kwargs):
    return {
        "name": name,
        "users": kwargs.pop("users", []),
        "groups": kwargs.pop("groups", []),
        "allowPrivilegedContainer": kwargs.pop("allowPrivilegedContainer", False),
        "allowHostNetwork": False, "allowHostPID": False, "allowHostIPC": False,
        "allowPrivilegeEscalation": kwargs.pop("allowPrivilegeEscalation", True),
        "runAsUser": kwargs.pop("runAsUser", {"type": "MustRunAs"}),
        "creationTimestamp": "2024-01-01T00:00:00Z",
        **kwargs,
    }


# ====================================================================== #
# Issue 1 — Aggregation                                                  #
# ====================================================================== #

def test_bound_ghosts_aggregate_one_row_per_missing_principal():
    """User `editor` bound by TWO RBs (in `default` and `demo`) must
    appear as ONE bound-ghost row with grants=[…2 bindings…]."""
    idx = make_index(
        namespaces=[{"name": "default", "labels": {}, "annotations": {}},
                     {"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role()],
        rbs=[
            {"name": "edit", "namespace": "default",
             "subjects": [{"kind": "User", "name": "editor"}],
             "roleRef": {"kind": "ClusterRole", "name": "edit"}},
            {"name": "edit", "namespace": "demo",
             "subjects": [{"kind": "User", "name": "editor"}],
             "roleRef": {"kind": "ClusterRole", "name": "edit"}},
        ],
    )
    a = engine.identity_audit(idx)
    editor_rows = [g for g in a["bound_ghosts"]
                   if g["subject"]["name"] == "editor"]
    assert len(editor_rows) == 1
    row = editor_rows[0]
    assert row["grant_count"] == 2
    grant_namespaces = sorted(g["namespace"] for g in row["grants"])
    assert grant_namespaces == ["default", "demo"]
    # Category 'real' iff any of the grants is real (both are here)
    assert row["category"] == "real"


def test_aggregated_ghost_carries_role_info_per_grant():
    """Each binding inside grants[] must carry role/role_kind so the
    table can render the per-binding path even after aggregation."""
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role()],
        rbs=[{"name": "edit", "namespace": "demo",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    a = engine.identity_audit(idx)
    row = [g for g in a["bound_ghosts"]
           if g["subject"]["name"] == "editor"][0]
    g0 = row["grants"][0]
    assert g0["role"] == "edit"
    assert g0["role_kind"] == "ClusterRole"
    assert g0["kind"] == "RoleBinding"
    assert g0["namespace"] == "demo"


def test_home_ghost_count_reflects_distinct_principals(monkeypatch):
    """Home review snapshot for ghost users counts DISTINCT names.
    Editor bound twice = '1 bound ghost', not 2."""
    idx = make_index(
        namespaces=[{"name": "default", "labels": {}, "annotations": {}},
                     {"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role()],
        rbs=[
            {"name": "edit", "namespace": "default",
             "subjects": [{"kind": "User", "name": "editor"}],
             "roleRef": {"kind": "ClusterRole", "name": "edit"}},
            {"name": "edit", "namespace": "demo",
             "subjects": [{"kind": "User", "name": "editor"}],
             "roleRef": {"kind": "ClusterRole", "name": "edit"}},
        ],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/").data.decode()
    # Single bound ghost: "1 bound ghost", not "2 bound ghosts"
    assert "1 bound ghost</strong>" in body
    assert "2 bound ghosts</strong>" not in body
    # editor appears exactly once in the preview (no duplication)
    assert body.count("<span class=\"mono\">editor</span>") == 1


def test_role_grants_still_show_per_binding_rows():
    """Permission-grant surfaces enumerate every binding, not principals.
    Two bindings for the same ghost user must still produce 2 grant rows."""
    idx = make_index(
        namespaces=[{"name": "default", "labels": {}, "annotations": {}},
                     {"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role()],
        rbs=[
            {"name": "edit", "namespace": "default",
             "subjects": [{"kind": "User", "name": "editor"}],
             "roleRef": {"kind": "ClusterRole", "name": "edit"}},
            {"name": "edit", "namespace": "demo",
             "subjects": [{"kind": "User", "name": "editor"}],
             "roleRef": {"kind": "ClusterRole", "name": "edit"}},
        ],
    )
    grants = engine.role_grants(idx)
    editor_grants = [g for g in grants if g["subject"].get("name") == "editor"]
    assert len(editor_grants) == 2
    assert sorted(g["binding"]["namespace"] for g in editor_grants) \
        == ["default", "demo"]


# ====================================================================== #
# Issue 2 — Ghost User/Group SCC subjects surface as resurrectable       #
# ====================================================================== #

def test_oc_adm_policy_add_scc_to_ghost_group_flags_resurrectable():
    """`oc adm policy add-scc-to-group anyuid crazy-anyuid-group` shape:
    a CRB binds ClusterRole `system:openshift:scc:anyuid` to
    Group/crazy-anyuid-group. The group doesn't exist. Must surface
    under resurrectable_implicit_scc_groups with kind=ghost-scc-subject."""
    idx = make_index(
        sccs=[_scc("anyuid", allowPrivilegedContainer=False,
                    runAsUser={"type": "RunAsAny"})],
        cluster_roles=[_scc_use_clusterrole("anyuid")],
        crbs=[{"name": "system:openshift:scc:anyuid",
               "subjects": [{"kind": "Group", "name": "crazy-anyuid-group"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:anyuid"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    matches = [r for r in rows if r.get("subject_name") == "crazy-anyuid-group"]
    assert len(matches) == 1
    r = matches[0]
    assert r["kind"] == "ghost-scc-subject"
    assert r["subject_kind"] == "Group"
    assert r["scc"] == "anyuid"
    assert r["severity"] == "high"  # runAsUser=RunAsAny → high
    assert r["baseline"] is False
    assert "anyuid" in r["explanation"]
    assert "crazy-anyuid-group" in r["explanation"]


def test_oc_adm_policy_add_scc_to_ghost_user_flags_resurrectable():
    """The User-form mirror of the Group ghost case."""
    idx = make_index(
        sccs=[_scc("privileged", allowPrivilegedContainer=True)],
        cluster_roles=[_scc_use_clusterrole("privileged")],
        crbs=[{"name": "system:openshift:scc:privileged",
               "subjects": [{"kind": "User", "name": "future-admin"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:privileged"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    matches = [r for r in rows if r.get("subject_name") == "future-admin"]
    assert len(matches) == 1
    r = matches[0]
    assert r["kind"] == "ghost-scc-subject"
    assert r["subject_kind"] == "User"
    assert r["severity"] == "critical"


def test_existing_group_does_not_surface_as_scc_ghost():
    """If the Group exists on the cluster, the SCC RBAC grant is live
    access (visible elsewhere), not a resurrectable ghost-scc-subject."""
    idx = make_index(
        groups=[{"name": "engineers", "users": ["alice"]}],
        sccs=[_scc("anyuid", allowPrivilegedContainer=False,
                    runAsUser={"type": "RunAsAny"})],
        cluster_roles=[_scc_use_clusterrole("anyuid")],
        crbs=[{"name": "system:openshift:scc:anyuid",
               "subjects": [{"kind": "Group", "name": "engineers"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:anyuid"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert all(r.get("subject_name") != "engineers" for r in rows)


def test_scc_ghost_subject_not_reported_under_limited_view():
    """is_admin=False — the subject index is incomplete, so we can't
    distinguish missing from unreadable. No false ghost-scc-subject row."""
    idx = make_index(
        sccs=[_scc("privileged", allowPrivilegedContainer=True)],
        cluster_roles=[_scc_use_clusterrole("privileged")],
        crbs=[{"name": "system:openshift:scc:privileged",
               "subjects": [{"kind": "Group", "name": "missing-team"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:privileged"}}],
    )
    idx["is_admin"] = False
    assert engine.resurrectable_implicit_scc_groups(idx) == []


# ====================================================================== #
# Ghosts must not get virtual-group reach                               #
# ====================================================================== #

def test_ghost_user_has_no_system_authenticated_reach():
    """rbac_groups_for_user returns [] for a User name not in the index.
    A ghost has no token and never authenticates, so synthesizing
    system:authenticated reach on /subject/User/<ghost> is misleading."""
    idx = make_index()  # no users
    assert engine.rbac_groups_for_user("editor", idx) == []
    # Existing user keeps virtual groups
    idx_with = make_index(users=[{"name": "alice"}])
    assert "system:authenticated" in engine.rbac_groups_for_user("alice", idx_with)


def test_ghost_sa_has_no_system_authenticated_reach():
    """Same logic for ServiceAccounts: a missing SA has no token."""
    idx = make_index(namespaces=[{"name": "demo", "labels": {},
                                    "annotations": {}}])
    # SA 'pipeline' does NOT exist
    assert engine.groups_for_serviceaccount("pipeline", "demo", idx) == []
    # SA that exists keeps virtual groups
    idx_with = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        sas=[{"name": "pipeline", "namespace": "demo",
              "labels": {}, "annotations": {}}],
    )
    groups = engine.groups_for_serviceaccount("pipeline", "demo", idx_with)
    assert "system:authenticated" in groups
    assert "system:serviceaccounts" in groups
    assert "system:serviceaccounts:demo" in groups


def test_ghost_user_effective_permissions_only_show_direct_paths():
    """An RB to nonexistent User editor + a CRB to system:authenticated
    must yield ONE path for editor (the direct one), not also the
    inherited 'via system:authenticated' path that exists for real users."""
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role(),
                       {"name": "view", "labels": {}, "annotations": {},
                        "aggregationRule": None,
                        "rules": [{"apiGroups": [""],
                                   "resources": ["pods"],
                                   "verbs": ["get"]}],
                        "creationTimestamp": "2024-01-01T00:00:00Z"}],
        crbs=[{"name": "view-all-auth",
               "subjects": [{"kind": "Group", "name": "system:authenticated"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        rbs=[{"name": "edit", "namespace": "demo",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    paths = engine.effective_permissions("User", "editor", None, idx)
    # exactly one path: the direct RB. Not the system:authenticated one.
    assert len(paths) == 1
    assert paths[0].via_group is None
    assert paths[0].role["name"] == "edit"


def test_ghost_user_namespace_reach_only_shows_direct_paths():
    """namespace_reach_for_subject should not synthesize virtual-group
    reach for a ghost — otherwise /subject/User/<ghost> renders a
    massive "Per namespace via system virtual groups" section that
    misleads the reviewer."""
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}},
                     {"name": "other", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role(),
                       {"name": "view", "labels": {}, "annotations": {},
                        "aggregationRule": None,
                        "rules": [{"apiGroups": [""],
                                   "resources": ["pods"],
                                   "verbs": ["get"]}],
                        "creationTimestamp": "2024-01-01T00:00:00Z"}],
        crbs=[{"name": "view-all-auth",
               "subjects": [{"kind": "Group", "name": "system:authenticated"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        rbs=[{"name": "edit", "namespace": "demo",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    reach = engine.namespace_reach_for_subject("User", "editor", None, idx)
    # No system: groups synthesized for the ghost
    assert "system:authenticated" not in reach["via_groups"]
    assert "system:authenticated:oauth" not in reach["via_groups"]
    # Only the direct RB path is visible — namespace 'demo' is the only key
    by_ns = reach["by_namespace"]
    assert set(by_ns.keys()) == {"demo"}


def test_subject_detail_page_for_ghost_omits_system_virtual_section(monkeypatch):
    """End-to-end: /subject/User/editor must not show the system
    virtual group reach section because editor doesn't authenticate."""
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role(),
                       {"name": "view", "labels": {}, "annotations": {},
                        "aggregationRule": None,
                        "rules": [{"apiGroups": [""],
                                   "resources": ["pods"],
                                   "verbs": ["get"]}],
                        "creationTimestamp": "2024-01-01T00:00:00Z"}],
        crbs=[{"name": "view-all-auth",
               "subjects": [{"kind": "Group", "name": "system:authenticated"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        rbs=[{"name": "edit", "namespace": "demo",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/subject/User/editor").get_data(as_text=True)
    # Ghost badge present
    assert ">ghost</span>" in body or ">Ghost</span>" in body
    # The 'view' role from the system:authenticated CRB must NOT appear
    # — editor can't get there.
    assert "ClusterRole/view" not in body
    assert "/clusterrole/view" not in body
    # The direct edit binding is visible
    assert "RoleBinding/edit" in body


def test_real_user_still_gets_virtual_group_reach():
    """Don't over-fix: a real (existing) User still inherits
    system:authenticated / system:authenticated:oauth reach."""
    idx = make_index(
        users=[{"name": "alice"}],
        cluster_roles=[{"name": "view", "labels": {}, "annotations": {},
                         "aggregationRule": None,
                         "rules": [{"apiGroups": [""],
                                    "resources": ["pods"],
                                    "verbs": ["get"]}],
                         "creationTimestamp": "2024-01-01T00:00:00Z"}],
        crbs=[{"name": "view-all-auth",
               "subjects": [{"kind": "Group", "name": "system:authenticated"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    paths = engine.effective_permissions("User", "alice", None, idx)
    via = [p.via_group for p in paths]
    assert "system:authenticated" in via
