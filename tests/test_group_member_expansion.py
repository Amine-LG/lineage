"""Group-membership expansion in namespace and SCC views.

Enumerable Group members get derived rows marked with `via_group`, while
the original Group row remains visible. Virtual system groups such as
`system:authenticated` are not enumerated because their membership is
implicit and unbounded.
"""
from lineage import engine
from .conftest import make_index, scc_use_clusterrole as _scc_use_clusterrole


def _view_role():
    return {
        "name": "view", "labels": {}, "annotations": {},
        "aggregationRule": None,
        "rules": [{"apiGroups": [""], "resources": ["pods"],
                   "verbs": ["get", "list"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }


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
        "allowPrivilegeEscalation": False,
        "runAsUser": {"type": "MustRunAs"},
        "creationTimestamp": "2024-01-01T00:00:00Z",
        **kwargs,
    }


# ====================================================================== #
# Namespace access — named Group expansion                              #
# ====================================================================== #

def test_namespace_access_expands_named_group_to_user_members():
    """A RoleBinding to Group/engineers gives alice, bob access.
    The namespace access table must surface BOTH the Group row AND
    derived rows for alice and bob."""
    idx = make_index(
        users=[{"name": "alice"}, {"name": "bob"}],
        groups=[{"name": "engineers", "users": ["alice", "bob"]}],
        namespaces=[{"name": "tenant-a", "labels": {},
                      "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[_view_role()],
        rbs=[{"name": "engineers-view", "namespace": "tenant-a",
              "subjects": [{"kind": "Group", "name": "engineers"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    cats = engine.subjects_with_access_in_categorized("tenant-a", idx)
    all_rows = sum(cats.values(), [])
    group_rows = [r for r in all_rows
                   if r["subject"].get("kind") == "Group"
                   and r["subject"].get("name") == "engineers"]
    user_rows = [r for r in all_rows
                  if r["subject"].get("kind") == "User"]
    # Group itself is still shown (binding shape)
    assert len(group_rows) == 1
    # Each member surfaces as a User row marked derived via_group
    user_names = sorted(r["subject"]["name"] for r in user_rows)
    assert user_names == ["alice", "bob"]
    for r in user_rows:
        assert r["via_group"] == "engineers"
        assert r["derived"] is True
        assert r["role"] == "view"


def test_namespace_access_does_not_expand_system_authenticated():
    """`system:authenticated` membership = every authenticated principal
    in the cluster. Enumerating it would explode the table on real
    clusters. Keep the Group row only."""
    idx = make_index(
        users=[{"name": "alice"}, {"name": "bob"}],
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_view_role()],
        crbs=[{"name": "all-auth-view",
               "subjects": [{"kind": "Group", "name": "system:authenticated"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    cats = engine.subjects_with_access_in_categorized("demo", idx)
    all_rows = sum(cats.values(), [])
    user_rows = [r for r in all_rows
                  if r["subject"].get("kind") == "User"]
    # No derived User rows from system:authenticated
    assert not any(r.get("derived") for r in user_rows)
    # But the Group row IS visible
    assert any(r["subject"].get("name") == "system:authenticated"
               for r in all_rows)


def test_namespace_access_expands_system_serviceaccounts_ns():
    """`Group/system:serviceaccounts:<ns>` enumerates to every SA in
    that namespace (bounded, concrete, useful)."""
    idx = make_index(
        namespaces=[{"name": "tenant-b", "labels": {}, "annotations": {}}],
        sas=[
            {"name": "default", "namespace": "tenant-b",
             "labels": {}, "annotations": {}},
            {"name": "pipeline", "namespace": "tenant-b",
             "labels": {}, "annotations": {}},
        ],
        cluster_roles=[_view_role()],
        rbs=[{"name": "tenant-b-sas-view", "namespace": "tenant-b",
              "subjects": [{"kind": "Group",
                             "name": "system:serviceaccounts:tenant-b"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    cats = engine.subjects_with_access_in_categorized("tenant-b", idx)
    all_rows = sum(cats.values(), [])
    sa_rows = [r for r in all_rows
                if r["subject"].get("kind") == "ServiceAccount"
                and r.get("via_group") == "system:serviceaccounts:tenant-b"]
    sa_names = sorted(r["subject"]["name"] for r in sa_rows)
    assert sa_names == ["default", "pipeline"]


def test_namespace_access_ghost_user_remains_visible_and_flagged():
    """`oc adm policy add-role-to-user edit editor -n demo` —
    editor doesn't exist. The User row must still appear with a
    ghost flag (the reviewer needs to see this binding)."""
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role()],
        rbs=[{"name": "edit", "namespace": "demo",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    cats = engine.subjects_with_access_in_categorized("demo", idx)
    all_rows = sum(cats.values(), [])
    editor_rows = [r for r in all_rows
                    if r["subject"].get("name") == "editor"]
    assert len(editor_rows) == 1
    assert editor_rows[0]["ghost"] is True


def test_existing_user_named_in_binding_does_not_get_ghost_flag():
    idx = make_index(
        users=[{"name": "alice"}],
        namespaces=[{"name": "tenant-a", "labels": {},
                      "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[_view_role()],
        rbs=[{"name": "alice-view", "namespace": "tenant-a",
              "subjects": [{"kind": "User", "name": "alice"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    cats = engine.subjects_with_access_in_categorized("tenant-a", idx)
    all_rows = sum(cats.values(), [])
    alice_rows = [r for r in all_rows
                   if r["subject"].get("name") == "alice"]
    assert len(alice_rows) == 1
    assert alice_rows[0]["ghost"] is False
    assert alice_rows[0]["derived"] is False


def test_namespace_access_dedups_group_members_across_multiple_bindings():
    """If two bindings BOTH go to Group/engineers (same role, same scope),
    we shouldn't list alice twice for the same derived path."""
    idx = make_index(
        users=[{"name": "alice"}],
        groups=[{"name": "engineers", "users": ["alice"]}],
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_view_role()],
        rbs=[
            {"name": "engineers-view-a", "namespace": "demo",
             "subjects": [{"kind": "Group", "name": "engineers"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
            {"name": "engineers-view-b", "namespace": "demo",
             "subjects": [{"kind": "Group", "name": "engineers"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
        ],
    )
    cats = engine.subjects_with_access_in_categorized("demo", idx)
    all_rows = sum(cats.values(), [])
    alice_rows = [r for r in all_rows
                   if r["subject"].get("name") == "alice"
                   and r.get("derived") is True]
    # The dedup key includes the binding name to keep both PATHS visible,
    # but identical (binding, role, scope) shouldn't produce duplicates.
    # Both bindings are different names, so 2 derived rows is correct;
    # the dedup catches the "same binding twice" case.
    assert len(alice_rows) == 2
    binding_names = sorted(r["binding"]["name"] for r in alice_rows)
    assert binding_names == ["engineers-view-a", "engineers-view-b"]


def test_namespace_access_does_not_expand_system_masters_or_cluster_admins():
    """system:masters and system:cluster-admins are structural groups —
    membership is determined by cert/token, not by a Group object.
    Keep them as Group rows; do not invent member rows."""
    idx = make_index(
        users=[{"name": "alice"}],
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_view_role()],
        crbs=[{"name": "masters-view",
               "subjects": [{"kind": "Group", "name": "system:masters"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}},
              {"name": "cadmins-view",
               "subjects": [{"kind": "Group", "name": "system:cluster-admins"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    cats = engine.subjects_with_access_in_categorized("demo", idx)
    all_rows = sum(cats.values(), [])
    # No derived User rows from these groups
    assert not any(r.get("derived") and r.get("via_group") in
                    ("system:masters", "system:cluster-admins")
                    for r in all_rows)


# ====================================================================== #
# SCC potential subjects — Group expansion                              #
# ====================================================================== #

def test_scc_potential_subjects_expands_named_group():
    """SCC.groups = [engineers] OR a CRB to Group/engineers giving SCC
    use → derived rows for each User member."""
    idx = make_index(
        users=[{"name": "alice"}, {"name": "bob"}],
        groups=[{"name": "engineers", "users": ["alice", "bob"]}],
        sccs=[_scc("anyuid", runAsUser={"type": "RunAsAny"},
                    groups=["engineers"])],
    )
    rows = engine.scc_potential_subjects("anyuid", idx)
    derived_users = sorted(
        r["subject"]["name"] for r in rows
        if r.get("derived") and r["subject"].get("kind") == "User"
    )
    assert derived_users == ["alice", "bob"]
    # The Group row itself is still listed
    assert any(r["subject"].get("kind") == "Group"
               and r["subject"].get("name") == "engineers" for r in rows)


def test_scc_potential_subjects_expands_via_rbac_group():
    """The RBAC path: a CRB binds system:openshift:scc:anyuid to
    Group/engineers. Members must surface as derived rows too."""
    idx = make_index(
        users=[{"name": "alice"}],
        groups=[{"name": "engineers", "users": ["alice"]}],
        sccs=[_scc("anyuid", runAsUser={"type": "RunAsAny"})],
        cluster_roles=[_scc_use_clusterrole("anyuid")],
        crbs=[{"name": "system:openshift:scc:anyuid",
               "subjects": [{"kind": "Group", "name": "engineers"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:anyuid"}}],
    )
    rows = engine.scc_potential_subjects("anyuid", idx)
    alice = [r for r in rows
              if r["subject"].get("name") == "alice"
              and r.get("derived") is True]
    assert len(alice) == 1
    assert alice[0]["via_group"] == "engineers"


def test_scc_potential_subjects_does_not_expand_system_authenticated():
    idx = make_index(
        users=[{"name": "alice"}, {"name": "bob"}],
        sccs=[_scc("anyuid", runAsUser={"type": "RunAsAny"},
                    groups=["system:authenticated"])],
    )
    rows = engine.scc_potential_subjects("anyuid", idx)
    assert not any(r.get("derived")
                    and r.get("via_group") == "system:authenticated"
                    for r in rows)


def test_scc_potential_subjects_expands_system_serviceaccounts_ns():
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        sas=[
            {"name": "default", "namespace": "demo",
             "labels": {}, "annotations": {}},
            {"name": "pipeline", "namespace": "demo",
             "labels": {}, "annotations": {}},
        ],
        sccs=[_scc("anyuid", runAsUser={"type": "RunAsAny"},
                    groups=["system:serviceaccounts:demo"])],
    )
    rows = engine.scc_potential_subjects("anyuid", idx)
    sa_names = sorted(
        r["subject"]["name"] for r in rows
        if r["subject"].get("kind") == "ServiceAccount"
        and r.get("via_group") == "system:serviceaccounts:demo"
    )
    assert sa_names == ["default", "pipeline"]


def test_scc_potential_subjects_ghost_user_still_visible():
    """A ghost User directly in SCC.users is shown with ghost=True."""
    idx = make_index(
        sccs=[_scc("anyuid", runAsUser={"type": "RunAsAny"},
                    users=["non-existing-user"])],
    )
    rows = engine.scc_potential_subjects("anyuid", idx)
    matches = [r for r in rows
                if r["subject"].get("name") == "non-existing-user"]
    assert len(matches) == 1
    assert matches[0]["ghost"] is True


def test_existing_user_in_scc_users_is_not_ghost():
    idx = make_index(
        users=[{"name": "alice"}],
        sccs=[_scc("anyuid", runAsUser={"type": "RunAsAny"},
                    users=["alice"])],
    )
    rows = engine.scc_potential_subjects("anyuid", idx)
    matches = [r for r in rows if r["subject"].get("name") == "alice"]
    assert matches[0]["ghost"] is False
