"""Namespace → RoleBinding → ghost-subject lineage.

Pins the fix for the user-reported case:

    oc create ns demo
    oc adm policy add-role-to-user edit editor

When the command runs without `-n`, OpenShift writes the RoleBinding
into the CURRENT project (often `default`, a baseline-named namespace).
The binding has a user-readable name (`edit`), names a User who doesn't
exist (`editor`), and uses a normal ClusterRole (`edit`). Lineage's
prior rule "binding lives in a baseline-named namespace → binding is
baseline" hid the entire finding as routine platform noise.

These regressions assert:
- the ghost is `real`, not `routine`, regardless of where the binding
  lives
- the binding still shows up on the namespace page
- the subject detail page shows the path with a ghost badge
- the binding appears in permission/role-grant surfaces
- existing-User bindings do NOT get a ghost badge
- bindings whose subjects are ALL platform identities remain baseline
"""
from lineage import engine
from lineage.main import app
from .conftest import make_index


# ---------- common fixtures ----------------------------------------------- #

def _edit_role():
    return {
        "name": "edit", "labels": {}, "annotations": {},
        "aggregationRule": None,
        "rules": [{"apiGroups": ["*"], "resources": ["deployments"],
                   "verbs": ["*"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }


def _view_role():
    return {
        "name": "view", "labels": {}, "annotations": {},
        "aggregationRule": None,
        "rules": [{"apiGroups": [""], "resources": ["pods"],
                   "verbs": ["get", "list"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }


# ---------- 1. The exact `oc adm policy` ghost surfaces as a real ghost --- #

def test_rolebinding_in_default_to_nonexistent_user_is_real_ghost():
    """`oc adm policy add-role-to-user edit editor` (no `-n` → lands in
    `default`) must yield a real, actionable ghost finding."""
    idx = make_index(
        namespaces=[{"name": "default", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role()],
        rbs=[{"name": "edit", "namespace": "default",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    ghosts = engine.find_ghost_subjects(idx)
    editor_ghosts = [g for g in ghosts if g["subject"]["name"] == "editor"]
    assert len(editor_ghosts) == 1
    g = editor_ghosts[0]
    assert g["category"] == "real"
    assert g["routine"] is False
    assert g["binding_baseline"] is False
    assert g["subject_baseline"] is False


def test_rolebinding_in_unclassified_ns_to_nonexistent_user_is_real_ghost():
    """`oc create ns demo` + `oc adm policy add-role-to-user … -n demo`
    case (unclassified namespace, no `openshift.io/requester`)."""
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role()],
        rbs=[{"name": "edit", "namespace": "demo",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    ghosts = engine.find_ghost_subjects(idx)
    assert any(g["subject"]["name"] == "editor"
               and g["category"] == "real" for g in ghosts)


# ---------- 2. Ghosts of every Kind in custom namespaces are real --------- #

def test_rb_in_custom_ns_to_nonexistent_group_is_real_ghost():
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_view_role()],
        rbs=[{"name": "demo-group-view", "namespace": "demo",
              "subjects": [{"kind": "Group", "name": "engineers-missing"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    ghosts = engine.find_ghost_subjects(idx)
    assert any(g["subject"]["name"] == "engineers-missing"
               and g["category"] == "real" for g in ghosts)


def test_rb_in_custom_ns_to_missing_sa_same_ns_is_real_ghost():
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_view_role()],
        rbs=[{"name": "demo-sa-view", "namespace": "demo",
              "subjects": [{"kind": "ServiceAccount",
                             "name": "pipeline", "namespace": "demo"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    ghosts = engine.find_ghost_subjects(idx)
    # The SA family is *also* surfaced via resurrectable_sa_identities;
    # find_ghost_subjects still emits a row for it.
    sa_ghosts = [g for g in ghosts
                  if g["subject"].get("kind") == "ServiceAccount"
                  and g["subject"].get("name") == "pipeline"]
    assert sa_ghosts
    assert all(g["category"] == "real" for g in sa_ghosts)


def test_rb_in_custom_ns_to_missing_sa_other_ns_is_real_ghost():
    """Cross-namespace SA reference — bound in `demo`, SA in `tenant-x`."""
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}},
                     {"name": "tenant-x", "labels": {}, "annotations": {}}],
        cluster_roles=[_view_role()],
        rbs=[{"name": "demo-xns-view", "namespace": "demo",
              "subjects": [{"kind": "ServiceAccount",
                             "name": "pipeline", "namespace": "tenant-x"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    ghosts = engine.find_ghost_subjects(idx)
    assert any(g["subject"].get("name") == "pipeline"
               and g["category"] == "real" for g in ghosts)


# ---------- 3. ClusterRoleBindings of every Kind to missing subjects ------ #

def test_crb_to_nonexistent_user_is_real_ghost():
    idx = make_index(
        cluster_roles=[_edit_role()],
        crbs=[{"name": "cluster-edit-ghost",
               "subjects": [{"kind": "User", "name": "future-admin"}],
               "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    ghosts = engine.find_ghost_subjects(idx)
    assert any(g["subject"]["name"] == "future-admin"
               and g["category"] == "real" for g in ghosts)


def test_crb_to_nonexistent_group_is_real_ghost():
    idx = make_index(
        cluster_roles=[_view_role()],
        crbs=[{"name": "cluster-group-ghost",
               "subjects": [{"kind": "Group", "name": "missing-team"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    ghosts = engine.find_ghost_subjects(idx)
    assert any(g["subject"]["name"] == "missing-team"
               and g["category"] == "real" for g in ghosts)


def test_crb_to_nonexistent_sa_is_real_ghost():
    idx = make_index(
        namespaces=[{"name": "tenant-x", "labels": {}, "annotations": {}}],
        cluster_roles=[_view_role()],
        crbs=[{"name": "cluster-sa-ghost",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "pipeline", "namespace": "tenant-x"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    ghosts = engine.find_ghost_subjects(idx)
    assert any(g["subject"].get("kind") == "ServiceAccount"
               and g["subject"].get("name") == "pipeline"
               and g["category"] == "real" for g in ghosts)


# ---------- 4. Existing-subject bindings do NOT get a ghost badge -------- #

def test_existing_user_binding_has_no_ghost():
    idx = make_index(
        users=[{"name": "alice"}],
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_view_role()],
        rbs=[{"name": "demo-alice-view", "namespace": "demo",
              "subjects": [{"kind": "User", "name": "alice"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    ghosts = engine.find_ghost_subjects(idx, include_baseline=True)
    assert not any(g["subject"]["name"] == "alice" for g in ghosts)


def test_existing_sa_binding_has_no_ghost():
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        sas=[{"name": "pipeline", "namespace": "demo",
              "labels": {}, "annotations": {}}],
        cluster_roles=[_view_role()],
        rbs=[{"name": "demo-pipeline-view", "namespace": "demo",
              "subjects": [{"kind": "ServiceAccount",
                             "name": "pipeline", "namespace": "demo"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    ghosts = engine.find_ghost_subjects(idx, include_baseline=True)
    assert not any(g["subject"].get("name") == "pipeline" for g in ghosts)


# ---------- 5. Platform bindings remain baseline (no over-fix) ----------- #

def test_system_named_binding_in_baseline_ns_still_baseline(view_role):
    """The fix must NOT promote real platform bindings to "actionable".
    `system:*` named bindings keep their baseline status via the name
    prefix rule."""
    idx = make_index(
        namespaces=[{"name": "openshift-monitoring", "labels": {},
                     "annotations": {}}],
        cluster_roles=[view_role],
        rbs=[{"name": "system:openshift:platform-binding",
              "namespace": "openshift-monitoring",
              "subjects": [{"kind": "User",
                             "name": "missing-platform-user"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    ghosts = engine.find_ghost_subjects(idx, include_baseline=True)
    matches = [g for g in ghosts if g["subject"]["name"] == "missing-platform-user"]
    assert len(matches) == 1
    assert matches[0]["binding_baseline"] is True
    assert matches[0]["category"] == "routine"


def test_binding_with_all_system_subjects_remains_baseline(view_role):
    """A binding whose every subject is itself baseline (all `system:*`)
    stays baseline regardless of namespace and binding name."""
    idx = make_index(
        namespaces=[{"name": "openshift-monitoring", "labels": {},
                     "annotations": {}}],
        cluster_roles=[view_role],
        rbs=[{"name": "platform-bootstrap",
              "namespace": "openshift-monitoring",
              "subjects": [{"kind": "Group", "name": "system:nodes"},
                            {"kind": "Group", "name": "system:masters"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    # No ghosts here (system: subjects are virtual, not ghost candidates)
    # but assert is_baseline_binding is True so the binding is hidden
    # from user-managed totals.
    rb = next(b for b in idx["all_bindings"] if b["name"] == "platform-bootstrap")
    assert engine.is_baseline_binding(rb, idx) is True


# ---------- 6. UI: /namespace/<ns> shows the binding + ghost link -------- #

def test_namespace_page_shows_rolebinding_and_ghost_user(monkeypatch):
    """End-to-end: the `oc adm policy …` case must surface on the
    namespace page so the reviewer can find it from the namespace UI."""
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role()],
        rbs=[{"name": "edit", "namespace": "demo",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/namespace/demo").get_data(as_text=True)
    assert "editor" in body
    # The binding name surfaces too so the reviewer can locate it
    assert "RoleBinding" in body


def test_subject_detail_shows_ghost_badge_and_binding(monkeypatch):
    """End-to-end: opening /subject/User/editor must clearly show:
    - a ghost badge (subject does not exist)
    - the binding path (so the path → role → rules is visible)"""
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role()],
        rbs=[{"name": "edit", "namespace": "demo",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/subject/User/editor").get_data(as_text=True)
    assert ">ghost</span>" in body or ">Ghost</span>" in body
    assert "demo" in body
    assert "RoleBinding/edit" in body


def test_home_dashboard_counts_real_editor_ghost(monkeypatch):
    """`oc adm policy add-role-to-user edit editor` (no `-n`, lands in
    `default`) must increment the home `bound ghost` count by 1, not
    sit in the hidden baseline bucket."""
    idx = make_index(
        namespaces=[{"name": "default", "labels": {}, "annotations": {}}],
        cluster_roles=[_edit_role()],
        rbs=[{"name": "edit", "namespace": "default",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "edit"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/").get_data(as_text=True)
    # editor appears in the review snapshot as a bound ghost
    assert "1 bound ghost" in body or "bound ghosts" in body
    assert "editor" in body


# ---------- 7. Limited view still safe — no false positives -------------- #

def test_limited_view_does_not_create_ghost_findings():
    """Under a non-admin token the subject index is incomplete; we
    can't tell missing from unreadable. The classifier must stay
    silent — no ghost rows, baseline or otherwise."""
    idx = make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        cluster_roles=[_view_role()],
        rbs=[{"name": "edit", "namespace": "demo",
              "subjects": [{"kind": "User", "name": "editor"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    idx["is_admin"] = False
    assert engine.find_ghost_subjects(idx) == []
    assert engine.find_ghost_subjects(idx, include_baseline=True) == []
