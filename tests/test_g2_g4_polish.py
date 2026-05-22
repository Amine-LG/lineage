"""G2 (auto-created SA context) and G4 (self-provisioner posture) plus
the /sccs filter/sort polish."""

from lineage import engine
from lineage.main import app
from .conftest import make_index


def _admin_cr():
    return {"name": "admin", "labels": {}, "annotations": {},
            "aggregationRule": None,
            "rules": [{"apiGroups": [""], "resources": ["*"],
                       "verbs": ["*"]}]}


# ---------- G2: auto-created SA flag + badge ---------- #

def test_resurrectable_sa_named_default_gets_auto_created_flag():
    """A resurrectable SA principal naming the default project SA must
    carry the `auto_created_sa` flag so the UI can highlight that the
    SA reappears the moment `oc new-project` runs — no `oc create sa`
    step needed."""
    idx = make_index(
        cluster_roles=[_admin_cr()],
        crbs=[{"name": "ghost-default-admin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "default",
                              "namespace": "retired-project"}],
               "roleRef": {"kind": "ClusterRole", "name": "admin"}}],
    )
    rows = engine.resurrectable_sa_identities(idx)
    row = next(r for r in rows if r["name"] == "default")
    assert row["auto_created_sa"] is True


def test_resurrectable_sa_named_builder_gets_auto_created_flag():
    idx = make_index(
        cluster_roles=[_admin_cr()],
        crbs=[{"name": "ghost-builder-admin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "builder",
                              "namespace": "retired-project"}],
               "roleRef": {"kind": "ClusterRole", "name": "admin"}}],
    )
    rows = engine.resurrectable_sa_identities(idx)
    row = next(r for r in rows if r["name"] == "builder")
    assert row["auto_created_sa"] is True


def test_resurrectable_sa_named_deployer_gets_auto_created_flag():
    idx = make_index(
        cluster_roles=[_admin_cr()],
        crbs=[{"name": "ghost-deployer-admin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "deployer",
                              "namespace": "retired-project"}],
               "roleRef": {"kind": "ClusterRole", "name": "admin"}}],
    )
    rows = engine.resurrectable_sa_identities(idx)
    row = next(r for r in rows if r["name"] == "deployer")
    assert row["auto_created_sa"] is True


def test_resurrectable_sa_with_custom_name_does_not_get_auto_flag():
    """Sanity: only the three documented OpenShift defaults get the flag."""
    idx = make_index(
        cluster_roles=[_admin_cr()],
        crbs=[{"name": "ghost-custom-admin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "custom-runner",
                              "namespace": "retired-project"}],
               "roleRef": {"kind": "ClusterRole", "name": "admin"}}],
    )
    rows = engine.resurrectable_sa_identities(idx)
    row = next(r for r in rows if r["name"] == "custom-runner")
    assert row["auto_created_sa"] is False


def test_identity_audit_page_renders_auto_created_sa_badge(monkeypatch):
    """End-to-end: the badge text appears in the rendered resurrectable
    table for a default-SA finding."""
    idx = make_index(
        cluster_roles=[_admin_cr()],
        crbs=[{"name": "ghost-default-admin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "default",
                              "namespace": "retired-project"}],
               "roleRef": {"kind": "ClusterRole", "name": "admin"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/identity-audit?severity=all").data.decode()
    assert "auto-created project SA" in body


# ---------- G2: SCC implicit-group auto-SA context ---------- #

def _impl_scc():
    return {"name": "legacy-pipeline-root", "users": [],
            "groups": ["system:serviceaccounts:retired-pipelines"],
            "allowPrivilegedContainer": False,
            "allowHostNetwork": False, "allowHostPID": False,
            "allowHostIPC": False,
            "allowPrivilegeEscalation": True,
            "runAsUser": {"type": "RunAsAny"},
            "creationTimestamp": "2025-06-01T00:00:00Z",
            "priority": 100}


def test_implicit_scc_group_carries_auto_created_sa_flag():
    idx = make_index(sccs=[_impl_scc()])
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert rows[0]["auto_created_sa"] is True


def test_implicit_scc_group_explanation_mentions_default_builder_deployer():
    idx = make_index(sccs=[_impl_scc()])
    rows = engine.resurrectable_implicit_scc_groups(idx)
    expl = rows[0]["explanation"]
    assert "default" in expl
    assert "builder" in expl
    assert "deployer" in expl


# ---------- G4: self-provisioner posture ---------- #

def _self_prov_crb(subject_group):
    return {"name": "self-provisioners",
            "subjects": [{"kind": "Group", "name": subject_group}],
            "roleRef": {"kind": "ClusterRole", "name": "self-provisioner"}}


def test_self_provisioner_posture_enabled_for_oauth_group():
    """The default OpenShift binding to `system:authenticated:oauth`
    must be recognised as enabled."""
    idx = make_index(crbs=[_self_prov_crb("system:authenticated:oauth")])
    p = engine.self_provisioner_posture(idx)
    assert p["state"] == "enabled"
    assert p["subject"] == "system:authenticated:oauth"
    assert p["binding"] == "self-provisioners"
    assert "non-admin" in p["reason"]


def test_self_provisioner_posture_enabled_for_authenticated_group():
    """Some older clusters bind to `system:authenticated` instead;
    same posture."""
    idx = make_index(crbs=[_self_prov_crb("system:authenticated")])
    p = engine.self_provisioner_posture(idx)
    assert p["state"] == "enabled"
    assert p["subject"] == "system:authenticated"


def test_self_provisioner_posture_disabled_when_no_matching_binding():
    """No CRB to self-provisioner for the broad groups → disabled."""
    idx = make_index()
    p = engine.self_provisioner_posture(idx)
    assert p["state"] == "disabled"
    assert p["binding"] is None


def test_self_provisioner_posture_unknown_when_crbs_forbidden():
    """When the session can't list CRBs, we cannot tell either way —
    surface 'unknown', do not guess."""
    idx = make_index()
    idx["fetch_error_kinds"] = {"crb"}
    p = engine.self_provisioner_posture(idx)
    assert p["state"] == "unknown"
    assert "ClusterRoleBindings are not readable" in p["reason"]


def test_self_provisioner_posture_ignores_non_default_binding():
    """A CRB to self-provisioner that names a specific User (or a
    narrow group) does NOT count as the cluster-wide enabled state."""
    idx = make_index(
        crbs=[{"name": "specific-admin-self-prov",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "self-provisioner"}}],
    )
    p = engine.self_provisioner_posture(idx)
    assert p["state"] == "disabled"


def test_identity_audit_renders_self_provisioner_banner(monkeypatch):
    """The /identity-audit page renders the posture pill in orange
    (posture-enabled) when self-provisioner is bound to a broad group."""
    idx = make_index(crbs=[_self_prov_crb("system:authenticated:oauth")])
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/identity-audit").data.decode()
    assert 'id="self-provisioner-posture"' in body
    assert "posture-enabled" in body
    assert "<strong>Self-provisioner:</strong>" in body
    assert ">enabled</span>" in body
    assert "non-admin" in body


def test_identity_audit_renders_disabled_posture(monkeypatch):
    """Disabled = green pill (posture-disabled)."""
    idx = make_index()
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/identity-audit").data.decode()
    assert "posture-disabled" in body
    assert ">disabled</span>" in body


# ---------- /sccs filter position + ISO sort ---------- #

def _scc(name, ts, **kw):
    return {"name": name, "users": [], "groups": [],
            "allowPrivilegedContainer": kw.pop("priv", False),
            "allowHostNetwork": False, "allowHostPID": False,
            "allowHostIPC": False,
            "allowPrivilegeEscalation": True,
            "runAsUser": {"type": "MustRunAs"},
            "creationTimestamp": ts,
            "priority": None}


def test_sccs_filter_input_lives_inside_a_toolbar(monkeypatch):
    """Consistency with the other pages: the filter input is right-
    aligned by living inside <div class="toolbar">. CSS handles the
    actual right-alignment via `input.search { margin-left: auto }`."""
    idx = make_index(sccs=[_scc("a", "2025-01-01T00:00:00Z")])
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/sccs").data.decode()
    # Toolbar wrapper around the filter input.
    import re
    m = re.search(
        r'<div class="toolbar">\s*<input type="search"[^>]*data-filter-target="#sccs-table"',
        body)
    assert m is not None, "filter input must be inside .toolbar"


def test_sccs_created_column_uses_real_timestamp_for_sort(monkeypatch):
    """The `Created` column shows humanage text but data-sort holds the
    real ISO timestamp. Two SCCs whose age display happens to read the
    same string still sort by exact creationTimestamp."""
    idx = make_index(sccs=[
        _scc("alpha", "2025-06-01T00:00:00Z"),
        _scc("beta",  "2025-06-02T00:00:00Z"),
    ])
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/sccs").data.decode()
    # data-sort attribute holds the ISO, not the rendered "x mo" text.
    assert 'data-sort="2025-06-01T00:00:00Z"' in body
    assert 'data-sort="2025-06-02T00:00:00Z"' in body
    # Server-side default order: newest first.
    assert body.index(">beta</a>") < body.index(">alpha</a>")


def test_sccs_sort_js_treats_iso_timestamps_as_strings():
    """The sortable JS must short-circuit parseFloat for ISO timestamps,
    otherwise same-year SCCs can tie incorrectly."""
    import pathlib
    js = pathlib.Path("lineage/static/lineage.js").read_text()
    assert r'/^\d{4}-\d{2}-\d{2}/' in js


def test_sccs_no_expand_details_wrapper(monkeypatch):
    """The /sccs main table must render inline — no <details> wrapper."""
    idx = make_index(sccs=[
        _scc(f"scc-{i:02d}", f"2025-{(i%12)+1:02d}-01T00:00:00Z")
        for i in range(15)
    ])
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/sccs").data.decode()
    assert "expand-details" not in body
    assert "Click to expand" not in body


def test_sccs_missing_timestamp_does_not_crash(monkeypatch):
    """A None creationTimestamp must not crash the page or the sort."""
    idx = make_index(sccs=[
        _scc("dated", "2025-01-01T00:00:00Z"),
        _scc("no-ts", None),
    ])
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/sccs").data.decode()
    assert ">dated</a>" in body
    assert ">no-ts</a>" in body
