"""Regressions for Path D — RBAC grants on a non-existent SCC.

OpenShift's `oc adm policy add-scc-to-{user,group}` accepts any name
for the SCC and writes a `system:openshift:scc:<name>` ClusterRole +
ClusterRoleBinding for it, regardless of whether the SCC actually
exists. The grant is dormant — but the moment an admin creates an SCC
with that exact name, every bound subject gains use of it instantly.

These tests pin:
- the dormant grant is flagged with kind=ghost-scc-target
- severity stays LOW while the SCC is absent (we cannot compute
  posture for a nonexistent SCC; the existing Path A/B/C handle
  posture-based severity once the SCC appears)
- the row tells the reviewer both the missing SCC and the (possibly
  missing) subject
- live SCC grants do NOT surface here
- limited view (non-admin) suppresses everything
"""
from lineage import engine
from lineage.main import app
from .conftest import make_index, scc_use_clusterrole as _scc_use_clusterrole


def _scc(name, **kwargs):
    return {
        "name": name,
        "users": kwargs.pop("users", []),
        "groups": kwargs.pop("groups", []),
        "allowPrivilegedContainer": kwargs.pop("allowPrivilegedContainer", False),
        "allowHostNetwork": False, "allowHostPID": False, "allowHostIPC": False,
        "allowPrivilegeEscalation": kwargs.pop("allowPrivilegeEscalation", False),
        "runAsUser": kwargs.pop("runAsUser", {"type": "MustRunAs"}),
        "creationTimestamp": "2024-01-01T00:00:00Z",
        **kwargs,
    }


# ---------- 1. ghost SCC + existing User ------------------------------- #

def test_oc_adm_add_scc_to_user_for_missing_scc_existing_user_flags_low():
    """`oc adm policy add-scc-to-user non-existing-scc alice`
    (alice is real, SCC does not exist) → ghost-scc-target, low."""
    idx = make_index(
        users=[{"name": "alice"}],
        sccs=[_scc("restricted-v2")],  # the missing SCC is NOT here
        cluster_roles=[_scc_use_clusterrole("non-existing-scc")],
        crbs=[{"name": "system:openshift:scc:non-existing-scc",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:non-existing-scc"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    matches = [r for r in rows
               if r.get("kind") == "ghost-scc-target"
               and r.get("scc") == "non-existing-scc"]
    assert len(matches) == 1
    r = matches[0]
    assert r["scc_present"] is False
    assert r["severity"] == "low"
    assert r["subject_kind"] == "User"
    assert r["subject_name"] == "alice"
    assert r["subject_present"] is True
    assert r["baseline"] is False
    assert "non-existing-scc" in r["explanation"]
    assert "reactivates this grant instantly" in r["explanation"]
    # And there's NO ghost-scc-subject row for alice (she exists)
    assert not any(r.get("kind") == "ghost-scc-subject"
                   and r.get("subject_name") == "alice" for r in rows)


# ---------- 2. ghost SCC + ghost User ---------------------------------- #

def test_missing_scc_and_missing_user_both_noted():
    """`oc adm policy add-scc-to-user non-existing-scc non-existing-scc-user`
    — both the SCC AND the user are absent. One ghost-scc-target row
    that calls out both gaps in the explanation."""
    idx = make_index(
        cluster_roles=[_scc_use_clusterrole("non-existing-scc")],
        crbs=[{"name": "system:openshift:scc:non-existing-scc",
               "subjects": [{"kind": "User",
                              "name": "non-existing-scc-user"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:non-existing-scc"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    matches = [r for r in rows if r.get("kind") == "ghost-scc-target"]
    assert len(matches) == 1
    r = matches[0]
    assert r["scc"] == "non-existing-scc"
    assert r["subject_present"] is False
    assert r["severity"] == "low"
    assert "does not currently exist either" in r["explanation"]


# ---------- 3. ghost SCC + ghost Group --------------------------------- #

def test_missing_scc_and_missing_group_both_noted():
    """`oc adm policy add-scc-to-group NO-SCC-GROUP None-existing-SCC-Group`
    — both the SCC AND the Group are absent. Pin the exact user-reported
    shape."""
    idx = make_index(
        cluster_roles=[_scc_use_clusterrole("NO-SCC-GROUP")],
        crbs=[{"name": "system:openshift:scc:NO-SCC-GROUP",
               "subjects": [{"kind": "Group",
                              "name": "None-existing-SCC-Group"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:NO-SCC-GROUP"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    matches = [r for r in rows if r.get("kind") == "ghost-scc-target"]
    assert len(matches) == 1
    r = matches[0]
    assert r["scc"] == "NO-SCC-GROUP"
    assert r["subject_kind"] == "Group"
    assert r["subject_name"] == "None-existing-SCC-Group"
    assert r["subject_present"] is False
    assert r["severity"] == "low"


# ---------- 4. ghost SCC + system:serviceaccounts:<missing-ns> group --- #

def test_missing_scc_with_missing_ns_sa_group_emits_ghost_scc_target():
    """Edge case: oc adm policy add-scc-to-group <missing-scc>
    system:serviceaccounts:tenant-x — the SCC AND the namespace are
    missing. ghost-scc-target fires (Path D); Path B does not (it
    requires the SCC to exist)."""
    idx = make_index(
        cluster_roles=[_scc_use_clusterrole("dormant-scc")],
        crbs=[{"name": "system:openshift:scc:dormant-scc",
               "subjects": [{"kind": "Group",
                              "name": "system:serviceaccounts:tenant-x"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:dormant-scc"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    targets = [r for r in rows if r.get("kind") == "ghost-scc-target"]
    assert len(targets) == 1
    assert targets[0]["scc"] == "dormant-scc"
    assert targets[0]["severity"] == "low"
    assert targets[0]["subject_present"] is False
    assert "missing namespace `tenant-x`" in targets[0]["explanation"]
    # Path B requires the SCC to be in `sccs_by_name` — it correctly skips
    impl_groups = [r for r in rows if r.get("kind") == "implicit-sa-group"]
    assert impl_groups == []


# ---------- 5. ghost SCC + existing Group ------------------------------ #

def test_missing_scc_existing_group_still_flagged():
    """If the Group exists but the SCC doesn't, still flag —
    creating the SCC immediately gives the existing Group use of it."""
    idx = make_index(
        groups=[{"name": "engineers", "users": ["alice"]}],
        cluster_roles=[_scc_use_clusterrole("future-scc")],
        crbs=[{"name": "system:openshift:scc:future-scc",
               "subjects": [{"kind": "Group", "name": "engineers"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:future-scc"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    matches = [r for r in rows
               if r.get("kind") == "ghost-scc-target"
               and r.get("scc") == "future-scc"]
    assert len(matches) == 1
    r = matches[0]
    assert r["subject_present"] is True
    assert r["subject_name"] == "engineers"


# ---------- 6. Custom role with rule.resourceNames=[missing] ---------- #

def test_custom_role_referencing_missing_scc_flagged():
    """A bespoke ClusterRole (not the system:openshift:scc:* shape)
    with verb=use on securitycontextconstraints + resourceNames=
    ['missing-scc'] is detected via rule inspection."""
    custom_role = {
        "name": "shared-scc-grantor",
        "labels": {}, "annotations": {}, "aggregationRule": None,
        "rules": [{"apiGroups": ["security.openshift.io"],
                   "resources": ["securitycontextconstraints"],
                   "verbs": ["use"],
                   "resourceNames": ["missing-scc"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }
    idx = make_index(
        users=[{"name": "alice"}],
        cluster_roles=[custom_role],
        crbs=[{"name": "shared-scc-binding",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "shared-scc-grantor"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    matches = [r for r in rows
               if r.get("kind") == "ghost-scc-target"
               and r.get("scc") == "missing-scc"]
    assert len(matches) == 1


# ---------- 7. Wildcard resourceNames does NOT trigger Path D --------- #

def test_wildcard_resource_names_does_not_emit_ghost_scc_target():
    """A rule with verbs=[use], resources=[scc], resourceNames=['*']
    grants every existing SCC but doesn't name any specific missing
    one. Don't fabricate ghost-scc-target rows from a wildcard."""
    wild_role = {
        "name": "wildcard-scc-user",
        "labels": {}, "annotations": {}, "aggregationRule": None,
        "rules": [{"apiGroups": ["security.openshift.io"],
                   "resources": ["securitycontextconstraints"],
                   "verbs": ["use"],
                   "resourceNames": ["*"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }
    idx = make_index(
        users=[{"name": "alice"}],
        sccs=[_scc("anyuid", allowPrivilegedContainer=False,
                    runAsUser={"type": "RunAsAny"})],
        cluster_roles=[wild_role],
        crbs=[{"name": "wildcard-binding",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "wildcard-scc-user"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert not any(r.get("kind") == "ghost-scc-target" for r in rows)


def test_empty_resource_names_does_not_emit_ghost_scc_target():
    """No resourceNames means 'all SCCs' — same wildcard semantics."""
    open_role = {
        "name": "any-scc-user",
        "labels": {}, "annotations": {}, "aggregationRule": None,
        "rules": [{"apiGroups": ["security.openshift.io"],
                   "resources": ["securitycontextconstraints"],
                   "verbs": ["use"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }
    idx = make_index(
        users=[{"name": "alice"}],
        sccs=[_scc("anyuid")],
        cluster_roles=[open_role],
        crbs=[{"name": "open-binding",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "any-scc-user"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert not any(r.get("kind") == "ghost-scc-target" for r in rows)


# ---------- 8. Existing SCC is NOT flagged via Path D ------------------ #

def test_existing_scc_not_emitted_via_ghost_scc_target():
    """A live SCC grant goes through Paths A/B/C, not D. Make sure
    we don't double-fire."""
    idx = make_index(
        users=[{"name": "alice"}],
        sccs=[_scc("anyuid", allowPrivilegedContainer=False,
                    runAsUser={"type": "RunAsAny"})],
        cluster_roles=[_scc_use_clusterrole("anyuid")],
        crbs=[{"name": "system:openshift:scc:anyuid",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:anyuid"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert not any(r.get("kind") == "ghost-scc-target" for r in rows)


# ---------- 8b. Role name convention alone is NOT a grant ------------- #

def test_scc_role_name_without_scc_use_rule_does_not_emit_ghost_target():
    """A custom ClusterRole can reuse the system:openshift:scc:* prefix
    without granting SCC use. The name alone is not enough."""
    idx = make_index(
        users=[{"name": "alice"}],
        cluster_roles=[{
            "name": "system:openshift:scc:missing-by-name-only",
            "labels": {}, "annotations": {}, "aggregationRule": None,
            "rules": [{"apiGroups": [""],
                       "resources": ["pods"],
                       "verbs": ["get"]}],
            "creationTimestamp": "2024-01-01T00:00:00Z",
        }],
        crbs=[{"name": "name-only-binding",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:missing-by-name-only"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert not any(r.get("kind") == "ghost-scc-target" for r in rows)


def test_missing_role_ref_with_scc_role_name_does_not_emit_ghost_target():
    """A CRB whose roleRef target does not exist grants nothing today.
    Creating only the SCC would not activate it, so Path D must not fire."""
    idx = make_index(
        users=[{"name": "alice"}],
        crbs=[{"name": "orphan-binding",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:missing-role-ref"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert not any(r.get("kind") == "ghost-scc-target" for r in rows)


# ---------- 9. Severity stays low — auto-escalates when SCC appears -- #

def test_ghost_scc_target_severity_is_low_regardless_of_subject_kind():
    """The user said 'low resurrectable things unless they later
    acquired more power'. Until the SCC exists, severity is low."""
    for subject in [
        {"kind": "User", "name": "alice"},
        {"kind": "Group", "name": "engineers"},
        {"kind": "ServiceAccount", "name": "pipeline", "namespace": "demo"},
    ]:
        idx = make_index(
            namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
            cluster_roles=[_scc_use_clusterrole("dormant")],
            crbs=[{"name": "system:openshift:scc:dormant",
                   "subjects": [subject],
                   "roleRef": {"kind": "ClusterRole",
                                "name": "system:openshift:scc:dormant"}}],
        )
        rows = engine.resurrectable_implicit_scc_groups(idx)
        targets = [r for r in rows if r.get("kind") == "ghost-scc-target"]
        assert len(targets) == 1
        assert targets[0]["severity"] == "low"


def test_ghost_scc_target_escalates_when_scc_is_created():
    """Auto-escalation: once an SCC with the missing name is created
    (and is privileged), the binding is re-classified through Path C
    (if subject is ghost) or appears as a live grant (if subject exists).
    The ghost-scc-target row drops out."""
    # Before: SCC absent → ghost-scc-target low
    before = make_index(
        users=[{"name": "alice"}],
        cluster_roles=[_scc_use_clusterrole("now-privileged")],
        crbs=[{"name": "system:openshift:scc:now-privileged",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:now-privileged"}}],
    )
    before_rows = engine.resurrectable_implicit_scc_groups(before)
    assert any(r.get("kind") == "ghost-scc-target"
               and r.get("scc") == "now-privileged"
               and r.get("severity") == "low" for r in before_rows)
    # After: an admin creates the SCC and makes it privileged
    after = make_index(
        users=[{"name": "alice"}],
        sccs=[_scc("now-privileged", allowPrivilegedContainer=True)],
        cluster_roles=[_scc_use_clusterrole("now-privileged")],
        crbs=[{"name": "system:openshift:scc:now-privileged",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:now-privileged"}}],
    )
    after_rows = engine.resurrectable_implicit_scc_groups(after)
    # ghost-scc-target row gone
    assert not any(r.get("kind") == "ghost-scc-target"
                   for r in after_rows)


# ---------- 10. Limited view safety ----------------------------------- #

def test_ghost_scc_target_not_reported_under_limited_view():
    idx = make_index(
        users=[{"name": "alice"}],
        cluster_roles=[_scc_use_clusterrole("missing-scc")],
        crbs=[{"name": "system:openshift:scc:missing-scc",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:missing-scc"}}],
    )
    idx["is_admin"] = False
    assert engine.resurrectable_implicit_scc_groups(idx) == []


# ---------- 11. UI: identity-audit renders the new section ------------- #

def test_identity_audit_page_renders_ghost_scc_target_section(monkeypatch):
    idx = make_index(
        users=[{"name": "alice"}],
        cluster_roles=[_scc_use_clusterrole("phantom-scc")],
        crbs=[{"name": "system:openshift:scc:phantom-scc",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:phantom-scc"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/identity-audit?severity=all").data.decode()
    assert 'id="resurrectable-ghost-scc-targets"' in body
    assert "SCC grants to non-existent SCCs" in body
    assert "phantom-scc" in body
    assert "missing SCC" in body


# ---------- 12. Baseline classification by subject provenance --------- #

def test_ghost_scc_target_with_baseline_subject_is_baseline():
    """A dormant SCC reference whose subjects are all platform identities
    (e.g., cluster-monitoring-operator) is operator plumbing — it is NOT
    a developer-actionable path. Mark baseline=True so the home card
    doesn't scare the reviewer."""
    idx = make_index(
        namespaces=[{"name": "openshift-monitoring", "labels": {},
                     "annotations": {}}],
        sas=[{"name": "cluster-monitoring-operator",
              "namespace": "openshift-monitoring",
              "labels": {}, "annotations": {}}],
        cluster_roles=[{
            "name": "cluster-monitoring-operator",
            "labels": {}, "annotations": {}, "aggregationRule": None,
            "rules": [{"apiGroups": ["security.openshift.io"],
                       "resources": ["securitycontextconstraints"],
                       "verbs": ["use"],
                       "resourceNames": ["node-exporter"]}],
            "creationTimestamp": "2024-01-01T00:00:00Z",
        }],
        crbs=[{"name": "cluster-monitoring-operator",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "cluster-monitoring-operator",
                              "namespace": "openshift-monitoring"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "cluster-monitoring-operator"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    targets = [r for r in rows
               if r.get("kind") == "ghost-scc-target"
               and r.get("scc") == "node-exporter"]
    assert len(targets) == 1
    assert targets[0]["baseline"] is True
    assert "platform identities" in (targets[0]["baseline_reason"] or "")


def test_baseline_ghost_scc_target_does_not_link_missing_scc(monkeypatch):
    idx = make_index(
        namespaces=[{"name": "openshift-monitoring", "labels": {},
                     "annotations": {}}],
        sas=[{"name": "cluster-monitoring-operator",
              "namespace": "openshift-monitoring",
              "labels": {}, "annotations": {}}],
        cluster_roles=[{
            "name": "cluster-monitoring-operator",
            "labels": {}, "annotations": {}, "aggregationRule": None,
            "rules": [{"apiGroups": ["security.openshift.io"],
                       "resources": ["securitycontextconstraints"],
                       "verbs": ["use"],
                       "resourceNames": ["node-exporter"]}],
            "creationTimestamp": "2024-01-01T00:00:00Z",
        }],
        crbs=[{"name": "cluster-monitoring-operator",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "cluster-monitoring-operator",
                              "namespace": "openshift-monitoring"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "cluster-monitoring-operator"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/identity-audit?severity=all").data.decode()

    assert "node-exporter" in body
    assert "missing SCC" in body
    assert 'href="/scc/node-exporter"' not in body


def test_ghost_scc_target_with_user_subject_is_not_baseline():
    """User's hand-typed `oc adm policy add-scc-to-user` shape: even
    though the CRB name starts with `system:openshift:scc:*`, the
    subject is a human-named user — actionable, not baseline."""
    idx = make_index(
        users=[{"name": "alice"}],
        cluster_roles=[_scc_use_clusterrole("non-existing-scc")],
        crbs=[{"name": "system:openshift:scc:non-existing-scc",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:non-existing-scc"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    targets = [r for r in rows
               if r.get("kind") == "ghost-scc-target"
               and r.get("scc") == "non-existing-scc"]
    assert len(targets) == 1
    assert targets[0]["baseline"] is False
    assert targets[0]["baseline_reason"] is None


# ---------- 13. Dedup: same (scc, subject, source) is one row -------- #

def test_ghost_scc_target_dedup_one_row_per_subject_per_missing_scc():
    """A single binding listing multiple resourceNames including one
    missing should produce one ghost-scc-target row per missing SCC,
    not duplicates."""
    role = {
        "name": "multi-grant",
        "labels": {}, "annotations": {}, "aggregationRule": None,
        "rules": [{"apiGroups": ["security.openshift.io"],
                   "resources": ["securitycontextconstraints"],
                   "verbs": ["use"],
                   "resourceNames": ["anyuid", "missing-a", "missing-b"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }
    idx = make_index(
        users=[{"name": "alice"}],
        sccs=[_scc("anyuid")],
        cluster_roles=[role],
        crbs=[{"name": "multi-grant-binding",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole", "name": "multi-grant"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    targets = [r for r in rows if r.get("kind") == "ghost-scc-target"]
    assert sorted(t["scc"] for t in targets) == ["missing-a", "missing-b"]
