"""Regression tests for the resurrectable implicit-SA-group finding.

The trigger is a real CRC scenario:

  - Custom SCC `legacy-pipeline-root` has
    `.groups: [system:serviceaccounts:legacy-pipelines]` and
    `runAsUser: RunAsAny`.
  - Project `legacy-pipelines` is deleted; the SCC.groups entry survives.
  - A non-admin recreates `legacy-pipelines` via `oc new-project`. The
    auto-created `default`/`builder`/`deployer` SAs satisfy the SCC
    group entry. A pod with `runAsUser: 0` is admitted under the SCC.

The identity-audit page should surface this alongside the
resurrectable-SA family.
"""

from lineage import engine
from lineage.main import app
from .conftest import make_index, scc_use_clusterrole as _scc_use_clusterrole


def _scc(name, **kwargs):
    """Minimal SCC dict; defaults match CRC's anyuid-like posture."""
    return {
        "name": name,
        "users": kwargs.pop("users", []),
        "groups": kwargs.pop("groups", []),
        "allowPrivilegedContainer": kwargs.pop("allowPrivilegedContainer", False),
        "allowHostNetwork": kwargs.pop("allowHostNetwork", False),
        "allowHostPID": kwargs.pop("allowHostPID", False),
        "allowHostIPC": kwargs.pop("allowHostIPC", False),
        "allowPrivilegeEscalation": kwargs.pop("allowPrivilegeEscalation", True),
        "runAsUser": kwargs.pop("runAsUser", {"type": "RunAsAny"}),
        "creationTimestamp": kwargs.pop("creationTimestamp",
                                         "2025-01-01T00:00:00Z"),
        **kwargs,
    }


# ---------- Headline contract: deleted ns → finding ---------- #

def test_scc_group_with_deleted_namespace_surfaces_as_resurrectable():
    """The exact CRC lab shape: SCC.groups names a namespace that does
    not exist as a namespace object."""
    idx = make_index(
        # namespaces=[] — legacy-pipelines is deleted.
        sccs=[_scc("legacy-pipeline-root",
                   groups=["system:serviceaccounts:legacy-pipelines"])],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    row = rows[0]
    assert row["kind"] == "implicit-sa-group"
    assert row["group"] == "system:serviceaccounts:legacy-pipelines"
    assert row["namespace"] == "legacy-pipelines"
    assert row["namespace_present"] is False
    assert row["scc"] == "legacy-pipeline-root"
    # runAsUser=RunAsAny → high (from _scc_severity).
    assert row["severity"] == "high"
    # Source attribution + explanation captions are part of the contract:
    assert "SCC/legacy-pipeline-root" == row["source"]
    assert "default, builder" in row["explanation"]


def test_scc_group_not_reported_when_visibility_is_limited():
    """Without cluster-wide subject/namespace visibility, a namespace
    missing from the index may simply be unreadable, not deleted."""
    idx = make_index(
        sccs=[_scc("legacy-pipeline-root",
                   groups=["system:serviceaccounts:legacy-pipelines"])],
    )
    idx["is_admin"] = False

    assert engine.resurrectable_implicit_scc_groups(idx) == []


# ---------- Inverse: present namespace must NOT appear ---------- #

def test_scc_group_with_present_namespace_does_not_appear():
    """When the namespace exists, the entry represents live access, not
    a resurrectable finding. The SCC detail page covers it."""
    idx = make_index(
        namespaces=[{"name": "legacy-pipelines", "labels": {},
                     "annotations": {}}],
        sccs=[_scc("legacy-pipeline-root",
                   groups=["system:serviceaccounts:legacy-pipelines"])],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert rows == []


# ---------- Severity reflects SCC posture ---------- #

def test_severity_critical_for_privileged_scc():
    idx = make_index(
        sccs=[_scc("custom-priv",
                   allowPrivilegedContainer=True,
                   groups=["system:serviceaccounts:deleted-ns"])],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert rows[0]["severity"] == "critical"
    assert rows[0]["is_privileged_scc"] is True


def test_severity_high_for_runasany_only():
    """The exact lab scenario: not privileged, but RunAsAny → high."""
    idx = make_index(
        sccs=[_scc("custom-root",
                   runAsUser={"type": "RunAsAny"},
                   groups=["system:serviceaccounts:deleted-ns"])],
    )
    assert engine.resurrectable_implicit_scc_groups(idx)[0]["severity"] == "high"


def test_severity_high_for_host_namespace():
    idx = make_index(
        sccs=[_scc("custom-host",
                   allowHostNetwork=True,
                   runAsUser={"type": "MustRunAs"},
                   groups=["system:serviceaccounts:deleted-ns"])],
    )
    assert engine.resurrectable_implicit_scc_groups(idx)[0]["severity"] == "high"


def test_severity_medium_for_privesc_only():
    idx = make_index(
        sccs=[_scc("custom-low",
                   allowPrivilegeEscalation=True,
                   runAsUser={"type": "MustRunAs"},
                   groups=["system:serviceaccounts:deleted-ns"])],
    )
    assert engine.resurrectable_implicit_scc_groups(idx)[0]["severity"] == "medium"


# ---------- Baseline-named namespaces are skipped ---------- #

def test_baseline_named_namespace_is_marked_baseline_not_dropped():
    """An SCC group pointing at a *baseline*-named ns (kube-system,
    openshift-*) that's currently missing is a platform-level event,
    not a self-provisioner risk. Surface it with baseline=True so it
    stays visible to admins but doesn't drive the home dashboard's
    actionable counters."""
    idx = make_index(
        sccs=[_scc("custom",
                   groups=["system:serviceaccounts:openshift-imaginary-operator"])],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    assert rows[0]["baseline"] is True
    assert "openshift-" in rows[0]["baseline_reason"]
    assert rows[0]["namespace"] == "openshift-imaginary-operator"


# ---------- Ignores non-SA-prefix groups ---------- #

def test_only_implicit_sa_groups_are_considered():
    """`system:authenticated`, `system:cluster-admins`, and custom Group
    names don't have the system:serviceaccounts:<ns> shape."""
    idx = make_index(
        sccs=[_scc("custom",
                   groups=["system:authenticated",
                           "system:cluster-admins",
                           "engineers"])],
    )
    assert engine.resurrectable_implicit_scc_groups(idx) == []


# ---------- Sorting: critical first ---------- #

def test_rows_sorted_critical_first():
    idx = make_index(
        sccs=[
            _scc("z-low",
                 allowPrivilegeEscalation=False,
                 runAsUser={"type": "MustRunAs"},
                 groups=["system:serviceaccounts:ns-low"]),
            _scc("a-priv",
                 allowPrivilegedContainer=True,
                 groups=["system:serviceaccounts:ns-priv"]),
        ],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert [r["severity"] for r in rows[:2]] == ["critical", "low"]


# ---------- identity_audit integration ---------- #

def test_identity_audit_returns_implicit_groups_key():
    """The audit dict carries the new family for the template."""
    idx = make_index(
        sccs=[_scc("legacy-pipeline-root",
                   groups=["system:serviceaccounts:legacy-pipelines"])],
    )
    audit = engine.identity_audit(idx)
    assert "resurrectable_implicit_groups" in audit
    assert len(audit["resurrectable_implicit_groups"]) == 1
    assert "resurrectable_implicit_critical" in audit


def test_identity_audit_total_includes_new_family():
    """The top-level `total` for the dashboard accounts for the
    new family — otherwise the home-page summary would understate."""
    empty = make_index()
    empty_total = engine.identity_audit(empty)["total"]
    with_finding = make_index(
        sccs=[_scc("legacy-pipeline-root",
                   groups=["system:serviceaccounts:legacy-pipelines"])],
    )
    new_total = engine.identity_audit(with_finding)["total"]
    assert new_total == empty_total + 1


# ---------- Existing resurrectable family unchanged ---------- #

def test_existing_resurrectable_sa_family_still_populates():
    """SA-principal resurrectable findings should still be reported."""
    idx = make_index(
        crbs=[{"name": "gone-sa-view",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "automation-sa",
                              "namespace": "retired-automation"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
        cluster_roles=[{"name": "cluster-admin", "labels": {},
                         "annotations": {}, "aggregationRule": None,
                         "rules": [{"apiGroups": ["*"], "resources": ["*"],
                                    "verbs": ["*"]}]}],
    )
    rs = engine.resurrectable_sa_identities(idx)
    assert any(r["name"] == "automation-sa" for r in rs)


# ---------- /identity-audit renders the new section ---------- #

def test_identity_audit_page_renders_implicit_group_section(monkeypatch):
    idx = make_index(
        sccs=[_scc("legacy-pipeline-root",
                   groups=["system:serviceaccounts:legacy-pipelines"])],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/identity-audit?severity=all").data.decode()

    # Section heading is now "SCC implicit-SA groups" (the parent heading
    # is "Resurrectable identities and SCC groups").
    assert "SCC implicit-SA groups" in body
    assert "legacy-pipeline-root" in body
    assert "system:serviceaccounts:legacy-pipelines" in body
    assert "default, builder" in body  # the auto-SA caption
    assert ">high</span>" in body or ">critical</span>" in body

    # New ordering: the SCC implicit-group sub-section must appear
    # ABOVE the ServiceAccount identities sub-section.
    implicit_pos = body.index("SCC implicit-SA groups")
    sa_pos = body.index("ServiceAccount identities")
    assert implicit_pos < sa_pos


def test_identity_audit_page_omits_section_when_no_findings(monkeypatch):
    idx = make_index()
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/identity-audit?severity=all").data.decode()
    # The lede paragraph references the SCC implicit-SA-group concept
    # in passing; the actual sub-section is gated by content. Assert on
    # the sub-section id + sub-section heading shape, not the bare string.
    assert 'id="resurrectable-implicit-groups"' not in body
    assert "<h3>SCC implicit-SA groups" not in body


# ---------- /scc/<name> page unchanged ---------- #

def test_home_dashboard_card_lists_both_families(monkeypatch):
    """The resurrectable card on / now covers BOTH the SA-resurrectable
    family AND the SCC implicit-SA group family. Counts split per family."""
    # One SCC group resurrectable + one SA resurrectable.
    idx = make_index(
        sccs=[_scc("legacy-pipeline-root",
                   groups=["system:serviceaccounts:legacy-pipelines"])],
        crbs=[{"name": "ghost-sa-admin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "automation-sa",
                              "namespace": "retired-automation"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
        cluster_roles=[{"name": "cluster-admin", "labels": {},
                         "annotations": {}, "aggregationRule": None,
                         "rules": [{"apiGroups": ["*"], "resources": ["*"],
                                    "verbs": ["*"]}]}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/").data.decode()

    # Card label covers both families.
    assert "critical resurrectable" in body
    # Slim per-family counts in the subtitle (singular forms).
    assert "1 SA" in body
    assert "1 SCC group" in body
    # Card link still goes to the resurrectable section so clicking
    # lands on both families.
    assert 'href="/identity-audit?severity=critical#resurrectable"' in body


def test_home_dashboard_critical_counter_sums_both_families(monkeypatch):
    """Critical-severity number in the card sums both family criticals."""
    # SA-resurrectable family contributes 1 critical (cluster-admin).
    # SCC implicit-group family contributes 1 critical (allowPrivileged).
    idx = make_index(
        sccs=[_scc("super-priv",
                   allowPrivilegedContainer=True,
                   groups=["system:serviceaccounts:retired-tenant"])],
        crbs=[{"name": "ghost-sa-admin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "automation-sa",
                              "namespace": "retired-automation"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
        cluster_roles=[{"name": "cluster-admin", "labels": {},
                         "annotations": {}, "aggregationRule": None,
                         "rules": [{"apiGroups": ["*"], "resources": ["*"],
                                    "verbs": ["*"]}]}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/").data.decode()
    # The card's <div class="num"> should read 2 — the sum.
    import re
    m = re.search(
        r'<div class="num">(\d+)</div>\s*'
        r'<div class="lab">critical resurrectable</div>',
        body)
    assert m is not None
    assert m.group(1) == "2"


def test_scc_detail_page_still_renders(monkeypatch):
    """SCC detail should keep its per-SCC namespace context."""
    idx = make_index(
        sccs=[_scc("legacy-pipeline-root",
                   groups=["system:serviceaccounts:legacy-pipelines"])],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/scc/legacy-pipeline-root").data.decode()
    assert "system:serviceaccounts:legacy-pipelines" in body


# ===================================================================== #
# RBAC-grant resurrection — the `oc adm policy add-scc-to-group` shape  #
# ===================================================================== #
#
# `oc adm policy add-scc-to-group <scc> <group>` does NOT mutate
# `scc.groups`. It binds the ClusterRole `system:openshift:scc:<scc>` to
# the named group via a (Cluster)RoleBinding. The grant is just as live
# as the direct field, and equally susceptible to namespace resurrection
# when the subject is `Group/system:serviceaccounts:<missing-ns>`.
#
# RBAC SCC use grants can also target implicit ServiceAccount groups.


# --- 1. direct scc.groups still works (parity check) ----------------- #

def test_direct_scc_groups_with_missing_ns_flags_resurrectable():
    idx = make_index(
        sccs=[_scc("privileged",
                   allowPrivilegedContainer=True,
                   groups=["system:serviceaccounts:missing-ns"])],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    r = rows[0]
    assert r["scc"] == "privileged"
    assert r["namespace"] == "missing-ns"
    assert r["severity"] == "critical"
    assert r["source"] == "SCC/privileged"
    assert r.get("source_kind") == "scc.groups"


# --- 2. `oc adm policy add-scc-to-group` (RBAC) flags too ------------- #

def test_rbac_use_grant_to_missing_ns_group_flags_resurrectable():
    """A CRB binds system:openshift:scc:privileged to
    Group/system:serviceaccounts:missing-ns. scc.groups is empty.
    This is exactly what `oc adm policy add-scc-to-group privileged
    system:serviceaccounts:missing-ns` writes."""
    idx = make_index(
        sccs=[_scc("privileged",
                   allowPrivilegedContainer=True,
                   groups=[])],
        cluster_roles=[_scc_use_clusterrole("privileged")],
        crbs=[{
            "name": "scc-priv-to-missing-ns",
            "subjects": [{"kind": "Group",
                          "apiGroup": "rbac.authorization.k8s.io",
                          "name": "system:serviceaccounts:missing-ns"}],
            "roleRef": {"kind": "ClusterRole",
                        "apiGroup": "rbac.authorization.k8s.io",
                        "name": "system:openshift:scc:privileged"},
        }],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    r = rows[0]
    assert r["scc"] == "privileged"
    assert r["namespace"] == "missing-ns"
    assert r["namespace_present"] is False
    assert r["severity"] == "critical"
    # Source attribution names the binding so admins can find the grant
    assert r["source"] == "ClusterRoleBinding/scc-priv-to-missing-ns"
    assert r["via"].startswith("RBAC use grant via")
    assert r.get("source_kind") == "rbac.use"
    assert r["binding_kind"] == "ClusterRoleBinding"
    assert r["binding_name"] == "scc-priv-to-missing-ns"
    assert r["role"] == "system:openshift:scc:privileged"
    # Explanation contract from the issue
    assert "RBAC grants use of SCC/privileged" in r["explanation"]
    assert "system:serviceaccounts:missing-ns" in r["explanation"]
    assert "recreating" in r["explanation"]


# --- 3. existing namespace must NOT be flagged ----------------------- #

def test_rbac_use_grant_existing_namespace_not_flagged():
    """When the namespace already exists, the RBAC grant is *live*
    SCC access (admin-visible elsewhere), not a resurrectable finding."""
    idx = make_index(
        namespaces=[{"name": "live-ns", "labels": {}, "annotations": {}}],
        sccs=[_scc("privileged", allowPrivilegedContainer=True, groups=[])],
        cluster_roles=[_scc_use_clusterrole("privileged")],
        crbs=[{
            "name": "scc-priv-to-live-ns",
            "subjects": [{"kind": "Group",
                          "name": "system:serviceaccounts:live-ns"}],
            "roleRef": {"kind": "ClusterRole",
                        "name": "system:openshift:scc:privileged"},
        }],
    )
    assert engine.resurrectable_implicit_scc_groups(idx) == []


# --- 4. recreated namespace makes the finding disappear -------------- #

def test_rbac_use_grant_disappears_after_namespace_recreated():
    """The dev-exploit lifecycle: before the namespace exists the finding
    is in /identity-audit resurrectable; once developer recreates it the
    finding drops out (and the live SCC access path appears elsewhere)."""
    binding = {
        "name": "scc-priv-to-tenant-x",
        "subjects": [{"kind": "Group",
                      "name": "system:serviceaccounts:tenant-x"}],
        "roleRef": {"kind": "ClusterRole",
                    "name": "system:openshift:scc:privileged"},
    }
    role = _scc_use_clusterrole("privileged")
    scc = _scc("privileged", allowPrivilegedContainer=True, groups=[])

    # Before: namespace absent → flagged
    idx_before = make_index(sccs=[scc], cluster_roles=[role], crbs=[binding])
    assert len(engine.resurrectable_implicit_scc_groups(idx_before)) == 1

    # After: developer recreates tenant-x → cleared
    idx_after = make_index(
        namespaces=[{"name": "tenant-x", "labels": {}, "annotations": {}}],
        sccs=[scc], cluster_roles=[role], crbs=[binding],
    )
    assert engine.resurrectable_implicit_scc_groups(idx_after) == []


# --- 5. limited / non-admin visibility must NOT false-positive -------- #

def test_rbac_use_grant_not_reported_when_limited_view():
    """A namespace missing from the index under a non-admin token may be
    unreadable, not deleted. Don't conjure a resurrectable finding."""
    idx = make_index(
        sccs=[_scc("privileged", allowPrivilegedContainer=True, groups=[])],
        cluster_roles=[_scc_use_clusterrole("privileged")],
        crbs=[{
            "name": "scc-priv-to-tenant",
            "subjects": [{"kind": "Group",
                          "name": "system:serviceaccounts:tenant-x"}],
            "roleRef": {"kind": "ClusterRole",
                        "name": "system:openshift:scc:privileged"},
        }],
    )
    idx["is_admin"] = False
    assert engine.resurrectable_implicit_scc_groups(idx) == []


# --- 6. raw system groups must NOT be misclassified ------------------ #

def test_rbac_grant_to_raw_system_groups_not_flagged():
    """`system:authenticated`, `system:authenticated:oauth`,
    `system:serviceaccounts` (no namespace), `system:cluster-admins`,
    `system:masters` — none of these are namespace-scoped SA groups
    and none can be "ghost" subjects (they are virtual or stable
    platform groups). They must NOT generate a resurrectable finding,
    even when the same binding also references a real ghost Group.

    The arbitrary `engineers` Group that doesn't exist on the cluster
    IS a real ghost subject, so it surfaces under Path C (ghost-scc-
    subject). Confirm both: system:* never appears; engineers does."""
    idx = make_index(
        sccs=[_scc("privileged", allowPrivilegedContainer=True, groups=[])],
        cluster_roles=[_scc_use_clusterrole("privileged")],
        crbs=[{
            "name": "scc-priv-to-noisy-group",
            "subjects": [
                {"kind": "Group", "name": "system:authenticated"},
                {"kind": "Group", "name": "system:authenticated:oauth"},
                {"kind": "Group", "name": "system:serviceaccounts"},
                {"kind": "Group", "name": "system:cluster-admins"},
                {"kind": "Group", "name": "system:masters"},
                {"kind": "Group", "name": "engineers"},
            ],
            "roleRef": {"kind": "ClusterRole",
                        "name": "system:openshift:scc:privileged"},
        }],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    # Exactly one row: the engineers ghost. Every system:* name skipped.
    assert len(rows) == 1
    r = rows[0]
    assert r["kind"] == "ghost-scc-subject"
    assert r["subject_kind"] == "Group"
    assert r["subject_name"] == "engineers"
    # No row references a system:* group
    for row in rows:
        assert not (row.get("group") or "").startswith("system:")


# --- 7. severity reflects SCC posture, not binding noise ------------- #

def test_rbac_grant_severity_matches_underlying_scc_posture():
    """A non-privileged SCC bound via RBAC to a missing-ns group must
    surface at the SCC's own severity (here: low for restricted-v2-like)."""
    idx = make_index(
        sccs=[_scc("restricted-v2",
                   allowPrivilegedContainer=False,
                   allowHostNetwork=False, allowHostPID=False,
                   allowHostIPC=False, allowPrivilegeEscalation=False,
                   runAsUser={"type": "MustRunAsRange"},
                   groups=[])],
        cluster_roles=[_scc_use_clusterrole("restricted-v2")],
        crbs=[{
            "name": "scc-restricted-to-missing-ns",
            "subjects": [{"kind": "Group",
                          "name": "system:serviceaccounts:missing-ns"}],
            "roleRef": {"kind": "ClusterRole",
                        "name": "system:openshift:scc:restricted-v2"},
        }],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    assert rows[0]["severity"] == "low"
    assert rows[0]["scc"] == "restricted-v2"


# --- bonus: custom Role granting SCC use via rule (not the named-role path) --

def test_rbac_custom_role_with_use_rule_flags_resurrectable():
    """A bespoke ClusterRole with a verb=use on
    securitycontextconstraints + resourceNames=[privileged] should be
    detected via rule inspection, even though its name isn't
    system:openshift:scc:privileged."""
    custom_role = {
        "name": "custom-scc-user",
        "labels": {}, "annotations": {}, "aggregationRule": None,
        "rules": [{
            "apiGroups": ["security.openshift.io"],
            "resources": ["securitycontextconstraints"],
            "verbs": ["use"],
            "resourceNames": ["privileged"],
        }],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }
    idx = make_index(
        sccs=[_scc("privileged", allowPrivilegedContainer=True, groups=[])],
        cluster_roles=[custom_role],
        crbs=[{
            "name": "custom-scc-use-binding",
            "subjects": [{"kind": "Group",
                          "name": "system:serviceaccounts:retired-team"}],
            "roleRef": {"kind": "ClusterRole", "name": "custom-scc-user"},
        }],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    assert rows[0]["scc"] == "privileged"
    assert rows[0]["namespace"] == "retired-team"
    assert rows[0]["severity"] == "critical"


# --- bonus: namespaced RoleBinding shape ---------------------------- #

def test_namespaced_rolebinding_grant_flags_resurrectable():
    """A RoleBinding (namespaced) granting SCC use to
    Group/system:serviceaccounts:<missing-ns> is detected the same way."""
    idx = make_index(
        namespaces=[{"name": "ops", "labels": {}, "annotations": {}}],
        sccs=[_scc("privileged", allowPrivilegedContainer=True, groups=[])],
        cluster_roles=[_scc_use_clusterrole("privileged")],
        rbs=[{
            "name": "scc-priv-to-missing-tenant",
            "namespace": "ops",
            "subjects": [{"kind": "Group",
                          "name": "system:serviceaccounts:missing-tenant"}],
            "roleRef": {"kind": "ClusterRole",
                        "name": "system:openshift:scc:privileged"},
        }],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    r = rows[0]
    assert r["namespace"] == "missing-tenant"
    assert r["binding_kind"] == "RoleBinding"
    assert r["binding_namespace"] == "ops"
    # Source carries the binding's namespace so admins can find it
    assert r["source"] == "RoleBinding/ops/scc-priv-to-missing-tenant"


# --- dedup guard: direct + RBAC for same (scc, ns) emit both rows ---- #

def _cluster_admin_role():
    return {
        "name": "cluster-admin", "labels": {}, "annotations": {},
        "aggregationRule": None,
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }


# ===================================================================== #
# Baseline classification (clean CRC vs actionable seeded scenarios)    #
# ===================================================================== #

def test_clean_platform_sa_in_openshift_namespace_is_baseline():
    """The exact clean-CRC shape: 16 platform SAs in openshift-* are
    bound to operator roles but their SA objects are not in the index.
    They must be flagged baseline so home dashboard counters stay 0."""
    idx = make_index(
        crbs=[{"name": "platform-binding",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "prometheus-k8s",
                              "namespace": "openshift-monitoring"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        cluster_roles=[{"name": "view", "labels": {}, "annotations": {},
                         "aggregationRule": None,
                         "rules": [{"apiGroups": [""], "resources": ["pods"],
                                    "verbs": ["get"]}]}],
    )
    rs = engine.resurrectable_sa_identities(idx)
    assert len(rs) == 1
    row = rs[0]
    assert row["namespace"] == "openshift-monitoring"
    assert row["baseline"] is True
    assert "openshift-" in row["baseline_reason"]


def test_kube_system_sa_is_baseline():
    """A resurrectable SA in kube-system is baseline — `oc new-project
    kube-system` is admission-blocked. Not developer-actionable."""
    idx = make_index(
        crbs=[{"name": "kube-binding",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "kube-controller-manager",
                              "namespace": "kube-system"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        cluster_roles=[{"name": "view", "labels": {}, "annotations": {},
                         "aggregationRule": None,
                         "rules": [{"apiGroups": [""], "resources": ["pods"],
                                    "verbs": ["get"]}]}],
    )
    rs = engine.resurrectable_sa_identities(idx)
    assert len(rs) == 1
    assert rs[0]["baseline"] is True


def test_actionable_resurrectable_sa_with_cluster_admin():
    """The seeded escalation scenario:
    system:serviceaccount:lineage-dev-escalation-demo:pipeline-admin
    bound to cluster-admin. Namespace is NOT openshift-*/kube-* — a
    developer with self-provisioner CAN recreate this name. Must
    surface as actionable critical and count on the home card."""
    idx = make_index(
        crbs=[{"name": "lineage-resurrected-admin-sa-crb",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "pipeline-admin",
                              "namespace": "lineage-dev-escalation-demo"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
        cluster_roles=[_cluster_admin_role()],
    )
    rs = engine.resurrectable_sa_identities(idx)
    assert len(rs) == 1
    row = rs[0]
    assert row["baseline"] is False
    assert row["baseline_reason"] is None
    assert row["severity"] == "critical"
    assert row["has_cluster_admin"] is True


def test_direct_scc_groups_openshift_ns_is_baseline():
    """`scc.groups = [system:serviceaccounts:openshift-platformer]`
    where that namespace is absent — baseline, not actionable."""
    idx = make_index(
        sccs=[_scc("custom",
                   groups=["system:serviceaccounts:openshift-platformer"])],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    assert rows[0]["baseline"] is True
    assert rows[0]["namespace"] == "openshift-platformer"


def test_direct_scc_groups_normal_ns_is_actionable():
    """`scc.groups = [system:serviceaccounts:tenant-x]` with tenant-x
    missing — developer-creatable, actionable."""
    idx = make_index(
        sccs=[_scc("privileged",
                   allowPrivilegedContainer=True,
                   groups=["system:serviceaccounts:tenant-x"])],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    assert rows[0]["baseline"] is False
    assert rows[0]["baseline_reason"] is None
    assert rows[0]["severity"] == "critical"


def test_rbac_scc_use_grant_openshift_ns_is_baseline():
    """`oc adm policy add-scc-to-group privileged
    system:serviceaccounts:openshift-foo` shape — even with privileged
    SCC, openshift-* is admission-protected so it's baseline noise."""
    idx = make_index(
        sccs=[_scc("privileged", allowPrivilegedContainer=True, groups=[])],
        cluster_roles=[_scc_use_clusterrole("privileged")],
        crbs=[{"name": "scc-priv-to-openshift-foo",
               "subjects": [{"kind": "Group",
                              "name": "system:serviceaccounts:openshift-foo"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:privileged"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    assert rows[0]["baseline"] is True
    assert rows[0]["namespace"] == "openshift-foo"


def test_rbac_scc_use_grant_normal_ns_is_actionable_critical():
    """The exact seeded SCC-resurrection scenario:
    `oc adm policy add-scc-to-group privileged
    system:serviceaccounts:lineage-scc-resurrection-demo` — developer
    CAN create the namespace. Must surface as actionable critical."""
    idx = make_index(
        sccs=[_scc("privileged", allowPrivilegedContainer=True, groups=[])],
        cluster_roles=[_scc_use_clusterrole("privileged")],
        crbs=[{"name": "system:openshift:scc:privileged",
               "subjects": [{"kind": "Group",
                              "name": "system:serviceaccounts:lineage-scc-resurrection-demo"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:privileged"}}],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    assert len(rows) == 1
    assert rows[0]["baseline"] is False
    assert rows[0]["severity"] == "critical"


def test_identity_audit_actionable_and_baseline_split():
    """identity_audit must return both splits explicitly so callers
    don't have to recompute the partition."""
    idx = make_index(
        sccs=[_scc("privileged",
                   allowPrivilegedContainer=True,
                   groups=["system:serviceaccounts:tenant-y"])],
        crbs=[
            # actionable critical
            {"name": "actionable-crb",
             "subjects": [{"kind": "ServiceAccount",
                            "name": "pipeline-admin",
                            "namespace": "lineage-dev-escalation-demo"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}},
            # baseline noise
            {"name": "platform-crb",
             "subjects": [{"kind": "ServiceAccount",
                            "name": "prometheus-k8s",
                            "namespace": "openshift-monitoring"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}},
        ],
        cluster_roles=[_cluster_admin_role()],
    )
    a = engine.identity_audit(idx)
    assert "resurrectable_actionable" in a
    assert "resurrectable_baseline" in a
    assert "resurrectable_implicit_actionable" in a
    assert "resurrectable_implicit_baseline" in a
    assert len(a["resurrectable_actionable"]) == 1
    assert len(a["resurrectable_baseline"]) == 1
    assert len(a["resurrectable_implicit_actionable"]) == 1
    # `total` reflects ACTIONABLE only — baseline shouldn't push the
    # home review-items tile.
    only_baseline_idx = make_index(
        sccs=[_scc("custom",
                   groups=["system:serviceaccounts:openshift-platformer"])],
        crbs=[{"name": "platform-only",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "prometheus-k8s",
                              "namespace": "openshift-monitoring"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
        cluster_roles=[_cluster_admin_role()],
    )
    only_baseline = engine.identity_audit(only_baseline_idx)
    assert only_baseline["total"] == 0


def test_home_card_zero_actionable_even_when_baseline_exists(monkeypatch):
    """The home Resurrectable card must show 0 (and link safely) when
    every resurrectable is baseline — the clean-CRC contract."""
    idx = make_index(
        # 16-style platform SA in openshift-monitoring — baseline
        crbs=[{"name": "platform-only",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "prometheus-k8s",
                              "namespace": "openshift-monitoring"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        cluster_roles=[{"name": "view", "labels": {}, "annotations": {},
                         "aggregationRule": None,
                         "rules": [{"apiGroups": [""], "resources": ["pods"],
                                    "verbs": ["get"]}]}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/").data.decode()

    # Card num must be 0, label "resurrectable" (not "critical")
    import re
    m = re.search(
        r'<div class="num">(\d+)</div>\s*'
        r'<div class="lab">(critical resurrectable|high resurrectable|resurrectable)</div>',
        body)
    assert m is not None
    assert m.group(1) == "0"
    assert m.group(2) == "resurrectable"
    # Baseline residue is still surfaced in the sub-line
    assert "1 baseline" in body
    # Click destination is safe — severity=all so reviewer can find baseline
    assert 'href="/identity-audit?severity=all#resurrectable"' in body


def test_home_card_actionable_critical_dominates_baseline(monkeypatch):
    """When there's even ONE actionable critical, the card must show
    critical — baseline must never demote the card's severity."""
    idx = make_index(
        sccs=[_scc("privileged", allowPrivilegedContainer=True,
                   # mix one baseline + one actionable
                   groups=["system:serviceaccounts:openshift-foo",
                            "system:serviceaccounts:tenant-x"])],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/").data.decode()
    # Card num = 1 (the actionable critical), label "critical resurrectable"
    import re
    m = re.search(
        r'<div class="num">(\d+)</div>\s*'
        r'<div class="lab">critical resurrectable</div>',
        body)
    assert m is not None
    assert m.group(1) == "1"
    # Sub-line: 0 SA · 1 SCC group · 1 baseline
    assert "0 SAs · 1 SCC group · 1 baseline" in body


def test_limited_view_still_returns_empty_no_false_baseline(monkeypatch):
    """is_admin=False short-circuits BEFORE we run the baseline check.
    No row, baseline or otherwise, should leak out under restricted
    visibility (the namespace might just be unreadable, not deleted)."""
    idx = make_index(
        sccs=[_scc("privileged", allowPrivilegedContainer=True,
                   groups=["system:serviceaccounts:openshift-foo",
                            "system:serviceaccounts:tenant-x"])],
    )
    idx["is_admin"] = False
    assert engine.resurrectable_implicit_scc_groups(idx) == []
    # SA family also short-circuits under is_admin=False
    assert engine.resurrectable_sa_identities(idx) == []


def test_cli_json_carries_baseline_flag_and_split_counts():
    """CLI JSON must annotate baseline rows and expose actionable vs
    baseline counts in the summary, so jq pipelines can filter."""
    from lineage.cli import collect_findings
    idx = make_index(
        sccs=[_scc("privileged", allowPrivilegedContainer=True,
                   groups=["system:serviceaccounts:openshift-foo",
                            "system:serviceaccounts:tenant-x"])],
        crbs=[
            {"name": "actionable-crb",
             "subjects": [{"kind": "ServiceAccount",
                            "name": "pipeline-admin",
                            "namespace": "lineage-dev-escalation-demo"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}},
            {"name": "platform-crb",
             "subjects": [{"kind": "ServiceAccount",
                            "name": "prometheus-k8s",
                            "namespace": "openshift-monitoring"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
        ],
        cluster_roles=[
            _cluster_admin_role(),
            {"name": "view", "labels": {}, "annotations": {},
             "aggregationRule": None,
             "rules": [{"apiGroups": [""], "resources": ["pods"],
                        "verbs": ["get"]}]},
        ],
    )
    f = collect_findings(idx)
    # Each row carries `baseline` (true/false) + reason
    for r in f["anomalies"]["resurrectable_sas"]:
        assert "baseline" in r
    for r in f["anomalies"]["resurrectable_implicit_groups"]:
        assert "baseline" in r
    # Summary exposes actionable vs baseline counts
    s = f["summary"]
    assert s["resurrectable_sas_actionable"] == 1
    assert s["resurrectable_sas_baseline"] == 1
    assert s["resurrectable_implicit_actionable"] == 1
    assert s["resurrectable_implicit_baseline"] == 1


def test_direct_and_rbac_paths_emit_separate_rows_for_same_scc_ns():
    """If both shapes exist for the same (scc, missing-ns), both must
    appear so the admin can see they have two separate grants to remove
    (deleting one doesn't address the other)."""
    idx = make_index(
        sccs=[_scc("privileged",
                   allowPrivilegedContainer=True,
                   groups=["system:serviceaccounts:double-grant"])],
        cluster_roles=[_scc_use_clusterrole("privileged")],
        crbs=[{
            "name": "scc-priv-to-double-grant",
            "subjects": [{"kind": "Group",
                          "name": "system:serviceaccounts:double-grant"}],
            "roleRef": {"kind": "ClusterRole",
                        "name": "system:openshift:scc:privileged"},
        }],
    )
    rows = engine.resurrectable_implicit_scc_groups(idx)
    # Two rows, both critical, different source_kind
    assert len(rows) == 2
    source_kinds = sorted(r["source_kind"] for r in rows)
    assert source_kinds == ["rbac.use", "scc.groups"]
