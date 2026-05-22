"""SCC detail tests."""

from lineage import engine
from lineage.main import app
from .conftest import make_index


def _scc(name, users=None, groups=None, privileged=False):
    return {
        "name": name,
        "priority": 10,
        "allowPrivilegedContainer": privileged,
        "allowHostNetwork": privileged,
        "allowHostPID": privileged,
        "allowHostIPC": privileged,
        "allowPrivilegeEscalation": privileged,
        "runAsUser": {"type": "RunAsAny" if privileged else "MustRunAsRange"},
        "creationTimestamp": "2024-01-01T00:00:00Z",
        "users": users or [],
        "groups": groups or [],
    }


def test_scc_potential_subjects_includes_direct_and_rbac_grants():
    use_privileged = {
        "name": "custom-use-privileged",
        "labels": {},
        "annotations": {},
        "aggregationRule": None,
        "rules": [{
            "apiGroups": ["security.openshift.io"],
            "resources": ["securitycontextconstraints"],
            "resourceNames": ["privileged"],
            "verbs": ["use"],
        }],
    }
    idx = make_index(
        namespaces=[{"name": "ci", "labels": {}, "annotations": {}}],
        sas=[{"name": "default", "namespace": "ci", "labels": {}}],
        sccs=[_scc(
            "privileged",
            users=["system:serviceaccount:gone:runner"],
            groups=["system:serviceaccounts:ci"],
            privileged=True,
        )],
        cluster_roles=[use_privileged],
        crbs=[{"name": "ci-pipeline-use-privileged",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "pipeline", "namespace": "ci"}],
               "roleRef": {"kind": "ClusterRole", "name": "custom-use-privileged"},
               "creationTimestamp": "2026-05-12T10:00:00Z"}],
    )

    rows = engine.scc_potential_subjects("privileged", idx)
    by_subject = {(r["kind"], r.get("namespace"), r["name"], r["source"]): r
                  for r in rows}

    direct = by_subject[("ServiceAccount", "gone", "runner", "SCC user list")]
    assert direct["resurrectable"] is True
    assert direct["state"] == "namespace deleted"

    rbac = by_subject[("ServiceAccount", "ci", "pipeline", "RBAC use grant")]
    assert rbac["resurrectable"] is True
    assert rbac["state"] == "SA missing"
    assert rbac["unknown"] is True
    assert rbac["creation_ts"] == "2026-05-12T10:00:00Z"
    assert rows[0]["source"] == "RBAC use grant"
    assert rows[0]["name"] == "pipeline"

    broad = by_subject[("Group", None, "system:serviceaccounts:ci", "SCC group list")]
    assert broad["broad"] is True
    assert broad["current_count"] == 1
    assert broad["unknown"] is True
    assert broad["baseline"] is False


def test_scc_potential_subjects_user_scc_binding_not_baseline_by_crb_name():
    """oc adm policy add-scc-to-user writes system:openshift:scc:* CRBs.
    The CRB name is platform-shaped, but a non-baseline subject is still
    actionable on the SCC detail page."""
    idx = make_index(
        users=[{"name": "alice"}],
        sccs=[_scc("custom-scc")],
        cluster_roles=[{
            "name": "system:openshift:scc:custom-scc",
            "labels": {}, "annotations": {}, "aggregationRule": None,
            "rules": [{
                "apiGroups": ["security.openshift.io"],
                "resources": ["securitycontextconstraints"],
                "resourceNames": ["custom-scc"],
                "verbs": ["use"],
            }],
        }],
        crbs=[{"name": "system:openshift:scc:custom-scc",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:custom-scc"}}],
    )

    rows = engine.scc_potential_subjects("custom-scc", idx)
    alice = next(r for r in rows if r["kind"] == "User"
                 and r["name"] == "alice")
    assert alice["source"] == "RBAC use grant"
    assert alice["baseline"] is False
    assert alice["unknown"] is False


def test_scc_potential_subjects_missing_scc_role_ref_is_not_live_access():
    """A binding to a missing system:openshift:scc:* ClusterRole grants
    nothing. The SCC detail page must not invent live SCC access."""
    idx = make_index(
        users=[{"name": "alice"}],
        sccs=[_scc("custom-scc")],
        crbs=[{"name": "orphan-scc-binding",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:custom-scc"}}],
    )

    rows = engine.scc_potential_subjects("custom-scc", idx)
    assert not any(r["kind"] == "User" and r["name"] == "alice"
                   for r in rows)


def test_scc_potential_subjects_scc_role_name_without_use_rule_ignored():
    """The role-name convention is not enough; the resolved role must
    actually grant use on the SCC."""
    idx = make_index(
        users=[{"name": "alice"}],
        sccs=[_scc("custom-scc")],
        cluster_roles=[{
            "name": "system:openshift:scc:custom-scc",
            "labels": {}, "annotations": {}, "aggregationRule": None,
            "rules": [{"apiGroups": [""],
                       "resources": ["pods"],
                       "verbs": ["get"]}],
        }],
        crbs=[{"name": "name-only-binding",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:custom-scc"}}],
    )

    rows = engine.scc_potential_subjects("custom-scc", idx)
    assert not any(r["kind"] == "User" and r["name"] == "alice"
                   for r in rows)


def test_scc_detail_page_shows_potential_subjects_table():
    # The Subjects-that-can-use table defaults to kind=User; the
    # resurrectable-SA row (forgotten-batch:runner) lives under the
    # ServiceAccount tab. Query it explicitly here.
    with app.test_client() as client:
        response = client.get(
            "/scc/privileged?subject_kind=ServiceAccount")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Subjects that can use this SCC" in body
    assert "forgotten-batch" in body
    assert "resurrectable" in body
    assert "Unclassified" in body
    assert "ServiceAccounts" in body


def test_scc_detail_subject_filters_are_linked():
    with app.test_client() as client:
        response = client.get(
            "/scc/anyuid?subject_bucket=all&subject_kind=ServiceAccount#scc-subjects"
        )

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'href="?subject_bucket=unknown&subject_kind=ServiceAccount#scc-subjects"' in body
    assert 'href="?subject_bucket=all&subject_kind=ServiceAccount#scc-subjects" class="active"' in body
    assert 'href="?subject_bucket=all&subject_kind=all#scc-subjects" class=""' in body
