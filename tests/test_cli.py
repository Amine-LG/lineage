"""CLI regression tests."""

from lineage import cli
from lineage.main import app
from .conftest import make_index


def test_render_text_handles_current_identity_audit_shape():
    findings = {
        "cluster": {"ok": True, "user": "alice", "server": "(mock)", "is_admin": True},
        "anomalies": {
            "latent_users": [
                {"username": "tom", "source": "htpasswd",
                 "detail": "in Secret openshift-config/htpasswd-secret (idp=dev)"}
            ],
            "phantom_users": [
                {"name": "bob", "reasons": ["removed from htpasswd (dev)"]}
            ],
            "bound_ghosts": [],
            "stranded_users": [],
            "orphan_identities": [],
            "resurrectable_sas": [
                {"principal": "system:serviceaccount:ci:pipeline",
                 "namespace": "ci", "name": "pipeline",
                 "namespace_present": True, "severity": "critical",
                 "grant_count": 1}
            ],
        },
        "summary": {
            "privileged_user_subjects": 0,
            "privileged_baseline_subjects": 0,
            "duplicate_user_bindings": 0,
            "anomalies_total": 3,
            "real_anomalies_present": True,
        },
    }

    text = cli.render_text(findings)

    assert "tom" in text
    assert "phantom users" in text
    assert "system:serviceaccount:ci:pipeline" in text


def test_collect_findings_includes_resurrectable_sas():
    idx = make_index(
        namespaces=[{"name": "ci", "labels": {}, "annotations": {}}],
        cluster_roles=[{"name": "cluster-admin", "labels": {}, "annotations": {},
                        "aggregationRule": None,
                        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}],
        crbs=[{"name": "ci-pipeline-clusteradmin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "pipeline", "namespace": "ci"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )

    findings = cli.collect_findings(idx)

    resurrectable = findings["anomalies"]["resurrectable_sas"]
    assert findings["summary"]["real_anomalies_present"] is True
    assert resurrectable[0]["principal"] == "system:serviceaccount:ci:pipeline"
    assert resurrectable[0]["severity"] == "critical"


def test_collect_findings_includes_resurrectable_implicit_scc_groups():
    idx = make_index(
        sccs=[{"name": "legacy-pipeline-root",
               "users": [],
               "groups": ["system:serviceaccounts:legacy-pipelines"],
               "allowPrivilegedContainer": False,
               "allowHostNetwork": False,
               "allowHostPID": False,
               "allowHostIPC": False,
               "allowPrivilegeEscalation": True,
               "runAsUser": {"type": "RunAsAny"},
               "creationTimestamp": "2025-01-01T00:00:00Z"}],
    )

    findings = cli.collect_findings(idx)

    groups = findings["anomalies"]["resurrectable_implicit_groups"]
    assert findings["summary"]["real_anomalies_present"] is True
    assert groups[0]["group"] == "system:serviceaccounts:legacy-pipelines"
    assert groups[0]["scc"] == "legacy-pipeline-root"
    assert "legacy-pipeline-root" in cli.render_text(findings)


def test_collect_findings_preserves_ghost_scc_target_fields():
    idx = make_index(
        cluster_roles=[{
            "name": "system:openshift:scc:missing-scc",
            "labels": {}, "annotations": {}, "aggregationRule": None,
            "rules": [{
                "apiGroups": ["security.openshift.io"],
                "resources": ["securitycontextconstraints"],
                "verbs": ["use"],
                "resourceNames": ["missing-scc"],
            }],
        }],
        crbs=[{
            "name": "system:openshift:scc:missing-scc",
            "subjects": [{"kind": "User", "name": "future-user"}],
            "roleRef": {"kind": "ClusterRole",
                        "name": "system:openshift:scc:missing-scc"},
        }],
    )

    findings = cli.collect_findings(idx)
    rows = findings["anomalies"]["resurrectable_implicit_groups"]

    assert rows[0]["kind"] == "ghost-scc-target"
    assert rows[0]["subject_kind"] == "User"
    assert rows[0]["subject_name"] == "future-user"
    assert rows[0]["scc"] == "missing-scc"


def test_render_text_distinguishes_ghost_scc_rows():
    findings = {
        "cluster": {"ok": True, "user": "alice", "server": "(mock)",
                    "is_admin": True},
        "anomalies": {
            "latent_users": [],
            "phantom_users": [],
            "bound_ghosts": [],
            "stranded_users": [],
            "orphan_identities": [],
            "resurrectable_sas": [],
            "resurrectable_implicit_groups": [
                {"kind": "ghost-scc-target", "scc": "future-root",
                 "severity": "low", "source": "ClusterRoleBinding/future-root",
                 "subject_kind": "User", "subject_name": "future-user",
                 "baseline": False},
                {"kind": "ghost-scc-subject", "scc": "privileged",
                 "severity": "critical",
                 "source": "ClusterRoleBinding/privileged-future-user",
                 "subject_kind": "User", "subject_name": "future-user",
                 "baseline": False},
                {"kind": "implicit-sa-group",
                 "group": "system:serviceaccounts:gone",
                 "namespace": "gone", "namespace_present": False,
                 "scc": "privileged", "severity": "critical",
                 "source": "SCC/privileged", "baseline": False},
            ],
        },
        "summary": {
            "privileged_user_subjects": 0,
            "privileged_baseline_subjects": 0,
            "duplicate_user_bindings": 0,
            "anomalies_total": 3,
            "real_anomalies_present": True,
        },
    }

    text = cli.render_text(findings)

    assert "SCC resurrectable/future grants" in text
    assert "future SCC/future-root for User/future-user" in text
    assert "missing User/future-user can use SCC/privileged" in text
    assert "system:serviceaccounts:gone via SCC/privileged" in text
    assert "None via SCC" not in text


def test_render_text_shows_source_for_duplicate_implicit_scc_groups():
    findings = {
        "cluster": {"ok": True, "user": "alice", "server": "(mock)",
                    "is_admin": True},
        "anomalies": {
            "latent_users": [],
            "phantom_users": [],
            "bound_ghosts": [],
            "stranded_users": [],
            "orphan_identities": [],
            "resurrectable_sas": [],
            "resurrectable_implicit_groups": [
                {"kind": "implicit-sa-group",
                 "group": "system:serviceaccounts:gone",
                 "namespace": "gone", "namespace_present": False,
                 "scc": "privileged", "severity": "critical",
                 "source": "SCC/privileged", "baseline": False},
                {"kind": "implicit-sa-group",
                 "group": "system:serviceaccounts:gone",
                 "namespace": "gone", "namespace_present": False,
                 "scc": "privileged", "severity": "critical",
                 "source": "ClusterRoleBinding/system:openshift:scc:privileged",
                 "baseline": False},
            ],
        },
        "summary": {
            "privileged_user_subjects": 0,
            "privileged_baseline_subjects": 0,
            "duplicate_user_bindings": 0,
            "anomalies_total": 2,
            "real_anomalies_present": True,
        },
    }

    text = cli.render_text(findings)

    assert "from SCC/privileged" in text
    assert "from ClusterRoleBinding/system:openshift:scc:privileged" in text


def test_clusterrole_detail_does_not_duplicate_bindings():
    with app.test_client() as client:
        response = client.get("/clusterrole/cluster-admin")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert body.count("ClusterRoleBinding/cluster-admin") == 1
