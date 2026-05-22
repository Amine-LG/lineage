"""Regression coverage for the bundled mock dataset."""

from lineage import engine
from lineage.main import app


def test_mock_dataset_has_roles_and_cross_namespace_access():
    idx = engine.index()

    assert ("mine-platform", "config-reader") in idx["roles_by_key"]
    assert ("mine-platform", "deployment-restarter") in idx["roles_by_key"]

    cross = engine.cross_namespace_bindings(idx)
    assert any(
        row["subject"]["namespace"] == "ci"
        and row["subject"]["name"] == "builder"
        and row["binding_namespace"] == "mine-platform"
        and row["role"] == "edit"
        for row in cross
    )

    pullers = engine.image_puller_grants(idx)
    assert any(
        row["role"] == "system:image-puller"
        and row["cross_namespace"]
        for row in pullers
    )
    assert any(
        row["role"] == "system:image-builder"
        and row["cross_namespace"]
        for row in pullers
    )


def test_mock_identity_audit_has_each_supported_anomaly_category():
    audit = engine.identity_audit(engine.index())

    latent_sources = {row["source"] for row in audit["latent_users"]}
    assert {"htpasswd", "group"} <= latent_sources
    assert audit["phantom_users"]
    assert audit["bound_ghosts"]
    assert audit["stranded_users"]
    assert audit["orphan_identities"]
    assert audit["resurrectable_sas"]
    assert audit["deleted_namespaces"]

    resurrectable = {
        (row["namespace"], row["name"]) for row in audit["resurrectable_sas"]
    }
    assert ("ci", "pipeline") in resurrectable
    assert ("legacy-pipelines", "runner") in resurrectable


def test_mock_aggregated_admin_clusterrole_expands_to_useful_rules():
    idx = engine.index()
    rules, components = engine.expand_aggregated_role(
        idx["cluster_roles_by_name"]["admin"], idx
    )
    component_names = {component["name"] for component in components}
    summary = engine.summarize_rules(rules)

    assert {"admin-storage", "admin-workloads", "admin-rbac"} <= component_names
    assert "secrets" in summary["resources"]
    assert "deployments" in summary["resources"]
    assert summary["total_rules"] >= 3


def test_mock_image_digest_drift_and_imagestream_usage_are_represented():
    idx = engine.index()

    drift = engine.image_drift(idx)
    assert any(
        row["image"] == "docker.io/library/nginx:1.25"
        and row["digest_count"] > 1
        for row in drift
    )

    streams = engine.imagestream_usage(idx)
    assert any(row["name"] == "api" and row["use_count"] > 0 for row in streams)
    assert any(row["name"] == "base" and row["use_count"] == 0 for row in streams)


def test_mock_namespace_classification_has_unknown_and_user_owned_projects():
    idx = engine.index()
    summaries = [engine.namespace_summary(ns, idx) for ns in engine.all_namespaces(idx)]

    assert any(row["category"] == "unknown" for row in summaries)
    assert any(row["category"] == "project" and row["user_owned"] for row in summaries)
    assert any(
        row["namespace"] == "mine-platform"
        and engine.is_mine_namespace(row, idx["current_user"])
        for row in summaries
    )


def test_mock_scc_access_includes_direct_and_rbac_use_grants():
    idx = engine.index()
    rows = engine.scc_potential_subjects("anyuid", idx)

    assert any(row["source"] == "SCC user list" for row in rows)
    assert any(row["source"] == "SCC group list" for row in rows)
    assert any(row["source"] == "RBAC use grant" for row in rows)
    assert any(
        row["kind"] == "ServiceAccount"
        and row["namespace"] == "mine-platform"
        and row["name"] == "builder"
        for row in rows
    )
    assert engine.pods_admitted_by_scc("anyuid", idx)


def test_mock_screenshot_routes_have_meaningful_content():
    route_expectations = {
        "/": ["Lineage", "resurrectable"],
        "/identity-audit": ["Latent users", "ServiceAccount identities"],
        "/subjects": ["eve", "pipeline"],
        "/subject/User/eve": ["engineers", "admin-rb", "secrets", "mine-platform"],
        "/roles": ["config-reader", "deployment-restarter"],
        "/clusterrole/admin": ["admin-workloads", "admin-rbac", "secrets"],
        "/cross-namespace": ["ci", "mine-platform", "system:image-puller"],
        "/sccs": ["anyuid", "privileged"],
        # The Subjects table defaults to kind=User; the SCC-user-list /
        # RBAC-use-grant rows live under the ServiceAccount + Group tabs.
        # Use ?subject_kind=all so the screenshot route shows every source.
        "/scc/anyuid?subject_kind=all": ["SCC user list", "RBAC use grant",
                                          "mine-platform"],
        "/namespaces": ["mine-platform"],
        "/namespace/mine-platform": ["Why this category", "builder", "anyuid"],
        "/images": ["Stale-by-digest", "ImageStreams", "api"],
        "/privileged": ["Resurrectable ServiceAccount", "cluster-admin"],
        "/permission-grants": ["admin-rb", "manual-approver"],
        "/who-can?verb=list&resource=secrets&namespace=mine-platform": [
            "eve",
            "engineers",
            "admin-rb",
        ],
        "/setup": ["ClusterRole", "auth can-i"],
    }

    with app.test_client() as client:
        for route, expected_text in route_expectations.items():
            response = client.get(route)
            body = response.get_data(as_text=True)

            assert response.status_code == 200, route
            for text in expected_text:
                assert text in body, route


