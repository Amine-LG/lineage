"""Aggregated ClusterRole page rendering tests."""

from lineage.main import app
from .conftest import make_index


def _aggregated(name, created, label):
    return {
        "name": name,
        "labels": {},
        "annotations": {},
        "creationTimestamp": created,
        "aggregationRule": {
            "clusterRoleSelectors": [{"matchLabels": {label: "true"}}],
        },
        "rules": [],
    }


def _component(name, created, label):
    return {
        "name": name,
        "labels": {label: "true"},
        "annotations": {},
        "creationTimestamp": created,
        "aggregationRule": None,
        "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
    }


def test_aggregated_page_orders_roles_and_components_by_creation(monkeypatch):
    idx = make_index(cluster_roles=[
        _aggregated("view", "2024-01-01T00:00:00Z",
                    "rbac.authorization.k8s.io/aggregate-to-view"),
        _aggregated("admin", "2024-02-01T00:00:00Z",
                    "rbac.authorization.k8s.io/aggregate-to-admin"),
        _component("admin-old", "2024-01-10T00:00:00Z",
                   "rbac.authorization.k8s.io/aggregate-to-admin"),
        _component("admin-new", "2024-03-01T00:00:00Z",
                   "rbac.authorization.k8s.io/aggregate-to-admin"),
        _component("view-component", "2024-01-15T00:00:00Z",
                   "rbac.authorization.k8s.io/aggregate-to-view"),
    ])

    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        response = client.get("/aggregated")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "newest first by creation date" in body
    assert body.index('<a href="/clusterrole/admin">admin</a>') < body.index(
        '<a href="/clusterrole/view">view</a>')
    assert body.index('<a href="/clusterrole/admin-new">admin-new</a>') < body.index(
        '<a href="/clusterrole/admin-old">admin-old</a>')
    assert '<details class="agg-card">' in body
    assert "Role details" in body


def test_aggregated_page_renders_match_expressions(monkeypatch):
    idx = make_index(cluster_roles=[
        {
            "name": "expr-agg",
            "labels": {},
            "annotations": {},
            "creationTimestamp": "2024-02-01T00:00:00Z",
            "aggregationRule": {
                "clusterRoleSelectors": [{
                    "matchExpressions": [
                        {"key": "lineage.test/aggregate",
                         "operator": "In", "values": ["yes"]},
                        {"key": "lineage.test/missing",
                         "operator": "DoesNotExist"},
                    ],
                }],
            },
            "rules": [],
        },
        {
            "name": "expr-component",
            "labels": {"lineage.test/aggregate": "yes"},
            "annotations": {},
            "creationTimestamp": "2024-03-01T00:00:00Z",
            "aggregationRule": None,
            "rules": [{"apiGroups": [""], "resources": ["pods"],
                       "verbs": ["get"]}],
        },
    ])

    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        response = client.get("/aggregated")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "lineage.test/aggregate in (yes)" in body
    assert "lineage.test/missing does not exist" in body
    assert "lineage.test/missing=&lt;absent&gt;" in body
