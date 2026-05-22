"""Test fixtures."""

import os
import sys

# Ensure tests run with mock data and the package is importable
os.environ["LINEAGE_MOCK"] = "1"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from lineage import engine as _engine


@pytest.fixture
def view_role():
    return {
        "name": "view", "labels": {}, "annotations": {},
        "aggregationRule": None,
        "rules": [{"apiGroups": [""], "resources": ["pods"],
                   "verbs": ["get", "list", "watch"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def admin_aggregated():
    return {
        "name": "admin", "labels": {}, "annotations": {},
        "aggregationRule": {
            "clusterRoleSelectors": [
                {"matchLabels": {"rbac.authorization.k8s.io/aggregate-to-admin": "true"}}
            ]
        },
        "rules": [],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def admin_workloads():
    return {
        "name": "admin-workloads",
        "labels": {"rbac.authorization.k8s.io/aggregate-to-admin": "true"},
        "annotations": {},
        "aggregationRule": None,
        "rules": [
            {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["*"]},
            {"apiGroups": [""], "resources": ["pods", "secrets"], "verbs": ["*"]},
        ],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }


@pytest.fixture
def cluster_admin_role():
    return {
        "name": "cluster-admin", "labels": {}, "annotations": {},
        "aggregationRule": None,
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }


def make_index(*, users=None, groups=None, namespaces=None, sas=None,
               identities=None, cluster_roles=None, roles=None,
               crbs=None, rbs=None, pods=None, sccs=None,
               htpasswd_users=None, htpasswd_available=True,
               htpasswd_configured=None, htpasswd_reason=None,
               oauth_cluster=None, imagestreams=None):
    """Build a fake engine index for tests, mirroring engine.index() shape."""
    users = users or []
    groups = groups or []
    namespaces = namespaces or []
    sas = sas or []
    identities = identities or []
    cluster_roles = cluster_roles or []
    roles = roles or []
    crbs = crbs or []
    rbs = rbs or []
    pods = pods or []
    sccs = sccs or []
    htpasswd_users = htpasswd_users or []
    oauth_cluster = oauth_cluster or {"identityProviders": []}
    imagestreams = imagestreams or []

    idents_by_user = {}
    for i in identities:
        u = (i.get("user") or {}).get("name", "")
        if u:
            idents_by_user.setdefault(u, []).append(i)

    return {
        "users_by_name": {u["name"]: u for u in users},
        "groups_by_name": {g["name"]: g for g in groups},
        "namespaces_by_name": {n["name"]: n for n in namespaces},
        "sas_by_key": {(s["namespace"], s["name"]): s for s in sas},
        "identities": identities,
        "identities_by_user": idents_by_user,
        "cluster_roles_by_name": {c["name"]: c for c in cluster_roles},
        "roles_by_key": {(r["namespace"], r["name"]): r for r in roles},
        "all_bindings": _engine._all_bindings(crbs, rbs),
        "pods": pods,
        "sccs_by_name": {s["name"]: s for s in sccs},
        "htpasswd_users": htpasswd_users,
        "htpasswd_available": htpasswd_available,
        "htpasswd_configured": bool(htpasswd_users) if htpasswd_configured is None
                                else htpasswd_configured,
        "htpasswd_reason": htpasswd_reason,
        "oauth_cluster": oauth_cluster,
        "imagestreams": imagestreams,
    }


@pytest.fixture
def make_idx():
    return make_index


def scc_use_clusterrole(scc_name):
    """ClusterRole shape that `oc adm policy add-scc-to-*` writes — also
    used to grant `use` on an SCC name that does not exist yet."""
    return {
        "name": f"system:openshift:scc:{scc_name}",
        "labels": {}, "annotations": {}, "aggregationRule": None,
        "rules": [{"apiGroups": ["security.openshift.io"],
                   "resources": ["securitycontextconstraints"],
                   "verbs": ["use"],
                   "resourceNames": [scc_name]}],
        "creationTimestamp": "2024-01-01T00:00:00Z",
    }
