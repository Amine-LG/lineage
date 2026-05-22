"""Newest-first sorting regression tests.

The SCCs page already pins this behavior in test_ui_polish.py. This file
extends the same contract to every other table whose row data carries a
creationTimestamp:

* /namespaces (was: tier-first)
* /namespace/<ns> SA / pod / RoleBinding tables (was: name only)
* /clusterroles (was: privileged-first / binding-count)
* /roles (was: baseline-first / binding-count)
* SA-detail engine helpers: jobs_for_sa, cronjobs_for_sa,
  bindings_referencing_sa (were: name-only or no sort)

Missing-timestamp rows must sort LAST so an empty/None creationTimestamp
never crashes the page and never silently jumps to the top.
"""

from lineage import engine
from lineage.main import app
from .conftest import make_index


# ---------- helpers ---------- #

def _ns(name, ts):
    return {"name": name, "labels": {}, "annotations": {},
            "creationTimestamp": ts}


def _cr(name, ts):
    return {"name": name, "labels": {}, "annotations": {},
            "aggregationRule": None, "rules": [], "creationTimestamp": ts}


def _role(ns, name, ts):
    return {"namespace": ns, "name": name, "rules": [],
            "creationTimestamp": ts}


def _sa(ns, name, ts):
    return {"namespace": ns, "name": name, "labels": {},
            "creationTimestamp": ts, "ownerReferences": []}


def _pod(ns, name, ts, *, sa="default"):
    return {"namespace": ns, "name": name, "labels": {}, "annotations": {},
            "ownerReferences": [], "spec": {"serviceAccountName": sa},
            "phase": "Running", "containerStatuses": [],
            "creationTimestamp": ts}


def _rb(ns, name, ts, *, sa_name="alice", sa_ns="alice-ns"):
    return {"name": name, "namespace": ns, "labels": {}, "annotations": {},
            "subjects": [{"kind": "ServiceAccount",
                          "name": sa_name, "namespace": sa_ns}],
            "roleRef": {"kind": "ClusterRole", "name": "view"},
            "creationTimestamp": ts}


# ---------- /namespaces ---------- #

def test_namespaces_page_sorts_newest_first(monkeypatch):
    idx = make_index(namespaces=[
        _ns("oldest-ns", "2024-01-01T00:00:00Z"),
        _ns("middle-ns", "2024-06-01T00:00:00Z"),
        _ns("newest-ns", "2025-12-31T00:00:00Z"),
    ])
    idx["fetch_error_kinds"] = set()
    idx["is_admin"] = True
    idx["current_user"] = "kubeadmin"
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/namespaces?category=all").data.decode()

    p_newest = body.index("/namespace/newest-ns")
    p_middle = body.index("/namespace/middle-ns")
    p_oldest = body.index("/namespace/oldest-ns")
    assert p_newest < p_middle < p_oldest


def test_namespaces_page_missing_ts_sorts_last(monkeypatch):
    idx = make_index(namespaces=[
        _ns("dated-ns", "2025-01-01T00:00:00Z"),
        _ns("no-ts-ns", None),
    ])
    idx["fetch_error_kinds"] = set()
    idx["is_admin"] = True
    idx["current_user"] = "kubeadmin"
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/namespaces?category=all").data.decode()
    assert body.index("/namespace/dated-ns") < body.index("/namespace/no-ts-ns")


# ---------- /clusterroles ---------- #

def test_clusterroles_page_sorts_newest_first(monkeypatch):
    idx = make_index(cluster_roles=[
        _cr("oldest-cr", "2024-01-01T00:00:00Z"),
        _cr("middle-cr", "2024-06-01T00:00:00Z"),
        _cr("newest-cr", "2025-12-31T00:00:00Z"),
    ])
    idx["fetch_error_kinds"] = set()
    idx["is_admin"] = True
    idx["current_user"] = "kubeadmin"
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/clusterroles").data.decode()

    p_newest = body.index("/clusterrole/newest-cr")
    p_middle = body.index("/clusterrole/middle-cr")
    p_oldest = body.index("/clusterrole/oldest-cr")
    assert p_newest < p_middle < p_oldest


def test_clusterroles_missing_ts_sorts_last(monkeypatch):
    idx = make_index(cluster_roles=[
        _cr("dated-cr", "2025-01-01T00:00:00Z"),
        _cr("no-ts-cr", None),
    ])
    idx["fetch_error_kinds"] = set()
    idx["is_admin"] = True
    idx["current_user"] = "kubeadmin"
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/clusterroles").data.decode()
    assert body.index("/clusterrole/dated-cr") < body.index("/clusterrole/no-ts-cr")


# ---------- /roles ---------- #

def test_roles_page_sorts_newest_first(monkeypatch):
    idx = make_index(
        namespaces=[_ns("team-a", "2024-01-01T00:00:00Z")],
        roles=[
            _role("team-a", "oldest-role", "2024-01-01T00:00:00Z"),
            _role("team-a", "middle-role", "2024-06-01T00:00:00Z"),
            _role("team-a", "newest-role", "2025-12-31T00:00:00Z"),
        ],
    )
    idx["fetch_error_kinds"] = set()
    idx["is_admin"] = True
    idx["current_user"] = "kubeadmin"
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/roles?bucket=all").data.decode()

    p_newest = body.index("/role/team-a/newest-role")
    p_middle = body.index("/role/team-a/middle-role")
    p_oldest = body.index("/role/team-a/oldest-role")
    assert p_newest < p_middle < p_oldest


# ---------- /namespace/<ns> ---------- #

def test_namespace_detail_sa_table_sorts_newest_first(monkeypatch):
    idx = make_index(
        namespaces=[_ns("team-a", "2024-01-01T00:00:00Z")],
        sas=[
            _sa("team-a", "oldest-sa", "2024-01-01T00:00:00Z"),
            _sa("team-a", "middle-sa", "2024-06-01T00:00:00Z"),
            _sa("team-a", "newest-sa", "2025-12-31T00:00:00Z"),
        ],
    )
    idx["fetch_error_kinds"] = set()
    idx["is_admin"] = True
    idx["current_user"] = "kubeadmin"
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/namespace/team-a").data.decode()

    p_newest = body.index("newest-sa")
    p_middle = body.index("middle-sa")
    p_oldest = body.index("oldest-sa")
    assert p_newest < p_middle < p_oldest


def test_namespace_detail_pod_table_sorts_newest_first(monkeypatch):
    idx = make_index(
        namespaces=[_ns("team-a", "2024-01-01T00:00:00Z")],
        pods=[
            _pod("team-a", "oldest-pod", "2024-01-01T00:00:00Z"),
            _pod("team-a", "newest-pod", "2025-12-31T00:00:00Z"),
        ],
    )
    idx["fetch_error_kinds"] = set()
    idx["is_admin"] = True
    idx["current_user"] = "kubeadmin"
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/namespace/team-a").data.decode()
    assert body.index("newest-pod") < body.index("oldest-pod")


def test_namespace_detail_rolebinding_table_sorts_newest_first(monkeypatch):
    idx = make_index(
        namespaces=[_ns("team-a", "2024-01-01T00:00:00Z")],
        rbs=[
            _rb("team-a", "oldest-rb", "2024-01-01T00:00:00Z"),
            _rb("team-a", "newest-rb", "2025-12-31T00:00:00Z"),
        ],
    )
    idx["fetch_error_kinds"] = set()
    idx["is_admin"] = True
    idx["current_user"] = "kubeadmin"
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/namespace/team-a").data.decode()
    # The "RoleBindings on this namespace" table renders names as
    # `RoleBinding/<name>`; sort is on the row's creationTimestamp.
    assert body.index("newest-rb") < body.index("oldest-rb")


# ---------- engine helpers feeding /subject/ServiceAccount/<name> ---------- #

def test_jobs_for_sa_sorts_newest_first():
    idx = make_index(sas=[_sa("team-a", "ci", "2024-01-01T00:00:00Z")])
    idx["jobs"] = [
        {"namespace": "team-a", "name": "oldest-job",
         "creationTimestamp": "2024-01-01T00:00:00Z",
         "ownerReferences": [],
         "spec": {"template": {"spec": {"serviceAccountName": "ci"}}}},
        {"namespace": "team-a", "name": "newest-job",
         "creationTimestamp": "2025-12-31T00:00:00Z",
         "ownerReferences": [],
         "spec": {"template": {"spec": {"serviceAccountName": "ci"}}}},
        {"namespace": "team-a", "name": "no-ts-job",
         "creationTimestamp": None,
         "ownerReferences": [],
         "spec": {"template": {"spec": {"serviceAccountName": "ci"}}}},
    ]
    rows = engine.jobs_for_sa("ci", "team-a", idx)
    names = [r["name"] for r in rows]
    assert names == ["newest-job", "oldest-job", "no-ts-job"]


def test_cronjobs_for_sa_sorts_newest_first():
    idx = make_index(sas=[_sa("team-a", "ci", "2024-01-01T00:00:00Z")])
    idx["cronjobs"] = [
        {"namespace": "team-a", "name": "oldest-cj",
         "creationTimestamp": "2024-01-01T00:00:00Z",
         "spec": {"jobTemplate": {"spec": {"template":
            {"spec": {"serviceAccountName": "ci"}}}}}},
        {"namespace": "team-a", "name": "newest-cj",
         "creationTimestamp": "2025-12-31T00:00:00Z",
         "spec": {"jobTemplate": {"spec": {"template":
            {"spec": {"serviceAccountName": "ci"}}}}}},
        {"namespace": "team-a", "name": "no-ts-cj",
         "creationTimestamp": None,
         "spec": {"jobTemplate": {"spec": {"template":
            {"spec": {"serviceAccountName": "ci"}}}}}},
    ]
    rows = engine.cronjobs_for_sa("ci", "team-a", idx)
    names = [r["name"] for r in rows]
    assert names == ["newest-cj", "oldest-cj", "no-ts-cj"]


def test_bindings_referencing_sa_sorts_newest_first():
    idx = make_index(
        sas=[_sa("team-a", "ci", "2024-01-01T00:00:00Z")],
        rbs=[
            {"name": "older-rb", "namespace": "team-a",
             "subjects": [{"kind": "ServiceAccount",
                           "name": "ci", "namespace": "team-a"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"},
             "creationTimestamp": "2024-01-01T00:00:00Z"},
            {"name": "newer-rb", "namespace": "team-a",
             "subjects": [{"kind": "ServiceAccount",
                           "name": "ci", "namespace": "team-a"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"},
             "creationTimestamp": "2025-12-31T00:00:00Z"},
            {"name": "no-ts-rb", "namespace": "team-a",
             "subjects": [{"kind": "ServiceAccount",
                           "name": "ci", "namespace": "team-a"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"},
             "creationTimestamp": None},
        ],
    )
    out = engine.bindings_referencing_sa("ci", "team-a", idx)
    names = [e["name"] for e in out["rbs_same_ns"]]
    assert names == ["newer-rb", "older-rb", "no-ts-rb"]
