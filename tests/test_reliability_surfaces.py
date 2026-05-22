"""Pre-release reliability surfaces.

Covers two things a non-admin / read-failing reviewer should not have to
guess at:
  - Limited-view (is_admin=False) routes must visibly warn rather than
    let empty tables read as 'clean cluster'.
  - oc fetch errors must be surfaced on /setup so an empty resource list
    reads as 'we couldn't read it' rather than 'nothing exists'.
"""

from lineage.main import app
from .conftest import make_index


# ---------- Cache TTL visibility ---------- #

def test_live_cache_ttl_is_named_and_set_to_five_minutes():
    """Cache TTL is 5 minutes (300 s). Tuned long enough to absorb a
    normal review sitting on one warm index; short enough that a manual
    cluster change isn't masked for an entire session. Manual
    /refresh always invalidates immediately regardless of TTL."""
    from lineage import cluster, data

    assert cluster.CACHE_TTL_SECONDS == 300
    assert data.CACHE_TTL_SECONDS == 300


def test_refresh_tooltip_shows_cache_ttl_label():
    """Header refresh button surfaces the TTL using a human label so the
    user understands when their next page load might re-fetch."""
    with app.test_client() as client:
        body = client.get("/").data.decode()

    assert "cache TTL: 5 min" in body
    assert 'method="post" action="/refresh"' in body


def test_refresh_requires_post(monkeypatch):
    from lineage import main as main_module
    called = {"value": False}
    monkeypatch.setattr(
        main_module.data,
        "invalidate_cache",
        lambda: called.__setitem__("value", True),
    )

    with app.test_client() as client:
        response = client.get("/refresh")

    assert response.status_code == 405
    assert called["value"] is False


def test_refresh_redirects_to_safe_local_path(monkeypatch):
    from lineage import main as main_module
    called = {"value": False}
    monkeypatch.setattr(
        main_module.data,
        "invalidate_cache",
        lambda: called.__setitem__("value", True),
    )

    with app.test_client() as client:
        response = client.post("/refresh", data={"next": "/subjects?bucket=all"})

    assert response.status_code == 302
    assert response.headers["Location"] == "/subjects?bucket=all"
    assert called["value"] is True


def test_refresh_rejects_external_redirect(monkeypatch):
    from lineage import main as main_module
    monkeypatch.setattr(main_module.data, "invalidate_cache", lambda: None)

    with app.test_client() as client:
        response = client.post(
            "/refresh",
            data={"next": "https://example.invalid/phish"},
        )

    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_deploy_manifest_sets_container_security_context():
    manifest = open("deploy/openshift/30-deployment.yaml").read()
    assert "securityContext:" in manifest
    assert "runAsNonRoot: true" in manifest
    assert "allowPrivilegeEscalation: false" in manifest
    assert "drop:" in manifest
    assert "- ALL" in manifest
    assert "type: RuntimeDefault" in manifest


def test_containerfile_runs_as_non_root():
    containerfile = open("Containerfile").read()
    assert "PYTHONDONTWRITEBYTECODE=1" in containerfile
    assert "HOME=/tmp" in containerfile
    assert "\nUSER 1001\n" in containerfile


# ---------- Limited-view banner on /identity-audit ---------- #

def test_identity_audit_warns_when_non_admin(monkeypatch):
    """is_admin=False should surface the limited-view banner so 0-count
    tables aren't misread as a clean cluster."""
    idx = make_index()
    idx["is_admin"] = False
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    monkeypatch.setattr(
        main_module.data, "live_status",
        lambda: {"ok": True, "user": "alice", "server": "(mock)",
                 "version": "mock", "mock": True, "is_admin": False},
    )

    with app.test_client() as client:
        body = client.get("/identity-audit").data.decode()

    assert "Limited view" in body
    # And the audit dataset is indeed empty (admin-gated paths return [])
    # — the warning is the only thing telling the reviewer it's not clean.
    assert "Needs cluster-admin to read all Users" in body


# ---------- Fetch-error visibility on /setup ---------- #

def test_setup_page_lists_fetch_errors(monkeypatch):
    """When cluster.fetch_errors() reports a failure, /setup must show
    it so an empty resource list isn't misread as 'nothing exists'."""
    errors = [
        {"key": "users", "kind": "users", "namespace": None,
         "error": "forbidden: User \"alice\" cannot list resource \"users\""},
        {"key": "pods:demo", "kind": "pods", "namespace": "demo",
         "error": "Forbidden"},
    ]
    from lineage import main as main_module
    monkeypatch.setattr(main_module.data, "fetch_errors", lambda: errors)

    with app.test_client() as client:
        body = client.get("/setup").data.decode()

    assert "resource reads returned an error" in body
    assert "users" in body
    assert "cannot list resource" in body
    # Per-namespace fetch shows its scope so reviewers can tell which
    # project lost which read.
    assert "namespace <code>demo</code>" in body


def test_setup_page_omits_fetch_errors_when_clean(monkeypatch):
    from lineage import main as main_module
    monkeypatch.setattr(main_module.data, "fetch_errors", lambda: [])
    with app.test_client() as client:
        body = client.get("/setup").data.decode()
    assert "resource reads returned an error" not in body


# ---------- Direct cluster.fetch_errors() behavior ---------- #

def test_cluster_fetch_errors_walks_cache():
    """Inject a cache entry with _error and verify fetch_errors() picks
    it up. Mock data path is intentionally exercised via the cluster
    module directly so we don't rely on the live oc CLI."""
    from lineage import cluster
    with cluster._lock:
        cluster._cache["users"] = {
            "ts": 0,
            "data": {"items": [], "_error": "forbidden"},
        }
        cluster._cache["pods:demo"] = {
            "ts": 0,
            "data": {"items": [], "_error": "Forbidden"},
        }
        cluster._cache["roles"] = {
            "ts": 0,
            "data": {"items": [{"metadata": {"name": "view"}}]},
        }
    try:
        out = cluster.fetch_errors()
    finally:
        with cluster._lock:
            cluster._cache.clear()
    kinds = {(e["kind"], e["namespace"]) for e in out}
    assert ("users", None) in kinds
    assert ("pods", "demo") in kinds
    # No false entry for the successful 'roles' fetch.
    assert all(e["kind"] != "roles" for e in out)
