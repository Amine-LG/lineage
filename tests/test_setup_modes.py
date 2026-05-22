"""Tests for the /setup page.

The page must:
* show the current session (mode, identity, server, version, cache)
* list the three runtime modes (local mock, local real, in-cluster)
* link to the deeper docs in /docs/
* never prescribe a fake `oc login --server=https://api.your-cluster…`
"""

from lineage.main import _current_mode, app


# ---------- mode classifier ---------- #

def test_mode_classifier_mock():
    assert _current_mode(
        {"ok": True, "user": "alice", "server": "(mock)",
         "version": "mock", "mock": True, "is_admin": True}
    ) == "mock"


def test_mode_classifier_in_cluster_via_sa_principal():
    assert _current_mode(
        {"ok": True,
         "user": "system:serviceaccount:lineage-incluster:lineage",
         "server": "https://10.0.0.1:443",
         "version": "4.19.8", "mock": False, "is_admin": True}
    ) == "in_cluster"


def test_mode_classifier_local_login():
    assert _current_mode(
        {"ok": True, "user": "kubeadmin", "server": "https://api.crc.testing:6443",
         "version": "4.19.8", "mock": False, "is_admin": True}
    ) == "local"


def test_mode_classifier_disconnected():
    assert _current_mode(
        {"ok": False, "error": "no kubeconfig", "mock": False, "is_admin": False}
    ) == "disconnected"


# ---------- /setup template rendering ---------- #

def test_setup_page_shows_three_runtime_modes():
    """The setup page lists the three runtime modes as bullets:
    Local — mock, Local — real cluster, In-cluster."""
    with app.test_client() as c:
        body = c.get("/setup").data.decode()
    assert ">Local — mock</strong>" in body
    assert ">Local — real cluster</strong>" in body
    assert ">In-cluster</strong>" in body


def test_setup_page_does_not_prescribe_fake_oc_login_url():
    """The old page hard-coded a fake api.your-cluster.example.com URL;
    that misled non-OpenShift readers and was the wrong shape on CRC.
    The new page must not ship a fake login example."""
    with app.test_client() as c:
        body = c.get("/setup").data.decode()
    assert "api.your-cluster" not in body.lower()


def test_setup_page_shows_current_session_block():
    """Mode / identity / server / version / cache must all be present in
    the rendered HTML so a reviewer can confirm what Lineage thinks it
    is looking at."""
    with app.test_client() as c:
        body = c.get("/setup").data.decode()
    assert ">Session<" in body
    assert ">Mode<" in body
    assert ">Identity<" in body
    assert ">Cluster<" in body
    assert ">OpenShift<" in body
    assert ">Cache<" in body


def test_setup_page_links_to_deeper_docs():
    """The page must point at the slim docs/ tree rather than
    re-explaining install steps inline forever."""
    with app.test_client() as c:
        body = c.get("/setup").data.decode()
    assert "docs/quickstart.md" in body
    assert "docs/in-cluster.md" in body
    assert "docs/permissions.md" in body


def test_setup_page_renders_under_mock_mode(monkeypatch):
    """Mock mode is the default for tests (conftest sets LINEAGE_MOCK=1).
    The page must render without crashing and label the mode chip."""
    with app.test_client() as c:
        body = c.get("/setup").data.decode()
    assert "mock" in body  # the mode chip


def test_setup_page_labels_in_cluster_mode(monkeypatch):
    """When the live_status user is an SA principal, the page labels the
    mode as in-cluster."""
    from lineage import main as main_module
    monkeypatch.setattr(
        main_module.data, "live_status",
        lambda: {"ok": True,
                 "user": "system:serviceaccount:lineage-incluster:lineage",
                 "server": "https://10.0.0.1:443",
                 "version": "4.19.8", "mock": False, "is_admin": True},
    )
    with app.test_client() as c:
        body = c.get("/setup").data.decode()
    assert "in-cluster" in body
    assert "system:serviceaccount:lineage-incluster:lineage" in body
    assert "4.19.8" in body
