"""Non-admin / partial-visibility regression tests.

Old behavior: Lineage gated whole pages on a coarse is_admin flag, so a
developer like Tom — who can `oc get clusterroles` but not list CRBs,
and who can read Roles in his own namespace — saw empty/misleading
tables. New behavior: render whatever is visible, add per-section
"not visible" notes for the missing related data.
"""

from unittest.mock import patch

from lineage.main import app
from .conftest import make_index


# ---------- /clusterroles ---------- #

def test_clusterroles_visible_to_non_admin_when_crs_readable(monkeypatch):
    """Tom can list ClusterRoles but not ClusterRoleBindings. The page
    must render the visible ClusterRoles and a 'bindings not visible'
    note rather than early-returning empty."""
    idx = make_index(
        cluster_roles=[
            {"name": "view", "labels": {}, "annotations": {},
             "aggregationRule": None,
             "rules": [{"apiGroups": [""], "resources": ["pods"],
                        "verbs": ["get", "list", "watch"]}],
             "creationTimestamp": "2024-01-01T00:00:00Z"},
            {"name": "cluster-admin", "labels": {}, "annotations": {},
             "aggregationRule": None,
             "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
             "creationTimestamp": "2024-01-01T00:00:00Z"},
        ],
    )
    idx["is_admin"] = False
    idx["fetch_error_kinds"] = {"crb"}  # CRBs not listable
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/clusterroles").data.decode()

    # Visible ClusterRoles appear in the table.
    assert ">view</a>" in body
    assert ">cluster-admin</a>" in body
    # Limited-view note about bindings being invisible.
    assert "Bindings not visible" in body
    # The misleading "Cluster-admin required" full-page block must be gone.
    assert "Cluster-admin required" not in body


def test_clusterroles_hides_only_when_clusterroles_themselves_unreadable(
        monkeypatch):
    """If even the ClusterRoles list is forbidden, the page should say so
    instead of showing an empty table."""
    idx = make_index()
    idx["is_admin"] = False
    idx["fetch_error_kinds"] = {"clusterroles", "crb"}
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/clusterroles").data.decode()

    assert "ClusterRoles not readable" in body


# ---------- /roles ---------- #

def test_roles_page_shows_visible_namespace_role_for_non_admin(monkeypatch):
    """Tom's project namespace was created with `oc create namespace`
    (no requester annotation), so it classifies as 'unknown'. With the
    default 'yours' bucket this would render '0 of 1'. For non-admin we
    now default to 'all' so the visible Role appears."""
    idx = make_index(
        namespaces=[{"name": "tom-sandbox", "labels": {}, "annotations": {}}],
        roles=[{"name": "config-editor", "namespace": "tom-sandbox",
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                           "verbs": ["get", "list", "update"]}],
                "creationTimestamp": "2025-04-01T10:00:00Z"}],
    )
    idx["is_admin"] = False
    idx["fetch_error_kinds"] = set()
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/roles").data.decode()

    assert "config-editor" in body
    # Not the empty-state line.
    assert "No roles in this view." not in body
    # Limited view note explains why the 'all' bucket is the default.
    assert "Limited view" in body


def test_roles_page_admin_default_unchanged(monkeypatch):
    """Regression guard: admin users still get the original 'yours'
    default; this fix is non-admin-only."""
    idx = make_index(
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        roles=[{"name": "reader", "namespace": "team-a",
                "rules": [], "creationTimestamp": "2025-01-01T00:00:00Z"}],
    )
    idx["is_admin"] = True
    idx["fetch_error_kinds"] = set()
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/roles").data.decode()

    # bucket=yours still chosen by default → the toggle row reflects it.
    assert 'class="active"' in body
    assert "Limited view" not in body


def test_roles_binding_count_note_when_rolebindings_unreadable(monkeypatch):
    idx = make_index(
        namespaces=[{"name": "tom-sandbox", "labels": {}, "annotations": {}}],
        roles=[{"name": "config-editor", "namespace": "tom-sandbox",
                "rules": [], "creationTimestamp": "2025-04-01T10:00:00Z"}],
    )
    idx["is_admin"] = False
    idx["fetch_error_kinds"] = {"rb"}  # RoleBindings not visible
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/roles").data.decode()

    assert "RoleBindings are not visible" in body


# ---------- Missing related data does not suppress primary objects ---------- #

def test_missing_crbs_does_not_suppress_clusterroles(monkeypatch):
    """The cross-cutting invariant: visible primary objects are never
    hidden because related objects are missing."""
    idx = make_index(
        cluster_roles=[
            {"name": "edit", "labels": {}, "annotations": {},
             "aggregationRule": None, "rules": [],
             "creationTimestamp": "2024-01-01T00:00:00Z"},
        ],
    )
    idx["is_admin"] = False
    idx["fetch_error_kinds"] = {"crb", "rb", "sa"}
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/clusterroles").data.decode()

    assert ">edit</a>" in body


# ---------- Version detection no longer requires clusterversion ---------- #

def _fake_version_status(version_json_bytes, *, user="tom", is_admin=False,
                          clusterversion_bytes=None):
    """Helper: install a fake subprocess that returns whatever bytes you
    pass for `oc version -o json`, plus working whoami output.

    If `clusterversion_bytes` is None the clusterversion lookup raises
    (unreadable). Otherwise it returns those bytes as the jsonpath result."""
    from lineage import cluster
    cluster._status_cache["data"] = None
    cluster._last_identity = {"user": None, "server": None}

    def fake_check_output(args, **kw):
        first = args[1] if len(args) > 1 else ""
        if first == "whoami":
            if "--show-server" in args:
                return b"https://api.example.test:6443"
            return user.encode()
        if first == "version":
            if version_json_bytes is None:
                raise __import__("subprocess").CalledProcessError(2, args)
            return version_json_bytes
        if first == "get" and "clusterversion" in args:
            if clusterversion_bytes is None:
                raise __import__("subprocess").CalledProcessError(1, args)
            return clusterversion_bytes
        return b""

    def fake_run(args, **kw):
        class R:
            returncode = 0 if is_admin else 1
        return R()
    return cluster, fake_check_output, fake_run


def test_live_status_prefers_release_client_version(monkeypatch):
    """Real CRC 4.19.8 output for the `tom` (non-admin) session contains
    releaseClientVersion=4.19.8 but no openshiftVersion. The previous
    parsing fell through to serverVersion.gitVersion (v1.32.7), which
    is misleading for an OpenShift cluster. Verified live against the
    user's CRC: tom and amine both lack openshiftVersion."""
    real_tom_output = (
        b'{"clientVersion": {"gitVersion": "4.19.0-..."},'
        b' "serverVersion": {"gitVersion": "v1.32.7"},'
        b' "releaseClientVersion": "4.19.8"}'
    )
    cluster, fake_check_output, fake_run = _fake_version_status(real_tom_output)
    with patch.object(cluster.subprocess, "check_output",
                      side_effect=fake_check_output), \
         patch.object(cluster.subprocess, "run", side_effect=fake_run):
        status = cluster.live_status()
    assert status["version"] == "4.19.8"  # not v1.32.7


def test_live_status_release_client_version_wins_over_openshift_version(
        monkeypatch):
    """Order: releaseClientVersion > openshiftVersion. The two usually
    match on a healthy cluster (kubeadmin sees both as 4.19.8), but the
    rule must hold regardless of order in the JSON blob."""
    blob = (b'{"openshiftVersion": "4.19.9",'
            b' "releaseClientVersion": "4.19.8",'
            b' "serverVersion": {"gitVersion": "v1.32.7"}}')
    cluster, fake_check_output, fake_run = _fake_version_status(blob)
    with patch.object(cluster.subprocess, "check_output",
                      side_effect=fake_check_output), \
         patch.object(cluster.subprocess, "run", side_effect=fake_run):
        status = cluster.live_status()
    assert status["version"] == "4.19.8"


def test_live_status_falls_back_to_openshift_version_if_release_missing(
        monkeypatch):
    """Older oc binaries may not populate releaseClientVersion. Fall
    back to openshiftVersion when present."""
    blob = (b'{"openshiftVersion": "4.18.2",'
            b' "serverVersion": {"gitVersion": "v1.31.0"}}')
    cluster, fake_check_output, fake_run = _fake_version_status(blob)
    with patch.object(cluster.subprocess, "check_output",
                      side_effect=fake_check_output), \
         patch.object(cluster.subprocess, "run", side_effect=fake_run):
        status = cluster.live_status()
    assert status["version"] == "4.18.2"


def test_live_status_in_container_prefers_clusterversion_over_k8s_git(
        monkeypatch):
    """In-container shape: the bundled `oc` (copied from origin-cli) does
    not populate releaseClientVersion or openshiftVersion, so `oc version
    -o json` only carries serverVersion.gitVersion (e.g. v1.32.7).

    When the pod SA can read ClusterVersion, the OpenShift version
    (status.desired.version, e.g. 4.19.8) must win over the Kubernetes
    git version — otherwise the UI misleadingly shows 'v1.32.7' for an
    OpenShift 4.19.8 cluster."""
    blob = b'{"serverVersion": {"gitVersion": "v1.32.7"}}'
    cluster, fake_check_output, fake_run = _fake_version_status(
        blob, user="system:serviceaccount:lineage-incluster:lineage",
        clusterversion_bytes=b"4.19.8")
    with patch.object(cluster.subprocess, "check_output",
                      side_effect=fake_check_output), \
         patch.object(cluster.subprocess, "run", side_effect=fake_run):
        status = cluster.live_status()
    assert status["version"] == "4.19.8"  # not v1.32.7


def test_live_status_last_resort_uses_kubernetes_git_version(monkeypatch):
    """Only when nothing else is available — releaseClientVersion absent,
    openshiftVersion absent, clusterversion unreadable — does Lineage
    fall through to the Kubernetes server gitVersion. Better than
    'unknown', but explicitly the last resort."""
    blob = b'{"serverVersion": {"gitVersion": "v1.32.7"}}'
    cluster, fake_check_output, fake_run = _fake_version_status(blob)
    with patch.object(cluster.subprocess, "check_output",
                      side_effect=fake_check_output), \
         patch.object(cluster.subprocess, "run", side_effect=fake_run):
        status = cluster.live_status()
    assert status["version"] == "v1.32.7"


def test_live_status_falls_back_to_clusterversion_if_oc_version_fails():
    """Older oc binaries may not support `version -o json` at all. The
    clusterversion fallback must still work for admins."""
    from lineage import cluster
    cluster._status_cache["data"] = None
    cluster._last_identity = {"user": None, "server": None}

    def fake_check_output(args, **kw):
        first = args[1] if len(args) > 1 else ""
        if first == "whoami":
            if "--show-server" in args:
                return b"https://api.example.test:6443"
            return b"alice"
        if first == "version":
            raise __import__("subprocess").CalledProcessError(2, args)
        if first == "get" and "clusterversion" in args:
            return b"4.18.0"
        return b""

    def fake_run(args, **kw):
        class R:
            returncode = 0
        return R()

    with patch.object(cluster.subprocess, "check_output",
                      side_effect=fake_check_output), \
         patch.object(cluster.subprocess, "run", side_effect=fake_run):
        status = cluster.live_status()

    assert status["version"] == "4.18.0"
