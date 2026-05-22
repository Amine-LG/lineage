"""User-marker merging in engine.all_subjects().

Real cluster scenario that motivated this (CRC 4.19.8):
  - User `alice` does NOT exist as a User object.
  - `alice` IS listed in the htpasswd Secret backing the `cool` IdP.
  - Some ClusterRoleBinding references the User `alice` as a subject.

So `alice` is both latent (in htpasswd, no User) and a ghost (referenced
by a binding without a backing object). The subject inventory should merge
those signals into one row.
"""

from lineage import engine
from .conftest import make_index


def _htpasswd_oauth():
    return {"identityProviders": [
        {"name": "cool", "type": "HTPasswd",
         "htpasswd": {"fileData": {"name": "new-htpasswd"}}}]}


def test_ghost_user_in_htpasswd_also_flagged_latent():
    """alice has no User object, is in htpasswd, and a binding references
    her. Lineage must surface BOTH ghost and latent so the reviewer sees
    'create the User and the binding wakes up' (ghost) AND 'her name is
    already in the IdP backing store' (latent) at the same time."""
    idx = make_index(
        crbs=[{"name": "alice-admin",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole", "name": "admin"}}],
        htpasswd_users=[
            {"username": "alice", "idp_name": "cool",
             "secret_namespace": "openshift-config",
             "secret_name": "new-htpasswd"},
        ],
        htpasswd_available=True,
        htpasswd_configured=True,
        oauth_cluster=_htpasswd_oauth(),
    )

    subjects = engine.all_subjects(idx)
    alice_rows = [s for s in subjects
                  if s["kind"] == "User" and s["name"] == "alice"]
    assert len(alice_rows) == 1, "alice must appear exactly once"
    row = alice_rows[0]
    assert row["ghost"] is True
    assert row["latent"] is True
    # Origin includes both facts so the page can explain WHY.
    assert "ghost" in row["origin"]
    assert "latent" in row["origin"]
    assert "htpasswd" in row["origin"]


def test_pure_latent_user_still_renders_when_no_ghost():
    """A plain latent user should still appear with the latent flag."""
    idx = make_index(
        htpasswd_users=[
            {"username": "tom-future-hire", "idp_name": "cool",
             "secret_namespace": "openshift-config",
             "secret_name": "new-htpasswd"},
        ],
        htpasswd_available=True,
        htpasswd_configured=True,
        oauth_cluster=_htpasswd_oauth(),
    )
    subjects = engine.all_subjects(idx)
    rows = [s for s in subjects
            if s["kind"] == "User" and s["name"] == "tom-future-hire"]
    assert len(rows) == 1
    assert rows[0]["latent"] is True
    assert rows[0]["ghost"] is False


def test_subject_identity_markers_does_not_set_htpasswd_backed_without_user():
    """Consistency with all_subjects(): htpasswd_backed only fires for a
    real User row. For a name that is latent (in htpasswd, no User) the
    latent flag already conveys 'an htpasswd entry exists' — adding
    htpasswd_backed would duplicate that fact and contradict /subjects."""
    idx = make_index(
        # alice has no User object
        htpasswd_users=[
            {"username": "alice", "idp_name": "cool",
             "secret_namespace": "openshift-config",
             "secret_name": "new-htpasswd"},
        ],
        htpasswd_available=True,
        htpasswd_configured=True,
        oauth_cluster=_htpasswd_oauth(),
    )
    markers = engine.subject_identity_markers(
        {"kind": "User", "name": "alice"}, idx)
    assert markers["latent"] is True
    assert markers["htpasswd_backed"] is False


def test_subject_identity_markers_sets_htpasswd_backed_for_real_user():
    """Inverse: when a User object exists, htpasswd_backed fires as before."""
    idx = make_index(
        users=[{"name": "amine"}],
        identities=[{"name": "cool:amine", "user": {"name": "amine"},
                     "providerName": "cool"}],
        htpasswd_users=[
            {"username": "amine", "idp_name": "cool",
             "secret_namespace": "openshift-config",
             "secret_name": "new-htpasswd"},
        ],
        htpasswd_available=True,
        htpasswd_configured=True,
        oauth_cluster=_htpasswd_oauth(),
    )
    markers = engine.subject_identity_markers(
        {"kind": "User", "name": "amine"}, idx)
    assert markers["htpasswd_backed"] is True
    assert markers["latent"] is False


def test_subject_detail_latent_user_without_binding_is_not_ghost(monkeypatch):
    """latent-user is in the htpasswd Secret but has no User object AND
    no binding references her. /subjects shows only the `latent` badge;
    /subject/User/latent-user must do the same — not falsely add a
    `ghost` badge just because the User object is missing. Found on
    real CRC 4.19.8 during the Users validation cycle."""
    idx = make_index(
        htpasswd_users=[
            {"username": "latent-user", "idp_name": "cool",
             "secret_namespace": "openshift-config",
             "secret_name": "lineage-test-htpasswd"},
        ],
        htpasswd_available=True,
        htpasswd_configured=True,
        oauth_cluster=_htpasswd_oauth(),
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    from lineage.main import app
    import re
    with app.test_client() as c:
        body = c.get("/subject/User/latent-user").data.decode()
    h1 = re.search(r"<h1>([\s\S]*?)</h1>", body)
    badges = re.findall(r'class="badge[^"]*"[^>]*>([^<]+)</span>',
                        h1.group(1) if h1 else "")
    assert "latent" in badges
    assert "ghost" not in badges


def test_subject_detail_bound_missing_user_still_ghost(monkeypatch):
    """A missing User referenced by RBAC should show the ghost badge."""
    idx = make_index(
        crbs=[{"name": "ghost-binding",
               "subjects": [{"kind": "User", "name": "missing-user"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        cluster_roles=[{"name": "view", "labels": {}, "annotations": {},
                         "aggregationRule": None,
                         "rules": [{"apiGroups": [""],
                                    "resources": ["pods"],
                                    "verbs": ["get"]}]}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    from lineage.main import app
    with app.test_client() as c:
        body = c.get("/subject/User/missing-user").data.decode()
    assert ">ghost</span>" in body


def test_existing_user_in_htpasswd_does_not_get_latent_flag():
    """A username that already has a User object is NOT latent — latent
    specifically means 'pre-provisioned in IdP, User not created yet.'
    A real User should not become latent just because the name is in htpasswd."""
    idx = make_index(
        users=[{"name": "amine"}],
        identities=[{"name": "cool:amine", "user": {"name": "amine"},
                     "providerName": "cool"}],
        htpasswd_users=[
            {"username": "amine", "idp_name": "cool",
             "secret_namespace": "openshift-config",
             "secret_name": "new-htpasswd"},
        ],
        htpasswd_available=True,
        htpasswd_configured=True,
        oauth_cluster=_htpasswd_oauth(),
    )
    subjects = engine.all_subjects(idx)
    row = next(s for s in subjects
               if s["kind"] == "User" and s["name"] == "amine")
    assert row["latent"] is False
    # And she IS htpasswd-backed (real User + in htpasswd).
    assert row["htpasswd_backed"] is True
