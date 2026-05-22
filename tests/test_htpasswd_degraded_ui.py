"""Cross-surface regression for the HTPasswd-degraded UX.

Covers the home banner, CLI text + JSON output, and the multi-marker
mock user so the bundled dataset surfaces 'No ID' + 'htpasswd-backed'
together.
"""

import json

from lineage import cli, engine
from lineage.main import app
from .conftest import make_index


def _htpasswd_oauth():
    return {"identityProviders": [
        {"name": "cool", "type": "HTPasswd",
         "htpasswd": {"fileData": {"name": "htpasswd-secret"}}}]}


# ---------- Home dashboard ---------- #

def test_home_renders_degraded_banner_when_htpasswd_unreadable(
        monkeypatch):
    idx = make_index(
        users=[{"name": "alice"}],
        identities=[{"name": "cool:alice", "user": {"name": "alice"},
                     "providerName": "cool"}],
        htpasswd_users=[],
        htpasswd_available=False,
        htpasswd_configured=True,
        htpasswd_reason="forbidden: get secrets",
        oauth_cluster=_htpasswd_oauth(),
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/").data.decode()

    assert "HTPasswd checks degraded" in body
    assert "forbidden: get secrets" in body
    assert 'href="/identity-audit#htpasswd-degraded"' in body


def test_home_omits_degraded_banner_when_htpasswd_readable(monkeypatch):
    idx = make_index(
        htpasswd_users=[],
        htpasswd_available=True,
        htpasswd_configured=False,
        oauth_cluster={"identityProviders": []},
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/").data.decode()

    assert "HTPasswd checks degraded" not in body


# ---------- CLI ---------- #

def test_cli_findings_carry_htpasswd_degraded_fields():
    idx = make_index(
        users=[{"name": "alice"}],
        identities=[{"name": "cool:alice", "user": {"name": "alice"},
                     "providerName": "cool"}],
        htpasswd_users=[],
        htpasswd_available=False,
        htpasswd_configured=True,
        htpasswd_reason="forbidden",
        oauth_cluster=_htpasswd_oauth(),
    )
    findings = cli.collect_findings(idx)
    htp = findings["htpasswd"]
    assert htp["configured"] is True
    assert htp["available"] is False
    assert htp["degraded"] is True
    assert htp["reason"] == "forbidden"
    # No false phantom claim while the check is unavailable.
    assert findings["anomalies"]["phantom_users"] == []
    # JSON round-trip preserves the fields.
    blob = json.loads(json.dumps(findings, default=str))
    assert blob["htpasswd"]["degraded"] is True


def test_cli_text_warns_on_htpasswd_degraded():
    findings = {
        "cluster": {"ok": True, "user": "alice", "server": "(mock)",
                    "is_admin": True},
        "htpasswd": {"configured": True, "available": False,
                     "degraded": True, "reason": "forbidden: get secrets"},
        "limited_view": False,
        "anomalies": {
            "latent_users": [], "phantom_users": [], "bound_ghosts": [],
            "stranded_users": [], "orphan_identities": [],
            "resurrectable_sas": [],
        },
        "summary": {
            "privileged_user_subjects": 0,
            "privileged_baseline_subjects": 0,
            "duplicate_user_bindings": 0,
            "anomalies_total": 0,
            "real_anomalies_present": False,
        },
    }
    text = cli.render_text(findings)

    assert "[WARN]" in text
    assert "HTPasswd checks degraded" in text
    assert "forbidden: get secrets" in text
    # Phantom / latent counts must not look like a clean OK while
    # the check could not run.
    assert "[SKIP]  0 phantom users" in text
    assert "[SKIP]  0 latent users" in text
    # Other lines stay as OK because they don't depend on htpasswd.
    assert "[OK]    0 orphan identities" in text


def test_cli_text_warns_on_limited_view_non_admin():
    findings = {
        "cluster": {"ok": True, "user": "alice", "server": "(mock)",
                    "is_admin": False},
        "htpasswd": {"configured": False, "available": True,
                     "degraded": False, "reason": None},
        "limited_view": True,
        "anomalies": {
            "latent_users": [], "phantom_users": [], "bound_ghosts": [],
            "stranded_users": [], "orphan_identities": [],
            "resurrectable_sas": [],
        },
        "summary": {
            "privileged_user_subjects": 0,
            "privileged_baseline_subjects": 0,
            "duplicate_user_bindings": 0,
            "anomalies_total": 0,
            "real_anomalies_present": False,
        },
    }
    text = cli.render_text(findings)

    assert "Limited view (non-admin)" in text
    assert "[SKIP]  0 bound ghosts" in text
    assert "[SKIP]  0 stranded users" in text
    assert "[SKIP]  0 orphan identities" in text
    assert "[SKIP]  0 phantom users" in text


# ---------- Mock data coverage ---------- #

def test_mock_data_carries_no_id_plus_htpasswd_backed_user():
    """The bundled mock dataset includes a User whose 'No ID' and
    'htpasswd-backed' badges coexist, so the multi-marker case is
    exercised in tests and visible in mock mode."""
    idx = engine.index()
    htpasswd = {h["username"] for h in idx["htpasswd_users"]}
    # The mock 'rhea-rehire' has no Identity and IS in htpasswd.
    assert "rhea-rehire" in idx["users_by_name"]
    assert idx["identities_by_user"].get("rhea-rehire") in (None, [])
    assert "rhea-rehire" in htpasswd

    markers = engine.subject_identity_markers(
        {"kind": "User", "name": "rhea-rehire"}, idx)
    assert markers["stranded"] is True
    assert markers["htpasswd_backed"] is True
    assert markers["phantom"] is False


def test_subjects_page_renders_both_badges_for_multi_marker_user():
    with app.test_client() as client:
        body = client.get("/subjects?bucket=all&kind=User").data.decode()
    # Find the rhea-rehire row and check both badges appear nearby.
    row_idx = body.find("rhea-rehire")
    assert row_idx > 0
    window = body[row_idx:row_idx + 1500]
    assert ">No ID</span>" in window
    assert "htpasswd-backed" in window


# ---------- Public helper rename ---------- #

def test_engine_exposes_public_subject_identity_markers():
    """main.py calls engine.subject_identity_markers (no underscore).
    The old private name remains as a back-compat alias."""
    assert hasattr(engine, "subject_identity_markers")
    assert callable(engine.subject_identity_markers)
    assert engine._subject_identity_markers is engine.subject_identity_markers


def test_dead_helper_subjects_with_access_in_is_gone():
    """subjects_with_access_in was unused — only the _categorized variant
    is wired into the UI. Re-adding it would resurrect dead code."""
    assert not hasattr(engine, "subjects_with_access_in")
    assert hasattr(engine, "subjects_with_access_in_categorized")
