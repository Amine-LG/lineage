"""Identity audit page rendering tests."""

from lineage.main import app
from .conftest import make_index


def test_identity_audit_defaults_to_critical_resurrectable_filter():
    with app.test_client() as client:
        response = client.get("/identity-audit")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'href="?severity=critical#resurrectable" class="active"' in body
    assert 'href="?severity=all#resurrectable" class=""' in body
    # Reorg: severity tabs are at the top of the section; the SA-table
    # filter input now lives inside the ServiceAccount sub-section.
    severity_pos = body.index('href="?severity=all#resurrectable"')
    filter_pos = body.index('data-filter-target="#resurrectable-table"')
    table_pos = body.index('id="resurrectable-table"')
    assert severity_pos < filter_pos < table_pos


def test_identity_audit_defaults_to_critical_even_when_no_critical(
        monkeypatch, view_role):
    idx = make_index(
        namespaces=[{"name": "ci", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[view_role],
        crbs=[{"name": "ci-pipeline-view",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "pipeline", "namespace": "ci"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )

    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    monkeypatch.setattr(main_module.data, "live_status", lambda: {
        "ok": True, "mock": True, "is_admin": True, "user": "mock",
        "server": "mock", "version": "mock",
    })

    with app.test_client() as client:
        response = client.get("/identity-audit")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'href="?severity=critical#resurrectable" class="active"' in body
    assert 'href="?severity=all#resurrectable" class=""' in body
    # New unified empty-state copy from the SA-resurrectable sub-section.
    assert ("No critical ServiceAccount findings." in body
            or "No critical identity findings." in body)
    assert '<span class="badge badge-info">low</span>' not in body


def test_identity_audit_bound_ghost_toggle_links_return_to_section(
        monkeypatch, view_role):
    idx = make_index(
        cluster_roles=[view_role],
        crbs=[{"name": "system:precreated-user-view",
               "subjects": [{"kind": "User", "name": "future-user"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )

    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        response = client.get("/identity-audit")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'id="bound-ghosts"' in body
    assert 'href="?severity=critical&show_all=1#bound-ghosts"' in body

    with app.test_client() as client:
        response = client.get("/identity-audit?show_all=1")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert 'href="/identity-audit?severity=critical#bound-ghosts"' in body


def test_identity_audit_stranded_users_and_idps_render_as_tables():
    with app.test_client() as client:
        response = client.get("/identity-audit")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "<th>User</th><th>Identity link</th><th>Subject page</th>" in body
    assert '<span class="badge badge-warn">No ID</span>' in body
    assert "manual-approver" in body
    assert "<th>Provider</th><th>Type</th><th>Audit support</th>" in body
    assert '<span class="badge badge-info">auditable</span>' in body
