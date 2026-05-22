"""Subjects page and inventory tests."""

from lineage import engine
from lineage.main import app, bucket_filter
from .conftest import make_index


def test_all_subjects_includes_all_resurrectable_sas_as_ghosts():
    idx = make_index(
        namespaces=[
            {"name": "ci", "labels": {},
             "annotations": {"openshift.io/requester": "alice"}},
            {"name": "tooling", "labels": {},
             "annotations": {"openshift.io/requester": "alice"}},
        ],
        crbs=[
            {"name": "ci-pipeline-clusteradmin",
             "subjects": [{"kind": "ServiceAccount",
                            "name": "pipeline", "namespace": "ci"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}},
            {"name": "tooling-deployer-admin",
             "subjects": [{"kind": "User",
                            "name": "system:serviceaccount:tooling:deployer"}],
             "roleRef": {"kind": "ClusterRole", "name": "admin"}},
        ],
        sccs=[{"name": "privileged", "priority": 10,
               "allowPrivilegedContainer": True,
               "allowHostNetwork": True,
               "allowHostPID": True,
               "allowHostIPC": True,
               "allowPrivilegeEscalation": True,
               "runAsUser": {"type": "RunAsAny"},
               "creationTimestamp": "2024-01-01T00:00:00Z",
               "users": ["system:serviceaccount:forgotten-batch:runner"],
               "groups": []}],
    )

    subjects = engine.all_subjects(idx)
    by_key = {(s["kind"], s["namespace"], s["name"]): s for s in subjects}

    for key in [
        ("ServiceAccount", "ci", "pipeline"),
        ("ServiceAccount", "tooling", "deployer"),
        ("ServiceAccount", "forgotten-batch", "runner"),
    ]:
        assert by_key[key]["ghost"] is True
        assert by_key[key]["resurrectable"] is True
        assert by_key[key]["baseline"] is False


def test_system_namespace_resurrectable_sa_stays_baseline_and_keeps_grant_date():
    idx = make_index(
        namespaces=[{"name": "kube-system", "labels": {}, "annotations": {}}],
        crbs=[{"name": "route-controller-admin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "route-controller",
                              "namespace": "kube-system"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
               "creationTimestamp": "2024-04-05T12:00:00Z"}],
    )

    subjects = engine.all_subjects(idx)
    row = next(s for s in subjects
               if s["kind"] == "ServiceAccount"
               and s["namespace"] == "kube-system"
               and s["name"] == "route-controller")

    assert row["ghost"] is True
    assert row["resurrectable"] is True
    assert row["baseline"] is True
    assert row["creationTimestamp"] == "2024-04-05T12:00:00Z"
    assert row not in bucket_filter(subjects, "yours")
    assert row in bucket_filter(subjects, "baseline")


def test_present_unknown_namespace_resurrectable_sa_classified_unknown():
    """A resurrectable SA in a present-but-unclassified namespace lands in
    the Unclassified bucket, not Baseline. (Previously such SAs were silently
    rolled into Baseline, masking review-worthy state.)"""
    idx = make_index(
        namespaces=[{"name": "scratch", "labels": {}, "annotations": {}}],
        crbs=[{"name": "scratch-runner-view",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "runner", "namespace": "scratch"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )

    subjects = engine.all_subjects(idx)
    row = next(s for s in subjects
               if s["kind"] == "ServiceAccount"
               and s["namespace"] == "scratch"
               and s["name"] == "runner")

    assert row["resurrectable"] is True
    assert row["baseline"] is False
    assert row["unknown"] is True


def test_subjects_page_yours_sa_filter_shows_resurrectable_ghost_sas():
    with app.test_client() as client:
        response = client.get("/subjects?bucket=yours&kind=ServiceAccount")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    for text in ["pipeline", "legacy-pipelines", "forgotten-batch", "tooling"]:
        assert text in body


def test_subjects_page_yours_ghost_filter_shows_resurrectable_ghost_sas():
    with app.test_client() as client:
        response = client.get("/subjects?bucket=yours&ghost=1")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    for text in ["pipeline", "legacy-pipelines", "forgotten-batch", "tooling"]:
        assert text in body


def test_subjects_page_links_subject_names_without_view_column():
    with app.test_client() as client:
        response = client.get("/subjects?bucket=all&kind=User")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert '<th data-nosort="1"></th>' not in body
    assert ">view</a>" not in body
    assert '<span class="kind-tag kind-user">User</span>' in body
    assert '<a href="/subject/User/eve">eve</a>' in body


def test_subject_detail_splits_system_virtual_group_paths():
    """Bindings to system:authenticated[:oauth] / system:serviceaccounts[:ns]
    must render inside the collapsible <details class="system-reach"> block,
    not in the primary path list — otherwise every user/SA page is buried in
    platform noise."""
    with app.test_client() as client:
        response = client.get("/subject/User/alice")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    # The mock binds platform-admins/oauth-users-self-review (system:authenticated:oauth)
    # to `view`. Find where the system-reach block begins in the Effective
    # permissions section, and verify the system path is INSIDE it.
    eff_idx = body.index("Effective permissions")
    eff = body[eff_idx:]
    sr_start = eff.index('class="system-reach"')
    primary = eff[:sr_start]
    system = eff[sr_start:]
    assert "system:authenticated:oauth" in system
    # Alice's direct + platform-admins paths must be in the PRIMARY block.
    assert "platform-admins" in primary
    assert "system:authenticated:oauth" not in primary


def test_subject_detail_only_system_paths_shows_fallback_note():
    """A subject whose ONLY bindings come from system virtual groups must
    still render: the primary section says so, and the collapsible holds
    the actual rows."""
    with app.test_client() as client:
        response = client.get("/subject/User/bob")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "All paths come from auto-membership virtual groups" in body
    assert 'class="system-reach"' in body


def test_subject_detail_effective_paths_make_namespaces_visible(monkeypatch):
    idx = make_index(
        users=[{"name": "alice"}],
        groups=[{"name": "payments-engineers", "users": ["alice"]}],
        cluster_roles=[{"name": "view", "rules": [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}
        ]}],
        rbs=[
            {"name": "payments-engineers-view", "namespace": "payments-dev",
             "subjects": [{"kind": "Group", "name": "payments-engineers"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
            {"name": "payments-engineers-view", "namespace": "payments-prod",
             "subjects": [{"kind": "Group", "name": "payments-engineers"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
        ],
    )
    monkeypatch.setattr("lineage.main.engine.index", lambda: idx)

    with app.test_client() as client:
        response = client.get("/subject/User/alice")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Namespace:" in body
    assert "path-scope-namespace" in body
    assert 'href="/namespace/payments-dev">payments-dev</a>' in body
    assert 'href="/namespace/payments-prod">payments-prod</a>' in body
    assert "path-node-meta\">Namespace" not in body
    assert "· namespace:" not in body
    assert body.count("payments-engineers-view") >= 2


def test_subject_detail_cluster_wide_effective_path_uses_cluster_scope_badge(monkeypatch):
    idx = make_index(
        users=[{"name": "alice"}],
        cluster_roles=[{"name": "view", "rules": [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}
        ]}],
        crbs=[
            {"name": "alice-view", "namespace": None,
             "subjects": [{"kind": "User", "name": "alice"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
        ],
    )
    monkeypatch.setattr("lineage.main.engine.index", lambda: idx)

    with app.test_client() as client:
        response = client.get("/subject/User/alice")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "path-scope-cluster" in body
    assert "Cluster-wide" in body


def test_latent_only_user_does_not_get_ghost_badge(monkeypatch):
    """Regression for round-4 audit A21.

    Before the fix, the subject_detail route computed
    ``has_any_binding`` from the full ``reach`` dict — which, after the
    system-virtual-group machinery landed, includes 20+ synthesized paths
    via ``system:authenticated`` for every authenticated principal. A
    user that exists only in the HTPasswd Secret (latent — no User
    object, no real binding) therefore had ``has_any_binding=True`` and
    fell through to ``is_ghost_flag=True``, displaying both the latent
    AND the ghost badge in the header. Latent and ghost are supposed to
    be mutually exclusive identity signals. The fix uses only PRIMARY
    reach for that check.
    """
    idx = make_index(
        users=[],  # no User object for the latent name
        htpasswd_users=[{"username": "latent-only-user"}],
        # A cluster-wide binding to system:authenticated so the
        # synthesized reach is non-empty — this is what mis-fired
        # before the fix.
        crbs=[{"name": "authn-view", "namespace": None,
                "subjects": [{"kind": "Group",
                               "name": "system:authenticated"}],
                "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        cluster_roles=[{"name": "view", "rules": [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]}],
    )
    monkeypatch.setattr("lineage.main.engine.index", lambda: idx)
    with app.test_client() as client:
        response = client.get("/subject/User/latent-only-user")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    # The header should carry the latent badge — and nothing else.
    assert '<span class="badge badge-warn">latent</span>' in body
    assert '<span class="badge badge-warn">ghost</span>' not in body


def test_subjects_page_surfaces_user_without_identity(monkeypatch):
    idx = make_index(
        users=[{"name": "manual-reviewer"}],
        identities=[],
    )

    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        response = client.get("/subjects?bucket=yours&kind=User")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert '<a href="/subject/User/manual-reviewer">manual-reviewer</a>' in body
    assert '<span class="badge badge-warn">No ID</span>' in body


def test_subject_detail_unknown_user_renders_without_template_globals():
    with app.test_client() as client:
        response = client.get("/subject/User/developer")

    assert response.status_code == 200
    assert "developer" in response.get_data(as_text=True)
