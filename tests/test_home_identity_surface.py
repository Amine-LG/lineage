"""Home identity surface regression tests."""

from lineage.main import app
from .conftest import make_index


def _ns(name, requester=None):
    annotations = {"openshift.io/requester": requester} if requester else {}
    return {"name": name, "labels": {}, "annotations": annotations}


def _pod(name, namespace):
    return {
        "name": name,
        "namespace": namespace,
        "labels": {},
        "annotations": {},
        "spec": {"containers": [{"name": "c", "image": "quay.io/acme/app:1"}]},
        "containerStatuses": [],
        "phase": "Running",
    }


def _sa(name, namespace):
    return {
        "name": name,
        "namespace": namespace,
        "labels": {},
        "annotations": {},
    }


def _imagestream(name, namespace):
    return {
        "name": name,
        "namespace": namespace,
        "dockerImageRepository": (
            f"image-registry.openshift-image-registry.svc:5000/"
            f"{namespace}/{name}"
        ),
        "spec_tags": [],
        "status_tags": [],
    }


def _scc(name):
    return {
        "name": name,
        "users": [],
        "groups": [],
        "allowPrivilegedContainer": False,
        "allowHostNetwork": False,
        "allowHostPID": False,
        "allowHostIPC": False,
        "allowPrivilegeEscalation": False,
        "runAsUser": {"type": "MustRunAsRange"},
    }


def _aggregated_role(name, labels=None, annotations=None):
    return {
        "name": name,
        "labels": labels or {},
        "annotations": annotations or {},
        "aggregationRule": {
            "clusterRoleSelectors": [
                {"matchLabels": {"lineage.test/aggregate": name}}
            ]
        },
        "rules": [],
    }


def _counter_card(body, label):
    label_index = _label_index(body, label)
    start = body.rfind('<a class="counter', 0, label_index)
    end = body.index("</a>", label_index) + len("</a>")
    return body[start:end]


def _label_index(body, label):
    return body.index(f'<div class="lab">{label}</div>')


def _counter_num(card):
    start = card.index('<div class="num">') + len('<div class="num">')
    end = card.index("</div>", start)
    return card[start:end].strip()


def test_home_identity_anomaly_card_excludes_resurrectable_sas(
        monkeypatch, cluster_admin_role):
    idx = make_index(
        namespaces=[{"name": "ci", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[cluster_admin_role],
        crbs=[{"name": "ci-pipeline-clusteradmin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "pipeline", "namespace": "ci"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )

    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        response = client.get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert '<section class="review-summary" aria-label="Dashboard summary">' in body
    assert '<div class="summary-num">1</div>' in body
    assert '<a class="summary-action" href="/identity-audit">' in body
    assert "<h2>Identity references need review</h2>" in body
    # Wording covers both resurrectable families now (SAs + SCC groups).
    assert "<strong>1 critical resurrectable</strong>" in body
    assert "<h2><span>Identity</span><small>Subjects and review-worthy references.</small></h2>" in body
    assert "<strong>0</strong> identity findings" not in body
    assert "critical/high resurrectable SA gap" not in body
    assert '<div class="num">0</div>\n      <div class="lab">identity findings</div>' in body
    # Card label and split counts include both families.
    assert "critical resurrectable" in body
    assert "1 SA · 0 SCC groups" in body
    assert '<div class="lab">latent users</div>' not in body
    assert "hero-lab\">identity anomalies" not in body
    resurrectable_card = _counter_card(body, "critical resurrectable")
    assert "counter-priv" in resurrectable_card
    assert "1 SA" in resurrectable_card


def test_home_review_summary_caps_examples_and_uses_plain_audit_link(monkeypatch):
    idx = make_index(users=[
        {"name": "alpha"},
        {"name": "beta"},
        {"name": "delta"},
        {"name": "gamma"},
    ])

    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        response = client.get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert '<a class="summary-action" href="/identity-audit">' in body
    assert "<strong>4 stranded users</strong>" in body
    # Preview cap is 2 per category — "+X more" carries the rest.
    assert "alpha, beta, +2 more" in body
    assert "delta," not in body
    assert "gamma," not in body


def test_home_clean_crc_style_baseline_counts_are_calm(monkeypatch):
    idx = make_index(
        namespaces=[
            _ns("openshift-monitoring"),
            _ns("openshift-config"),
        ],
        pods=[
            _pod("prometheus-k8s-0", "openshift-monitoring"),
            _pod("oauth-openshift-abc", "openshift-config"),
        ],
        sccs=[
            _scc("privileged"),
            _scc("restricted-v3"),
        ],
        cluster_roles=[
            _aggregated_role(
                "admin",
                labels={"kubernetes.io/bootstrapping": "rbac-defaults"},
                annotations={"rbac.authorization.kubernetes.io/autoupdate": "true"},
            ),
            _aggregated_role(
                "olm.og.openshift-cluster-monitoring.view-test",
                labels={
                    "olm.managed": "true",
                    "olm.owner.namespace": "openshift-monitoring",
                },
            ),
        ],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/").get_data(as_text=True)

    pods = _counter_card(body, "pods")
    sccs = _counter_card(body, "SCCs")
    aggregated = _counter_card(body, "aggregated roles")
    assert _counter_num(pods) == "0"
    assert "of 2 total" in pods
    assert _counter_num(sccs) == "0"
    assert "of 2 total" in sccs
    assert _counter_num(aggregated) == "0"
    assert "of 2 total" in aggregated


def test_home_custom_project_objects_increment_card_counts(monkeypatch):
    idx = make_index(
        namespaces=[
            _ns("openshift-monitoring"),
            _ns("team-app", requester="alice"),
        ],
        pods=[
            _pod("prometheus-k8s-0", "openshift-monitoring"),
            _pod("api-1", "team-app"),
        ],
        sccs=[
            _scc("restricted-v3"),
            _scc("team-app-scc"),
        ],
        cluster_roles=[
            _aggregated_role(
                "admin",
                labels={"kubernetes.io/bootstrapping": "rbac-defaults"},
                annotations={"rbac.authorization.kubernetes.io/autoupdate": "true"},
            ),
            _aggregated_role("team-app-aggregate"),
        ],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/").get_data(as_text=True)

    pods = _counter_card(body, "pods")
    sccs = _counter_card(body, "SCCs")
    aggregated = _counter_card(body, "aggregated roles")
    assert _counter_num(pods) == "1"
    assert "of 2 total" in pods
    assert _counter_num(sccs) == "1"
    assert "of 2 total" in sccs
    assert _counter_num(aggregated) == "1"
    assert "of 2 total" in aggregated


def test_home_unclassified_namespace_objects_count_and_link_to_unclassified(
        monkeypatch):
    idx = make_index(
        namespaces=[_ns("raw-lab")],
        sas=[_sa("builder", "raw-lab")],
        pods=[_pod("api-1", "raw-lab")],
        imagestreams=[_imagestream("api", "raw-lab")],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/").get_data(as_text=True)
        namespaces = client.get(
            "/namespaces?category=unknown#namespaces-list"
        ).get_data(as_text=True)
        subjects = client.get(
            "/subjects?bucket=unknown&kind=ServiceAccount#subjects-list"
        ).get_data(as_text=True)
        images = client.get(
            "/images?bucket=unknown#images-overview"
        ).get_data(as_text=True)

    cards = {
        label: _counter_card(body, label)
        for label in (
            "namespaces",
            "pods",
            "service accounts",
            "images",
            "ImageStreams",
            "registries",
        )
    }
    for card in cards.values():
        assert _counter_num(card) == "1"
        assert "of 1 total" in card
    assert "/namespaces?category=unknown#namespaces-list" in cards["namespaces"]
    assert "/namespaces?category=unknown#namespaces-list" in cards["pods"]
    assert "/subjects?bucket=unknown&kind=ServiceAccount#subjects-list" in cards[
        "service accounts"]
    assert "/images?bucket=unknown#images-list" in cards["images"]
    assert "/images?bucket=unknown#imagestreams" in cards["ImageStreams"]
    assert "/images?bucket=unknown#registries" in cards["registries"]
    assert "raw-lab" in namespaces
    assert "unclassified" in namespaces
    assert "builder" in subjects
    assert "quay.io/acme/app:1" in images
    assert "api" in images


def test_home_group_card_does_not_count_virtual_sa_group_as_real(monkeypatch):
    idx = make_index(
        namespaces=[
            _ns("amine-project", requester="amine"),
        ],
        cluster_roles=[
            {"name": "view",
             "rules": [{"apiGroups": [""], "resources": ["pods"],
                        "verbs": ["get", "list"]}]},
        ],
        rbs=[{"name": "amine-project-sa-view",
              "namespace": "amine-project",
              "subjects": [{"kind": "Group",
                             "name": "system:serviceaccounts:amine-project"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/").get_data(as_text=True)
        subjects_body = client.get(
            "/subjects?bucket=all&kind=Group#subjects-list"
        ).get_data(as_text=True)

    card = _counter_card(body, "group subjects")
    assert _counter_num(card) == "0"
    assert "0 real · 1 virtual" in card
    assert "system:serviceaccounts:amine-project" in subjects_body
    assert "virtual" in subjects_body


def test_home_resurrectable_baseline_findings_do_not_drive_card(monkeypatch,
                                                                cluster_admin_role):
    idx = make_index(
        namespaces=[_ns("openshift-monitoring")],
        cluster_roles=[cluster_admin_role],
        crbs=[{"name": "platform-prometheus-admin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "prometheus-k8s",
                              "namespace": "openshift-monitoring"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/").get_data(as_text=True)

    card = _counter_card(body, "resurrectable")
    assert _counter_num(card) == "0"
    assert "1 baseline" in card
    assert "Dashboard summary" not in body


def test_home_resurrectable_card_falls_back_to_all_when_no_critical_or_high(
        monkeypatch, view_role):
    """When there are no critical or high resurrectable findings but a
    real lower-severity finding exists, the card must NOT read '0
    critical' — it should switch to the all-severities view so the
    finding is still discoverable from the dashboard."""
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

    with app.test_client() as client:
        response = client.get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert '<section class="review-summary" aria-label="Dashboard summary">' not in body
    # Card label drops the severity prefix when nothing is critical/high.
    card = _counter_card(body, "resurrectable")
    # And the number reflects the total resurrectable findings (so the
    # card is not a misleading "0").
    assert '<div class="num">1</div>' in card
    assert "counter-priv" not in card
    assert "counter-warn" not in card
    # Subtitle lists per-family counts only (severity breakdown moved out
    # to /identity-audit to keep the home card scannable).
    assert "1 SA · 0 SCC groups" in card


def test_home_dashboard_card_order():
    with app.test_client() as client:
        response = client.get("/")

    assert response.status_code == 200
    body = response.get_data(as_text=True)

    expected_order = [
        "identity findings",
        "critical resurrectable",
        "user subjects",
        "group subjects",
        "privileged bindings",
        "duplicate bindings",
        "role grants",
        "aggregated roles",
        "namespaces",
        "pods",
        "service accounts",
        "SCCs",
        "images",
        "ImageStreams",
        "registries",
        "digest drift",
    ]
    positions = [_label_index(body, label) for label in expected_order]
    assert positions == sorted(positions)


def test_identity_audit_has_identity_anomalies_anchor():
    with app.test_client() as client:
        response = client.get("/identity-audit")

    assert response.status_code == 200
    assert 'id="identity-anomalies"' in response.get_data(as_text=True)


def test_stranded_user_badge_renders_on_permission_surfaces(
        monkeypatch, cluster_admin_role):
    idx = make_index(
        users=[{"name": "manual-reviewer"}],
        identities=[],
        namespaces=[{"name": "app", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[cluster_admin_role],
        rbs=[{"name": "manual-reviewer-admin", "namespace": "app",
              "subjects": [{"kind": "User", "name": "manual-reviewer"}],
              "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )

    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        for path in ("/", "/privileged", "/permission-grants"):
            response = client.get(path)
            assert response.status_code == 200
            body = response.get_data(as_text=True)
            assert "manual-reviewer" in body
            assert '<span class="badge badge-warn">No ID</span>' in body
