"""UI polish regression tests covering:
  - history-aware "Back" link partial
  - /sccs Created column, newest-first sort, limited-view banner
  - Dashboard resurrectable card: critical-vs-high-vs-fallback shapes
  - SCC list threshold/expand for long tables
"""

from pathlib import Path

from lineage.main import app
from .conftest import make_index


# ---------- Back link partial ---------- #

def _scc():
    return {
        "name": "test-scc", "users": [], "groups": [],
        "allowPrivilegedContainer": False, "allowHostNetwork": False,
        "allowHostPID": False, "allowHostIPC": False,
        "allowPrivilegeEscalation": True,
        "runAsUser": {"type": "MustRunAs"},
        "creationTimestamp": "2025-06-01T00:00:00Z",
        "priority": None,
    }


def test_back_link_calls_history_back(monkeypatch):
    """Each detail page renders the shared "← Back" control. It is a
    plain button that fires window.history.back() — exactly what the
    browser's own back button does. No fallback URL, no same-origin
    branching."""
    idx = make_index(sccs=[_scc()])
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/scc/test-scc").data.decode()

    # The control's label is just "Back" (not "Back to SCCs").
    assert ">&larr; Back</button>" in body
    # And it fires history.back().
    assert "window.history.back()" in body
    # The control is a button, not an anchor — no spurious href to confuse
    # right-click / open-in-new-tab.
    assert 'class="back-link"' in body


def test_back_link_label_is_generic_on_subject_detail():
    with app.test_client() as c:
        body = c.get("/subject/User/eve").data.decode()
    assert ">&larr; Back</button>" in body
    assert "Back to subjects" not in body


def test_back_link_label_is_generic_on_role_detail():
    with app.test_client() as c:
        body = c.get("/role/mine-platform/config-reader").data.decode()
    assert ">&larr; Back</button>" in body
    assert "Back to Roles" not in body


def test_back_link_label_is_generic_on_clusterrole_detail():
    with app.test_client() as c:
        body = c.get("/clusterrole/cluster-admin").data.decode()
    assert ">&larr; Back</button>" in body
    assert "Back to ClusterRoles" not in body


def test_back_link_label_is_generic_on_namespace_detail():
    with app.test_client() as c:
        body = c.get("/namespace/mine-platform").data.decode()
    assert ">&larr; Back</button>" in body
    assert "Back to namespaces" not in body


def test_back_link_label_is_generic_on_image_detail():
    with app.test_client() as c:
        # Pick any image visible in the mock dataset.
        body = c.get("/images").data.decode()
        # Find first image ref to navigate into.
        import re
        m = re.search(r'href="(/image\?ref=[^"]+)"', body)
        assert m is not None, "could not find an image link"
        body = c.get(m.group(1)).data.decode()
    assert ">&larr; Back</button>" in body
    assert "Back to images" not in body


def test_dense_tables_wrap_long_unbroken_text_globally():
    with app.test_client() as c:
        subjects = c.get("/subjects").data.decode()
        grants = c.get("/permission-grants").data.decode()

    css = Path("lineage/static/style.css").read_text(encoding="utf-8")
    assert 'id="subjects-table"' in subjects
    assert 'id="grants-table"' in grants
    assert "table-layout: auto" in css
    # Min cell width raised so short labels (e.g. "Scope") don't get
    # squeezed into one-letter-per-line stacks between wider neighbors.
    assert "--dense-cell-min: 6rem" in css
    assert "--dense-cell-max: min(28rem, 55vw)" in css
    assert "max-width: var(--dense-cell-max)" in css
    assert "table.dense td[data-sort]" in css
    assert "max-width: var(--dense-meta-cell-max)" in css
    # Default text cells use the soft `break-word`; only mono / link
    # cells can break mid-word with `anywhere` (for long unbreakable
    # identifiers like image digests or system:* group names).
    assert "table.dense td .mono" in css
    assert "overflow-wrap: break-word" in css
    assert "overflow-wrap: anywhere" in css


def test_permission_grants_marks_missing_role_without_broken_link(monkeypatch):
    idx = make_index(
        users=[{"name": "alice"}],
        crbs=[{"name": "dangling-role-ref",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "future-clusterrole"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/permission-grants").data.decode()

    assert "future-clusterrole" in body
    assert "missing role" in body
    assert 'href="/clusterrole/future-clusterrole"' not in body


def test_namespaces_highest_role_cell_wraps_long_privileged_badge():
    css = Path("lineage/static/style.css").read_text(encoding="utf-8")
    template = Path("lineage/templates/namespaces.html").read_text(encoding="utf-8")

    assert 'class="highest-role-cell" data-sort="{{ r.highest_tier }}"' in template
    assert 'class="badge badge-priv role-badge"' in template
    assert "table.dense td.highest-role-cell[data-sort]" in css
    assert "table.dense td.highest-role-cell .role-badge" in css
    assert "white-space: normal" in css


# ---------- /sccs Created column + sort ---------- #

def _scc_with(name, ts, **kw):
    return {
        "name": name, "users": [], "groups": [],
        "allowPrivilegedContainer": kw.pop("priv", False),
        "allowHostNetwork": False, "allowHostPID": False,
        "allowHostIPC": False, "allowPrivilegeEscalation": True,
        "runAsUser": {"type": "MustRunAs"},
        "creationTimestamp": ts,
        "priority": kw.pop("priority", None),
        **kw,
    }


def test_sccs_page_has_created_column():
    """/sccs renders a Created column header."""
    with app.test_client() as c:
        body = c.get("/sccs").data.decode()
    assert "<th>Created</th>" in body


def test_sccs_page_sorts_newest_first(monkeypatch):
    """Rows on /sccs come in reverse creationTimestamp order."""
    idx = make_index(sccs=[
        _scc_with("oldest", "2024-01-01T00:00:00Z"),
        _scc_with("middle", "2024-06-01T00:00:00Z"),
        _scc_with("newest", "2025-12-31T00:00:00Z"),
    ])
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/sccs").data.decode()

    p_newest = body.index(">newest</a>")
    p_middle = body.index(">middle</a>")
    p_oldest = body.index(">oldest</a>")
    assert p_newest < p_middle < p_oldest


def test_sccs_page_tolerates_missing_timestamp(monkeypatch):
    """A SCC with an empty creationTimestamp must not crash the sort
    or the template. Missing-ts SCCs sort LAST (after dated ones)."""
    idx = make_index(sccs=[
        _scc_with("dated", "2025-01-01T00:00:00Z"),
        _scc_with("no-ts", None),
    ])
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/sccs").data.decode()
    # Both rows present, no 500.
    assert ">dated</a>" in body
    assert ">no-ts</a>" in body
    assert body.index(">dated</a>") < body.index(">no-ts</a>")


# ---------- /sccs limited-view banner ---------- #

def test_sccs_page_limited_view_banner_when_forbidden(monkeypatch):
    """When the cluster reader couldn't list SCCs (fetch_error_kinds
    contains 'scc' AND no rows came back), /sccs must NOT render an
    empty 0-row table that reads as 'no SCCs exist'. Instead, show a
    Limited View banner pointing at /setup."""
    idx = make_index()       # no SCCs
    idx["fetch_error_kinds"] = {"scc"}
    idx["is_admin"] = False
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/sccs").data.decode()

    assert "SCC inventory not visible" in body
    # The 0-row table must not appear.
    assert '<table class="dense sortable" id="sccs-table">' not in body


def test_sccs_page_shows_table_when_admin_even_if_empty(monkeypatch):
    """Inverse: an admin who legitimately sees 0 SCCs (theoretical)
    should NOT get the "not visible" banner — it would be misleading."""
    idx = make_index()
    idx["fetch_error_kinds"] = set()
    idx["is_admin"] = True
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/sccs").data.decode()
    # 0 rows, but the table renders + the limited banner does NOT fire.
    assert "SCC inventory not visible" not in body


# ---------- /sccs always inline ---------- #

def test_sccs_page_always_renders_inline(monkeypatch):
    """The main /sccs table renders inline regardless of row count.
    SCCs are a small, often-reviewed set; collapsing them by default
    hides the very rows reviewers come to /sccs to see."""
    idx = make_index(sccs=[
        _scc_with(f"scc-{i:02d}", f"2025-0{(i % 9) + 1}-01T00:00:00Z")
        for i in range(12)
    ])
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/sccs").data.decode()

    # No expand wrapper around the main SCC table.
    assert '<details class="expand-details">' not in body
    assert "Click to expand" not in body
    # All 12 rows visible inline.
    for i in range(12):
        assert f">scc-{i:02d}</a>" in body


# ---------- Dashboard card high-but-no-critical ---------- #

def test_dashboard_card_switches_to_high_when_no_critical(monkeypatch, admin_aggregated):
    """A binding that grants `admin` ClusterRole produces a HIGH
    severity resurrectable finding. The dashboard card should adapt:
    'high resurrectable…', `counter-warn`, num = high count, and link
    directly to the high-severity filter."""
    idx = make_index(
        cluster_roles=[admin_aggregated],
        crbs=[{"name": "ghost-admin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "ghost-sa",
                              "namespace": "retired"}],
               "roleRef": {"kind": "ClusterRole", "name": "admin"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as c:
        body = c.get("/").data.decode()

    # No critical → card switches to high.
    assert "high resurrectable" in body
    # Link reflects the chosen severity.
    assert 'href="/identity-audit?severity=high#resurrectable"' in body
    # critical-named card text does NOT appear (would mislead).
    assert "critical resurrectable" not in body


def test_dashboard_card_neutral_when_no_critical_or_high(monkeypatch, view_role):
    """0 critical AND 0 high → card shifts to the neutral "all severities" link."""
    idx = make_index(
        cluster_roles=[view_role],
        crbs=[{"name": "ghost-view",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "ghost-sa",
                              "namespace": "team-a"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with app.test_client() as c:
        body = c.get("/").data.decode()
    assert "resurrectable" in body
    assert "critical resurrectable identities" not in body
    assert "high resurrectable identities" not in body
    assert 'href="/identity-audit?severity=all#resurrectable"' in body
