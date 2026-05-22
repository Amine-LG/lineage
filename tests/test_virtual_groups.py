"""Virtual / system Group surfacing tests."""

from lineage import engine
from lineage.main import app
from .conftest import make_index


# ---------- engine.virtual_groups_referenced ---------- #

def test_virtual_groups_referenced_collects_from_bindings():
    idx = make_index(
        crbs=[
            {"name": "oauth-self", "subjects": [
                {"kind": "Group", "name": "system:authenticated:oauth"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
            {"name": "real-people", "subjects": [
                {"kind": "Group", "name": "engineers"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
        ],
        groups=[{"name": "engineers", "users": ["eve"]}],
    )
    assert engine.virtual_groups_referenced(idx) == [
        "system:authenticated:oauth"
    ]


def test_virtual_groups_referenced_collects_from_scc_groups():
    idx = make_index(
        sccs=[{"name": "restricted-v2",
               "users": [],
               "groups": ["system:authenticated"]}],
    )
    assert "system:authenticated" in engine.virtual_groups_referenced(idx)


def test_virtual_groups_referenced_excludes_real_groups():
    """A 'system:'-prefixed name that DOES exist as a Group object should
    not be treated as virtual."""
    idx = make_index(
        groups=[{"name": "system:masters", "users": []}],
        crbs=[{"name": "masters",
               "subjects": [{"kind": "Group", "name": "system:masters"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )
    assert "system:masters" not in engine.virtual_groups_referenced(idx)


# ---------- engine.describe_virtual_group ---------- #

def test_describe_virtual_group_uses_generic_mechanism_note():
    """No per-name hardcoded descriptions. Every system:* name that
    isn't the structural SA convention gets the same generic note that
    describes the apiserver mechanism — Lineage does not assert a
    curated meaning for each well-known name."""
    samples = [
        "system:authenticated",
        "system:authenticated:oauth",
        "system:masters",
        "system:nodes",
        "system:cluster-admins",
        "system:openshift:some-future-thing",
    ]
    notes = [engine.describe_virtual_group(n) for n in samples]
    # All non-SA descriptions are identical — proves no dictionary lookup.
    assert len(set(notes)) == 1
    assert "Synthesized by the apiserver" in notes[0]
    assert "bindings below" in notes[0]


def test_describe_virtual_group_serviceaccounts_namespace_counts_sas():
    """The system:serviceaccounts:<ns> convention is structural — its
    membership is derivable from the index, so the description includes
    a current count and namespace-presence note."""
    idx = make_index(
        namespaces=[{"name": "team-a", "labels": {}, "annotations": {}}],
        sas=[
            {"name": "default", "namespace": "team-a"},
            {"name": "builder", "namespace": "team-a"},
        ],
    )
    note = engine.describe_virtual_group("system:serviceaccounts:team-a", idx)
    assert "team-a" in note
    assert "2 ServiceAccounts" in note
    assert "namespace present" in note


def test_describe_virtual_group_serviceaccounts_namespace_absent():
    """If the referenced namespace is gone, surface that — derivable
    from observable index state, no name knowledge."""
    idx = make_index()  # no namespaces, no SAs
    note = engine.describe_virtual_group(
        "system:serviceaccounts:legacy", idx)
    assert "legacy" in note
    assert "not visible" in note or "recreated" in note


def test_describe_virtual_group_escapes_serviceaccount_namespace_html():
    idx = make_index()
    note = engine.describe_virtual_group(
        "system:serviceaccounts:<script>alert(1)</script>", idx)
    assert "<script>" not in note
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in note


def test_describe_virtual_group_all_serviceaccounts_counts_total():
    idx = make_index(sas=[
        {"name": "default", "namespace": "a"},
        {"name": "builder", "namespace": "b"},
        {"name": "default", "namespace": "b"},
    ])
    note = engine.describe_virtual_group("system:serviceaccounts", idx)
    assert "every namespace" in note
    assert "3 currently visible" in note


def test_describe_virtual_group_non_system_returns_none():
    assert engine.describe_virtual_group("engineers") is None
    assert engine.describe_virtual_group("") is None


def test_engine_has_no_hardcoded_virtual_group_dictionary():
    """Virtual group descriptions should come from structural rules."""
    import inspect
    src = inspect.getsource(engine)
    assert "_VIRTUAL_GROUP_DESCRIPTIONS" not in src


# ---------- all_subjects surfaces virtual groups ---------- #

def test_all_subjects_includes_virtual_group(make_idx):
    idx = make_idx(
        crbs=[{"name": "oauth-self",
               "subjects": [{"kind": "Group",
                              "name": "system:authenticated:oauth"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    subjects = engine.all_subjects(idx)
    row = next((s for s in subjects
                if s["kind"] == "Group"
                and s["name"] == "system:authenticated:oauth"), None)
    assert row is not None
    assert row.get("virtual") is True
    assert row.get("baseline") is True
    assert row.get("ghost") is False


def test_all_subjects_classifies_serviceaccount_virtual_group_by_namespace(
        make_idx):
    idx = make_idx(
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        rbs=[{"name": "team-a-sas", "namespace": "team-a",
              "subjects": [{"kind": "Group",
                             "name": "system:serviceaccounts:team-a"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )

    subjects = engine.all_subjects(idx)
    row = next(s for s in subjects
               if s["kind"] == "Group"
               and s["name"] == "system:serviceaccounts:team-a")

    assert row["virtual"] is True
    assert row["baseline"] is False
    assert row["unknown"] is False


def test_all_subjects_marks_missing_namespace_serviceaccount_group_unknown(
        make_idx):
    idx = make_idx(
        crbs=[{"name": "future-sas",
               "subjects": [{"kind": "Group",
                              "name": "system:serviceaccounts:future-team"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )

    subjects = engine.all_subjects(idx)
    row = next(s for s in subjects
               if s["kind"] == "Group"
               and s["name"] == "system:serviceaccounts:future-team")

    assert row["virtual"] is True
    assert row["baseline"] is False
    assert row["unknown"] is True


def test_all_subjects_does_not_duplicate_real_group(make_idx):
    """A system:masters Group that exists as an object should appear once,
    not as both real and virtual."""
    idx = make_idx(
        groups=[{"name": "system:masters", "users": []}],
        crbs=[{"name": "masters",
               "subjects": [{"kind": "Group", "name": "system:masters"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )
    subjects = engine.all_subjects(idx)
    matches = [s for s in subjects
               if s["kind"] == "Group" and s["name"] == "system:masters"]
    assert len(matches) == 1
    assert matches[0].get("virtual") is not True  # real Group, not virtual


# ---------- /subjects page renders the virtual badge ---------- #

def test_subjects_page_lists_virtual_group_with_badge(monkeypatch, make_idx):
    idx = make_idx(
        crbs=[{"name": "oauth-self",
               "subjects": [{"kind": "Group",
                              "name": "system:authenticated:oauth"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        # Virtual groups are baseline-classified; surface them on bucket=all.
        body = client.get(
            "/subjects?bucket=all&kind=Group"
        ).data.decode()

    assert "system:authenticated:oauth" in body
    assert ">virtual</span>" in body


# ---------- /subject/Group/<system:*> detail page ---------- #

def test_subject_detail_virtual_group_shows_banner_and_badge(
        monkeypatch, make_idx):
    idx = make_idx(
        crbs=[{"name": "oauth-self",
               "subjects": [{"kind": "Group",
                              "name": "system:authenticated:oauth"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        cluster_roles=[{"name": "view", "labels": {}, "annotations": {},
                         "aggregationRule": None,
                         "rules": [{"apiGroups": [""], "resources": ["pods"],
                                    "verbs": ["get"]}]}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get(
            "/subject/Group/system:authenticated:oauth"
        ).data.decode()

    assert "Virtual / system group" in body
    assert ">virtual</span>" in body
    # Misleading "isn't populated" message must not appear for virtual groups.
    assert "Group exists but isn't populated" not in body
    # The Members heading should not render either — there is no member
    # concept for a virtual group.
    assert "<h2>Members (" not in body


def test_subject_detail_real_empty_group_still_shows_isnt_populated(
        monkeypatch, make_idx):
    """Regression guard: the original 'isn't populated' line still appears
    for a *real* but empty Group object, since that case is genuinely an
    unpopulated cluster object, not a virtual one."""
    idx = make_idx(
        groups=[{"name": "empty-team", "users": []}],
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/subject/Group/empty-team").data.decode()

    assert "Group exists but isn't populated" in body
    assert "Virtual / system group" not in body


def test_subject_detail_nonexistent_non_system_group_still_ghosts(
        monkeypatch, make_idx):
    """The other arm of the user's report: NonexistingEntity (no system:
    prefix, not virtual) should continue to surface as a ghost."""
    idx = make_idx()
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)

    with app.test_client() as client:
        body = client.get("/subject/Group/NonexistingEntity").data.decode()

    assert ">ghost</span>" in body
    assert "Virtual / system group" not in body


# ---------- macro consistency ---------- #

def test_markers_macro_renders_virtual_badge_with_tooltip():
    """Spot-check that the macro emits the tooltip explaining what virtual
    means so reviewers can tell why the badge appeared."""
    with app.test_client() as client:
        body = client.get(
            "/subject/Group/system:authenticated:oauth"
        ).data.decode()
    assert 'title="Synthesized by the apiserver' in body
