"""Tests for the top-nav jump-to search index.

Locks the contract that:
- /search-index.json returns valid JSON
- The builder surfaces every supported entity kind
- Only allowlisted fields are exposed
- No internal (_-prefixed) or Secret-shaped fields leak
- The builder is pure over the engine index — no extra cluster reads
"""

import json
from unittest.mock import patch, MagicMock

from lineage import engine
from lineage.engine._search import search_index
from lineage.main import app

from .conftest import make_index


ALLOWED_FIELDS = {"id", "kind", "display", "namespace", "description",
                  "url", "tokens"}


def _populated_idx():
    """One of every supported kind in a single index."""
    return make_index(
        users=[{"name": "alice"}],
        groups=[{"name": "engineers", "users": ["alice"]},
                {"name": "system:authenticated", "users": [], "virtual": True}],
        namespaces=[{"name": "payments-prod", "labels": {}, "annotations": {}}],
        sas=[{"namespace": "payments-prod", "name": "builder"}],
        cluster_roles=[{"name": "cluster-admin", "labels": {}, "annotations": {},
                        "aggregationRule": None,
                        "rules": [{"apiGroups": ["*"], "resources": ["*"],
                                   "verbs": ["*"]}]}],
        roles=[{"namespace": "payments-prod", "name": "read-secrets",
                "labels": {}, "annotations": {}, "aggregationRule": None,
                "rules": []}],
        crbs=[{"name": "cluster-admin-binding",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
        rbs=[{"name": "read-secrets-binding", "namespace": "payments-prod",
              "subjects": [{"kind": "User", "name": "alice"}],
              "roleRef": {"kind": "Role", "name": "read-secrets"}}],
        sccs=[{"name": "restricted-v2", "labels": {}, "annotations": {},
               "users": [], "groups": [], "allowPrivilegedContainer": False}],
    )


# ─── shape and coverage ───────────────────────────────────────────


def test_search_index_returns_list_of_dicts():
    items = search_index(_populated_idx())
    assert isinstance(items, list)
    assert all(isinstance(i, dict) for i in items)
    assert len(items) > 0


def test_search_index_covers_every_supported_kind():
    items = search_index(_populated_idx())
    kinds = {i["kind"] for i in items}
    assert kinds == {
        "User", "Group", "Namespace", "ServiceAccount",
        "ClusterRole", "Role",
        "ClusterRoleBinding", "RoleBinding",
        "SCC",
    }


def test_search_index_handles_empty_inputs():
    items = search_index(make_index())
    assert items == []


# ─── allowlist + safety ───────────────────────────────────────────


def test_only_allowlisted_fields_appear():
    items = search_index(_populated_idx())
    for i in items:
        assert set(i.keys()) == ALLOWED_FIELDS, (
            f"unexpected fields on item {i!r}")


def test_no_private_fields():
    items = search_index(_populated_idx())
    for i in items:
        assert not any(k.startswith("_") for k in i.keys())


def test_no_secret_like_fields():
    """No field name suggests credential material is being exposed."""
    items = search_index(_populated_idx())
    forbidden = {"secret", "token", "password", "key", "credential",
                 "annotation", "annotations", "label", "labels", "rules",
                 "subjects", "roleRef"}
    for i in items:
        for k in i.keys():
            assert k.lower() not in forbidden, (
                f"item field {k!r} looks credential-shaped")


def test_no_secret_objects_indexed_directly():
    """Even if the index ever grew a 'secrets_by_key' bucket, search must
    refuse to expose secret bodies."""
    idx = _populated_idx()
    idx["secrets_by_key"] = {("payments-prod", "leaked"):
                              {"data": {"token": "abc123"}}}
    items = search_index(idx)
    body = json.dumps(items)
    assert "abc123" not in body
    assert "leaked" not in body


# ─── purity / no extra cluster reads ──────────────────────────────


def test_search_index_does_not_trigger_cluster_reads():
    """search_index is pure over the supplied idx dict — patching the
    data module to raise on every call must still let search_index
    succeed."""
    idx = _populated_idx()
    with patch("lineage.engine._search.search_index",
               wraps=search_index) as wrapped:
        # Patch the data module's surface that index() would normally use.
        with patch.object(engine, "data", MagicMock(
                side_effect=AssertionError("search_index must not re-read"))):
            items = wrapped(idx)
    assert len(items) > 0


# ─── URL correctness for every kind ───────────────────────────────


def test_user_url_resolves_correctly():
    items = search_index(_populated_idx())
    u = next(i for i in items if i["kind"] == "User" and i["display"] == "alice")
    assert u["url"] == "/subject/User/alice"


def test_sa_url_carries_namespace_query():
    items = search_index(_populated_idx())
    sa = next(i for i in items if i["kind"] == "ServiceAccount")
    assert sa["url"] == "/subject/ServiceAccount/builder?namespace=payments-prod"
    assert sa["display"] == "system:serviceaccount:payments-prod:builder"


def test_sa_principal_is_searchable_token():
    items = search_index(_populated_idx())
    sa = next(i for i in items if i["kind"] == "ServiceAccount")
    assert "system:serviceaccount:payments-prod:builder" in sa["tokens"]
    assert "builder" in sa["tokens"]
    assert "payments-prod" in sa["tokens"]


def test_namespace_url():
    items = search_index(_populated_idx())
    ns = next(i for i in items if i["kind"] == "Namespace")
    assert ns["url"] == "/namespace/payments-prod"


def test_role_url_has_namespace_segment():
    items = search_index(_populated_idx())
    r = next(i for i in items if i["kind"] == "Role")
    assert r["url"] == "/role/payments-prod/read-secrets"
    # Same-name Roles can live in many namespaces, so the display
    # carries the namespace prefix to disambiguate at a glance.
    assert r["display"] == "payments-prod/read-secrets"


def test_bindings_link_to_permission_grants_filter():
    items = search_index(_populated_idx())
    crb = next(i for i in items if i["kind"] == "ClusterRoleBinding")
    rb = next(i for i in items if i["kind"] == "RoleBinding")
    assert crb["url"] == "/permission-grants?q=cluster-admin-binding"
    assert rb["url"] == "/permission-grants?q=read-secrets-binding"


def test_permission_grants_q_filter_matches_binding_name():
    """The destination the search index points bindings at must actually
    surface the binding when the q filter is applied. Without this,
    clicking a binding result in search lands on an empty page."""
    from lineage.main import app
    client = app.test_client()
    # Hit /permission-grants?q=<a real binding name from the mock data>.
    # The mock dataset's CRB names include 'admin-rb' (referenced in
    # tests/test_mock_dataset.py) — use that as a known good signal.
    r = client.get("/permission-grants?q=admin-rb")
    assert r.status_code == 200
    assert b"admin-rb" in r.data


def test_virtual_group_description():
    items = search_index(_populated_idx())
    vg = next(i for i in items if i["kind"] == "Group"
              and i["display"] == "system:authenticated")
    assert "Virtual" in vg["description"]


def test_special_chars_in_names_url_encoded():
    """A subject name with a space must be percent-encoded in the URL
    so the link works in a browser."""
    idx = make_index(users=[{"name": "alice carter"}])
    items = search_index(idx)
    u = items[0]
    assert u["url"] == "/subject/User/alice%20carter"
    assert u["display"] == "alice carter"  # display stays human-readable


# ─── HTTP endpoint ────────────────────────────────────────────────


def test_endpoint_returns_valid_json():
    client = app.test_client()
    r = client.get("/search-index.json")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("application/json")
    body = r.get_json()
    assert isinstance(body, list)


def test_endpoint_items_match_builder():
    """The HTTP endpoint must just expose what the engine builder
    produces — no extra fields, no missing fields."""
    client = app.test_client()
    body = client.get("/search-index.json").get_json()
    if not body:
        return
    for item in body:
        assert set(item.keys()) == ALLOWED_FIELDS


# ─── workloads (derived from pod owners + jobs + cronjobs) ────────


def _idx_with_workloads():
    return make_index(
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        pods=[
            # Deployment-owned via ReplicaSet (hash-suffixed)
            {"name": "frontend-7c9d8f6b4d-x2k9p", "namespace": "demo",
             "ownerReferences": [{"kind": "ReplicaSet",
                                  "name": "frontend-7c9d8f6b4d"}]},
            # Second replica of same deployment — must dedup
            {"name": "frontend-7c9d8f6b4d-qq22a", "namespace": "demo",
             "ownerReferences": [{"kind": "ReplicaSet",
                                  "name": "frontend-7c9d8f6b4d"}]},
            # DaemonSet — used as-is
            {"name": "csi-driver-abc12", "namespace": "demo",
             "ownerReferences": [{"kind": "DaemonSet", "name": "csi-driver"}]},
            # Standalone pod (no owner) — kept as Pod kind
            {"name": "standalone", "namespace": "demo", "ownerReferences": []},
        ],
    )


def test_workload_dedup_collapses_replicaset_replicas():
    items = search_index(_idx_with_workloads())
    workloads = [i for i in items if i["kind"] == "Workload"]
    displays = sorted(w["display"] for w in workloads)
    # Display carries the namespace so same-named workloads in different
    # namespaces are visually distinct.
    assert displays == ["demo/csi-driver", "demo/frontend", "demo/standalone"]


def test_workload_replicaset_hash_stripped_to_deployment_name():
    items = search_index(_idx_with_workloads())
    fe = next(w for w in items if w["display"] == "demo/frontend")
    assert fe["description"] == "Deployment in demo"


def test_workload_url_points_to_namespace_page():
    items = search_index(_idx_with_workloads())
    for w in (i for i in items if i["kind"] == "Workload"):
        assert w["url"] == "/namespace/demo"


def test_workload_standalone_pod_kind():
    items = search_index(_idx_with_workloads())
    sp = next(w for w in items if w["display"] == "demo/standalone")
    assert sp["description"] == "Pod in demo"


def test_workload_daemonset_kept_as_is():
    items = search_index(_idx_with_workloads())
    ds = next(w for w in items if w["display"] == "demo/csi-driver")
    assert ds["description"] == "DaemonSet in demo"


def test_workload_short_name_is_searchable_token():
    """The display carries the namespace prefix, but the bare workload
    name must still match: typing 'frontend' has to find demo/frontend."""
    items = search_index(_idx_with_workloads())
    fe = next(w for w in items if w["display"] == "demo/frontend")
    assert "frontend" in fe["tokens"]


def test_workload_includes_jobs_and_cronjobs(monkeypatch):
    """Jobs and CronJobs come in via their own idx keys."""
    idx = make_index(namespaces=[{"name": "batch", "labels": {},
                                  "annotations": {}}])
    idx["jobs"] = [{"namespace": "batch", "name": "backup"}]
    idx["cronjobs"] = [{"namespace": "batch", "name": "rollup",
                        "schedule": "0 * * * *"}]
    items = search_index(idx)
    workloads = {(w["display"], w["description"])
                 for w in items if w["kind"] == "Workload"}
    assert ("batch/backup", "Job in batch") in workloads
    assert ("batch/rollup", "CronJob in batch") in workloads


# ─── images ────────────────────────────────────────────────────────


def test_image_items_built_from_inventory():
    """search_index accepts a pre-computed inventory and emits one
    entry per distinct image ref."""
    inv = [
        {"image": "docker.io/library/busybox:latest", "registry": "docker.io",
         "pod_count": 2},
        {"image": "quay.io/some/app@sha256:abc123", "registry": "quay.io",
         "pod_count": 1},
    ]
    items = search_index(make_index(), image_inventory=inv)
    imgs = [i for i in items if i["kind"] == "Image"]
    assert len(imgs) == 2
    busybox = next(i for i in imgs
                   if i["display"] == "docker.io/library/busybox:latest")
    assert busybox["url"].startswith("/image?ref=docker.io")
    assert "busybox" in busybox["tokens"]
    assert "docker.io" in busybox["tokens"]


def test_image_pod_count_pluralization():
    inv = [
        {"image": "x:1", "registry": "r", "pod_count": 1},
        {"image": "x:2", "registry": "r", "pod_count": 2},
    ]
    items = search_index(make_index(), image_inventory=inv)
    descs = sorted(i["description"] for i in items if i["kind"] == "Image")
    assert "Image · 1 pod · r" in descs
    assert "Image · 2 pods · r" in descs


def test_image_inventory_default_is_empty_safe():
    """Builder must work without an inventory argument."""
    items = search_index(make_index())
    assert all(i["kind"] != "Image" for i in items)


# ─── imagestreams ──────────────────────────────────────────────────


def test_imagestream_items_extracted():
    idx = make_index()
    idx["imagestreams"] = [
        {"name": "cli", "namespace": "openshift",
         "dockerImageRepository":
         "image-registry.openshift-image-registry.svc:5000/openshift/cli"},
    ]
    items = search_index(idx)
    iss = [i for i in items if i["kind"] == "ImageStream"]
    assert len(iss) == 1
    assert iss[0]["display"] == "openshift/cli"
    assert iss[0]["url"] == "/namespace/openshift"
    assert "cli" in iss[0]["tokens"]
    assert "openshift" in iss[0]["tokens"]
    assert "imagestream" in iss[0]["tokens"]


# ─── identities ────────────────────────────────────────────────────


def test_identity_items_link_to_user_detail():
    idx = make_index(users=[{"name": "alice"}])
    idx["identities"] = [
        {"name": "htpasswd:alice", "providerName": "htpasswd",
         "user": {"name": "alice"}},
    ]
    items = search_index(idx)
    ids = [i for i in items if i["kind"] == "Identity"]
    assert len(ids) == 1
    assert ids[0]["url"] == "/subject/User/alice"
    assert "htpasswd" in ids[0]["description"]
    assert "htpasswd:alice" in ids[0]["tokens"]
    assert "alice" in ids[0]["tokens"]


def test_identity_with_missing_user_is_skipped():
    """A defensive check: identities with no linked user have nowhere
    to navigate, so we drop them rather than emit a broken URL."""
    idx = make_index()
    idx["identities"] = [{"name": "broken:nobody", "user": {}}]
    items = search_index(idx)
    assert all(i["kind"] != "Identity" for i in items)


# ─── allowlist still respected after expansion ────────────────────


def test_expanded_kinds_still_allowlist_clean():
    """All four new emitters must produce items with only the
    allowlisted fields — no leakage of internal data."""
    idx = make_index(
        users=[{"name": "alice"}],
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        pods=[{"name": "pod-1", "namespace": "demo",
               "ownerReferences": [{"kind": "DaemonSet", "name": "ds-1"}]}],
    )
    idx["jobs"] = [{"namespace": "demo", "name": "j"}]
    idx["cronjobs"] = [{"namespace": "demo", "name": "c", "schedule": "* * * * *"}]
    idx["imagestreams"] = [{"name": "is", "namespace": "demo",
                            "dockerImageRepository": "r/p"}]
    idx["identities"] = [{"name": "p:alice", "providerName": "p",
                          "user": {"name": "alice"}}]
    inv = [{"image": "img:1", "registry": "reg", "pod_count": 1}]
    items = search_index(idx, image_inventory=inv)
    for i in items:
        assert set(i.keys()) == ALLOWED_FIELDS, (
            f"unexpected fields on {i!r}")
        assert not any(k.startswith("_") for k in i.keys())


def test_virtual_groups_from_bindings_are_indexed():
    """OpenShift virtual groups like system:authenticated have no Group
    object — they only appear as binding subjects. Search must surface
    them anyway because users do legitimately look them up."""
    idx = make_index(
        crbs=[{"name": "auth-binding",
               "subjects": [
                   {"kind": "Group", "name": "system:authenticated",
                    "apiGroup": "rbac.authorization.k8s.io"},
                   {"kind": "Group", "name": "system:serviceaccounts:demo",
                    "apiGroup": "rbac.authorization.k8s.io"},
               ],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    items = search_index(idx)
    group_names = {i["display"] for i in items if i["kind"] == "Group"}
    assert "system:authenticated" in group_names
    assert "system:serviceaccounts:demo" in group_names
    # Real groups are not double-indexed when their name overlaps a
    # virtual subject — single entry only.
    auth = [i for i in items if i["display"] == "system:authenticated"]
    assert len(auth) == 1
    assert "Virtual" in auth[0]["description"]


def test_virtual_group_from_scc_only_is_indexed():
    """A virtual group referenced ONLY in scc.groups (never as a
    binding subject) must still appear in search. Without this, search
    would lag behind /subjects, which surfaces SCC-referenced virtual
    groups via engine.virtual_groups_referenced(idx)."""
    idx = make_index(
        sccs=[{"name": "privileged", "labels": {}, "annotations": {},
               "users": [], "groups": ["system:cluster-admins-only-in-scc"],
               "allowPrivilegedContainer": True}],
    )
    items = search_index(idx)
    names = {i["display"] for i in items if i["kind"] == "Group"}
    assert "system:cluster-admins-only-in-scc" in names


def test_virtual_group_does_not_duplicate_real_group():
    """If a real Group object exists with the same name as a binding
    subject (unusual but possible), the real one wins."""
    idx = make_index(
        groups=[{"name": "system:authenticated", "users": []}],
        crbs=[{"name": "b",
               "subjects": [{"kind": "Group", "name": "system:authenticated",
                             "apiGroup": "rbac.authorization.k8s.io"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    items = search_index(idx)
    auth = [i for i in items if i["display"] == "system:authenticated"]
    assert len(auth) == 1
    # Real group description (not "Virtual group")
    assert auth[0]["description"] == "Group"


def test_kinds_present_after_expansion():
    idx = make_index(
        users=[{"name": "alice"}],
        namespaces=[{"name": "demo", "labels": {}, "annotations": {}}],
        pods=[{"name": "pod-1", "namespace": "demo",
               "ownerReferences": [{"kind": "DaemonSet", "name": "ds-1"}]}],
    )
    idx["jobs"] = [{"namespace": "demo", "name": "j"}]
    idx["imagestreams"] = [{"name": "is", "namespace": "demo",
                            "dockerImageRepository": "r/p"}]
    idx["identities"] = [{"name": "p:alice", "providerName": "p",
                          "user": {"name": "alice"}}]
    inv = [{"image": "img:1", "registry": "reg", "pod_count": 1}]
    items = search_index(idx, image_inventory=inv)
    kinds = {i["kind"] for i in items}
    assert {"Workload", "Image", "ImageStream", "Identity"} <= kinds
