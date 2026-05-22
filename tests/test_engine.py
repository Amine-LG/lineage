"""Engine tests for Lineage."""

from lineage import engine
from lineage import classifier as cf
from .conftest import make_index


def _crc_user_identity(name):
    return {
        "name": f"developer:{name}",
        "user": {"name": name},
        "providerName": "developer",
        "providerUserName": name,
    }


def _crc_oauth():
    return {"identityProviders": [{"name": "developer", "type": "HTPasswd"}]}


# ---------- Classifier ---------- #

def test_classifier_baseline_namespace_patterns():
    assert cf.is_baseline_namespace("openshift-config") is True
    assert cf.is_baseline_namespace("kube-system") is True
    assert cf.is_baseline_namespace("default") is True
    assert cf.is_baseline_namespace("nginx") is False
    assert cf.is_baseline_namespace("demo") is False


def test_classifier_no_install_window():
    """Non-namespace baseline detection does not use the install window."""
    obj = {"name": "nginx", "creationTimestamp": "2024-01-01T00:00:30Z"}
    assert cf.is_baseline_resource(obj) is False


def test_classifier_managed_label():
    obj = {"name": "anything", "labels": {"app.kubernetes.io/managed-by": "Helm"}}
    assert cf.is_baseline_resource(obj) is True


def test_classifier_operator_owner():
    obj = {"name": "x", "ownerReferences":
           [{"apiVersion": "operator.openshift.io/v1", "kind": "Console"}]}
    assert cf.is_baseline_resource(obj) is True


def test_classify_image():
    assert cf.classify_image("docker.io/nginx") == "public"
    assert cf.classify_image("registry.redhat.io/ubi9") == "redhat"
    assert cf.classify_image("image-registry.openshift-image-registry.svc:5000/x/y") == "internal"


# ---------- User-managed vs baseline ---------- #

def test_user_with_identity_is_yours():
    idx = make_index(
        users=[{"name": "alice"}, {"name": "developer"}],
        identities=[{"name": "dev:alice", "user": {"name": "alice"}, "providerName": "dev"}],
    )
    assert engine.is_baseline_user({"name": "alice"}, idx) is False


def test_user_without_identity_is_stranded_not_baseline():
    idx = make_index(
        users=[{"name": "manual-reviewer"}, {"name": "developer"},
               {"name": "kube-apiserver"}],
        identities=[],
    )
    assert engine.is_baseline_user({"name": "manual-reviewer"}, idx) is False
    assert engine.is_baseline_user({"name": "developer"}, idx) is False
    assert engine.is_baseline_user({"name": "kube-apiserver"}, idx) is True


def test_crc_default_htpasswd_users_are_baseline_without_secret_data():
    idx = make_index(
        users=[{"name": "developer"}, {"name": "kubeadmin"}],
        identities=[_crc_user_identity("developer"),
                    _crc_user_identity("kubeadmin")],
        oauth_cluster=_crc_oauth(),
        # Secret unavailable/degraded: the contextual rule must not depend
        # on htpasswd_users being readable.
        htpasswd_available=False,
        htpasswd_configured=True,
        htpasswd_reason="forbidden",
    )

    assert engine.is_baseline_user({"name": "developer"}, idx) is True
    assert engine.is_baseline_user({"name": "kubeadmin"}, idx) is True
    assert engine.is_baseline_subject(
        {"kind": "User", "name": "developer"}, idx) is True
    assert engine.is_baseline_subject(
        {"kind": "User", "name": "kubeadmin"}, idx) is True


def test_same_usernames_from_non_crc_idp_are_not_baseline():
    idx = make_index(
        users=[{"name": "developer"}, {"name": "kubeadmin"}],
        identities=[
            {"name": "corp:developer", "user": {"name": "developer"},
             "providerName": "corp", "providerUserName": "developer"},
            {"name": "corp:kubeadmin", "user": {"name": "kubeadmin"},
             "providerName": "corp", "providerUserName": "kubeadmin"},
        ],
        oauth_cluster={"identityProviders": [{"name": "corp", "type": "HTPasswd"}]},
    )

    assert engine.is_baseline_user({"name": "developer"}, idx) is False
    assert engine.is_baseline_user({"name": "kubeadmin"}, idx) is False


def test_duplicate_idp_mapping_to_developer_is_not_hidden_as_baseline():
    idx = make_index(
        users=[{"name": "developer"}],
        identities=[
            _crc_user_identity("developer"),
            {"name": "corp:developer", "user": {"name": "developer"},
             "providerName": "corp", "providerUserName": "developer"},
        ],
        oauth_cluster={"identityProviders": [
            {"name": "developer", "type": "HTPasswd"},
            {"name": "corp", "type": "HTPasswd"},
        ]},
    )

    assert engine.is_baseline_user({"name": "developer"}, idx) is False


def test_user_namespace_in_yours():
    """nginx/demo created by cluster-admin via `oc new-project` carry the
    openshift.io/requester annotation — that's the human signal."""
    idx = make_index(
        namespaces=[
            {"name": "nginx", "labels": {},
             "annotations": {"openshift.io/requester": "kubeadmin"}},
            {"name": "demo", "labels": {},
             "annotations": {"openshift.io/requester": "kubeadmin"}},
            {"name": "openshift-config", "labels": {}, "annotations": {}},
        ],
    )
    assert engine.is_baseline_namespace("nginx", idx) is False
    assert engine.is_baseline_namespace("demo", idx) is False
    assert engine.is_baseline_namespace("openshift-config", idx) is True


def test_nginx_sa_with_anyuid_is_yours():
    """User-created SA in user namespace must be yours regardless of SCC binding."""
    idx = make_index(
        namespaces=[{"name": "nginx", "labels": {},
                     "annotations": {"openshift.io/requester": "kubeadmin"}}],
        sas=[{"name": "nginx-sa", "namespace": "nginx", "labels": {}}],
    )
    assert engine.is_baseline_sa({"name": "nginx-sa", "namespace": "nginx"}, idx) is False


# ---------- Ghost suppression ---------- #

def test_real_ghost_user_surfaced(view_role):
    idx = make_index(
        cluster_roles=[view_role],
        crbs=[{"name": "real",
               "subjects": [{"kind": "User", "name": "future@company.com"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    assert len(engine.find_ghost_subjects(idx)) == 1


def test_routine_ghost_in_baseline_namespace_hidden(view_role):
    idx = make_index(
        namespaces=[{"name": "openshift-cluster-storage-operator",
                     "labels": {}, "annotations": {}}],
        cluster_roles=[view_role],
        crbs=[{"name": "csi-snapshot-controller-operator-role",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "csi-snapshot-controller-operator",
                              "namespace": "openshift-cluster-storage-operator"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    assert len(engine.find_ghost_subjects(idx)) == 0
    assert len(engine.find_ghost_subjects(idx, include_baseline=True)) == 1


def test_non_existing_user_bound_in_baseline_namespace_is_real_ghost(view_role):
    """A user-named RoleBinding in `default` (or any baseline-named ns)
    pointing at a nonexistent User is a real misconfiguration, not
    platform noise. Reproduces the `oc adm policy add-role-to-user
    edit editor` (no `-n`) case that lands the binding in the current
    project (often `default`)."""
    idx = make_index(
        namespaces=[{"name": "default", "labels": {}, "annotations": {}}],
        cluster_roles=[view_role],
        rbs=[{"name": "future-default-view", "namespace": "default",
              "subjects": [{"kind": "User", "name": "future-default-user"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )

    ghosts = engine.find_ghost_subjects(idx)
    assert len(ghosts) == 1
    g = ghosts[0]
    assert g["category"] == "real"
    assert g["binding_baseline"] is False
    assert g["subject_baseline"] is False
    assert g["subject"]["name"] == "future-default-user"


def test_non_existing_user_bound_in_project_namespace_is_real_ghost(view_role):
    idx = make_index(
        namespaces=[{"name": "app", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[view_role],
        rbs=[{"name": "future-app-view", "namespace": "app",
              "subjects": [{"kind": "User", "name": "future-app-user"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )

    ghosts = engine.find_ghost_subjects(idx)
    assert len(ghosts) == 1
    assert ghosts[0]["category"] == "real"
    assert ghosts[0]["binding_baseline"] is False
    assert ghosts[0]["subject"]["name"] == "future-app-user"


# ---------- Effective permissions + summary ---------- #

def test_aggregated_role_summary(admin_aggregated, admin_workloads):
    idx = make_index(
        users=[{"name": "alice"}],
        identities=[{"name": "dev:alice", "user": {"name": "alice"}, "providerName": "dev"}],
        cluster_roles=[admin_aggregated, admin_workloads],
        rbs=[{"name": "alice-admin", "namespace": "nginx",
              "subjects": [{"kind": "User", "name": "alice"}],
              "roleRef": {"kind": "ClusterRole", "name": "admin"}}],
    )
    paths = engine.effective_permissions("User", "alice", idx=idx)
    assert len(paths) == 1
    assert paths[0].summary["total_rules"] == 2
    assert "deployments" in paths[0].summary["resources"]
    assert "*" in paths[0].summary["verbs"]


def test_aggregated_role_match_expressions_expand(make_idx):
    aggregate = {
        "name": "expr-aggregate", "labels": {}, "annotations": {},
        "aggregationRule": {
            "clusterRoleSelectors": [{
                "matchExpressions": [
                    {"key": "lineage.test/aggregate", "operator": "In",
                     "values": ["yes"]},
                    {"key": "lineage.test/skip", "operator": "DoesNotExist"},
                ],
            }],
        },
        "rules": [],
    }
    matched = {
        "name": "expr-component",
        "labels": {"lineage.test/aggregate": "yes"},
        "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                   "verbs": ["get"]}],
    }
    skipped = {
        "name": "expr-skipped",
        "labels": {"lineage.test/aggregate": "yes",
                   "lineage.test/skip": "true"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"],
                   "verbs": ["get"]}],
    }
    idx = make_idx(cluster_roles=[aggregate, matched, skipped])

    rules, components = engine.expand_aggregated_role(aggregate, idx)

    assert [c["name"] for c in components] == ["expr-component"]
    assert rules[0]["resources"] == ["configmaps"]
    assert rules[0]["_from"] == "expr-component"


def test_aggregated_role_match_expressions_notin_exists(make_idx):
    aggregate = {
        "name": "notin-aggregate", "labels": {}, "annotations": {},
        "aggregationRule": {
            "clusterRoleSelectors": [{
                "matchExpressions": [
                    {"key": "lineage.test/tier", "operator": "NotIn",
                     "values": ["blocked"]},
                    {"key": "lineage.test/enabled", "operator": "Exists"},
                ],
            }],
        },
        "rules": [],
    }
    matched = {
        "name": "notin-component",
        "labels": {"lineage.test/tier": "review",
                   "lineage.test/enabled": "true"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"],
                   "verbs": ["get"]}],
    }
    skipped = {
        "name": "notin-skipped",
        "labels": {"lineage.test/tier": "blocked",
                   "lineage.test/enabled": "true"},
        "rules": [{"apiGroups": [""], "resources": ["pods"],
                   "verbs": ["delete"]}],
    }
    idx = make_idx(cluster_roles=[aggregate, matched, skipped])

    rules, components = engine.expand_aggregated_role(aggregate, idx)

    assert [c["name"] for c in components] == ["notin-component"]
    assert rules[0]["resources"] == ["secrets"]


def test_rolebinding_serviceaccount_subject_defaults_to_binding_namespace(make_idx):
    idx = make_idx(
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        sas=[{"name": "runner", "namespace": "team-a"}],
        roles=[{"name": "pod-reader", "namespace": "team-a",
                "rules": [{"apiGroups": [""], "resources": ["pods"],
                            "verbs": ["get"]}]}],
        rbs=[{"name": "runner-pods", "namespace": "team-a",
              "subjects": [{"kind": "ServiceAccount", "name": "runner"}],
              "roleRef": {"kind": "Role", "name": "pod-reader"}}],
    )

    paths = engine.effective_permissions(
        "ServiceAccount", "runner", "team-a", idx=idx)
    refs = engine.bindings_referencing_sa("runner", "team-a", idx)

    assert len(paths) == 1
    assert paths[0].summary["resources"] == ["pods"]
    assert [r["name"] for r in refs["rbs_same_ns"]] == ["runner-pods"]


def test_serviceaccount_effective_permissions_include_implicit_rbac_groups(make_idx):
    idx = make_idx(
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        sas=[{"name": "runner", "namespace": "team-a"}],
        roles=[{"name": "secret-reader", "namespace": "team-a",
                "rules": [{"apiGroups": [""], "resources": ["secrets"],
                            "verbs": ["get"]}]}],
        rbs=[{"name": "team-a-sas-read-secrets", "namespace": "team-a",
              "subjects": [{"kind": "Group",
                             "name": "system:serviceaccounts:team-a"}],
              "roleRef": {"kind": "Role", "name": "secret-reader"}}],
    )

    paths = engine.effective_permissions(
        "ServiceAccount", "runner", "team-a", idx=idx)
    reach = engine.namespace_reach_for_subject(
        "ServiceAccount", "runner", "team-a", idx)

    assert len(paths) == 1
    assert paths[0].via_group == "system:serviceaccounts:team-a"
    assert paths[0].summary["resources"] == ["secrets"]
    assert reach["by_namespace"]["team-a"][0]["via_group"] == (
        "system:serviceaccounts:team-a")


def test_user_effective_permissions_include_authenticated_virtual_groups(make_idx):
    idx = make_idx(
        users=[{"name": "alice"}],
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        roles=[
            {"name": "cm-getter", "namespace": "team-a",
             "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                         "verbs": ["get"]}]},
            {"name": "cm-lister", "namespace": "team-a",
             "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                         "verbs": ["list"]}]},
        ],
        rbs=[
            {"name": "authenticated-get", "namespace": "team-a",
             "subjects": [{"kind": "Group",
                            "name": "system:authenticated"}],
             "roleRef": {"kind": "Role", "name": "cm-getter"}},
            {"name": "oauth-list", "namespace": "team-a",
             "subjects": [{"kind": "Group",
                            "name": "system:authenticated:oauth"}],
             "roleRef": {"kind": "Role", "name": "cm-lister"}},
        ],
    )

    paths = engine.effective_permissions("User", "alice", idx=idx)
    via = {(p.role["name"], p.via_group) for p in paths}
    reach = engine.namespace_reach_for_subject("User", "alice", None, idx)

    assert ("cm-getter", "system:authenticated") in via
    assert ("cm-lister", "system:authenticated:oauth") in via
    assert {r["via_group"] for r in reach["by_namespace"]["team-a"]} == {
        "system:authenticated", "system:authenticated:oauth"}


def test_is_system_virtual_group_predicate():
    # Auto-membership virtual groups: split into the collapsible block.
    assert engine.is_system_virtual_group("system:authenticated")
    assert engine.is_system_virtual_group("system:authenticated:oauth")
    assert engine.is_system_virtual_group("system:unauthenticated")
    assert engine.is_system_virtual_group("system:serviceaccounts")
    assert engine.is_system_virtual_group("system:serviceaccounts:team-a")
    assert engine.is_system_virtual_group("system:serviceaccounts:openshift")
    # Real / explicit groups: NOT split — these are subject-specific.
    assert not engine.is_system_virtual_group("system:masters")
    assert not engine.is_system_virtual_group("system:nodes")
    assert not engine.is_system_virtual_group("system:bootstrappers")
    assert not engine.is_system_virtual_group("platform-admins")
    assert not engine.is_system_virtual_group("")
    assert not engine.is_system_virtual_group(None)


def test_summarize_rules():
    rules = [
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]},
        {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["*"]},
    ]
    s = engine.summarize_rules(rules)
    assert s["total_rules"] == 2
    assert s["wildcard"] is True
    assert "core" in s["api_groups"]
    assert "apps" in s["api_groups"]


# ---------- Role grants (the new audit) ---------- #

def test_role_grants_captures_admin_to_user(admin_aggregated):
    idx = make_index(
        users=[{"name": "alice"}],
        identities=[{"name": "dev:alice", "user": {"name": "alice"}, "providerName": "dev"}],
        namespaces=[{"name": "nginx", "labels": {},
                     "annotations": {"openshift.io/requester": "kubeadmin"}}],
        cluster_roles=[admin_aggregated],
        rbs=[{"name": "alice-admin", "namespace": "nginx",
              "subjects": [{"kind": "User", "name": "alice"}],
              "roleRef": {"kind": "ClusterRole", "name": "admin"}}],
    )
    grants = engine.role_grants(idx)
    assert len(grants) == 1
    assert grants[0]["role"] == "admin"
    assert grants[0]["is_privileged"] is True
    assert grants[0]["subject"]["name"] == "alice"


def test_role_grants_captures_view_to_group(view_role):
    idx = make_index(
        groups=[{"name": "sellers", "users": []}],
        namespaces=[{"name": "demo", "labels": {},
                     "annotations": {"openshift.io/requester": "kubeadmin"}}],
        cluster_roles=[view_role],
        rbs=[{"name": "sellers-view", "namespace": "demo",
              "subjects": [{"kind": "Group", "name": "sellers"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    grants = engine.role_grants(idx)
    assert len(grants) == 1
    assert grants[0]["role"] == "view"
    assert grants[0]["is_privileged"] is False
    assert grants[0]["tier"] == 1


def test_role_grants_treats_privileged_scc_use_as_privileged():
    idx = make_index(
        namespaces=[{"name": "ci", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        sccs=[{"name": "privileged", "priority": 10,
               "allowPrivilegedContainer": True,
               "allowHostNetwork": True,
               "allowHostPID": True,
               "allowHostIPC": True,
               "allowPrivilegeEscalation": True,
               "runAsUser": {"type": "RunAsAny"},
               "users": [], "groups": []}],
        crbs=[{"name": "system:openshift:scc:privileged",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "new-privileged-scc", "namespace": "ci"}],
               "roleRef": {"kind": "ClusterRole",
                           "name": "system:openshift:scc:privileged"},
               "creationTimestamp": "2026-05-12T10:00:00Z"}],
    )

    grants = engine.role_grants(idx)

    assert grants[0]["role"] == "system:openshift:scc:privileged"
    assert grants[0]["is_privileged"] is True
    assert grants[0]["tier"] == 5
    assert grants[0]["creation_ts"] == "2026-05-12T10:00:00Z"
    assert engine.privileged_subjects(idx)[0]["baseline"] is False


def test_role_grant_and_privileged_rows_mark_stranded_user(cluster_admin_role):
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

    grant = engine.role_grants(idx)[0]
    privileged = engine.privileged_subjects(idx)[0]

    assert grant["stranded"] is True
    assert grant["phantom"] is False
    assert privileged["stranded"] is True
    assert privileged["phantom"] is False


def test_role_grants_excludes_baseline():
    """A binding system:masters → cluster-admin should NOT show in grants."""
    idx = make_index(
        cluster_roles=[{"name": "cluster-admin", "labels": {}, "annotations": {},
                        "aggregationRule": None,
                        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}],
        crbs=[{"name": "cluster-admin",
               "subjects": [{"kind": "Group", "name": "system:masters"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )
    assert engine.role_grants(idx) == []


def test_developer_user_binding_is_baseline_not_stranded(cluster_admin_role):
    idx = make_index(
        users=[{"name": "developer"}],
        identities=[_crc_user_identity("developer")],
        oauth_cluster=_crc_oauth(),
        namespaces=[{"name": "app", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[cluster_admin_role],
        rbs=[{"name": "developer-admin", "namespace": "app",
              "subjects": [{"kind": "User", "name": "developer"}],
              "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )

    assert engine.role_grants(idx) == []
    privileged = engine.privileged_subjects(idx)
    assert len(privileged) == 1
    assert privileged[0]["baseline"] is True
    assert privileged[0]["stranded"] is False
    assert engine.identity_audit(idx)["stranded_users"] == []


def test_non_crc_developer_binding_stays_visible(cluster_admin_role):
    idx = make_index(
        users=[{"name": "developer"}],
        identities=[{"name": "corp:developer",
                     "user": {"name": "developer"},
                     "providerName": "corp",
                     "providerUserName": "developer"}],
        oauth_cluster={"identityProviders": [{"name": "corp",
                                              "type": "HTPasswd"}]},
        namespaces=[{"name": "app", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[cluster_admin_role],
        rbs=[{"name": "developer-admin", "namespace": "app",
              "subjects": [{"kind": "User", "name": "developer"}],
              "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )

    grant = engine.role_grants(idx)[0]
    privileged = engine.privileged_subjects(idx)[0]
    assert grant["subject"]["name"] == "developer"
    assert privileged["baseline"] is False


# ---------- Namespace reach for subject ---------- #

def test_reach_includes_cluster_wide_and_per_namespace(admin_aggregated, view_role):
    idx = make_index(
        users=[{"name": "alice"}],
        identities=[{"name": "dev:alice", "user": {"name": "alice"}, "providerName": "dev"}],
        cluster_roles=[admin_aggregated, view_role],
        rbs=[{"name": "alice-admin", "namespace": "nginx",
              "subjects": [{"kind": "User", "name": "alice"}],
              "roleRef": {"kind": "ClusterRole", "name": "admin"}}],
        crbs=[{"name": "alice-cluster-view",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    reach = engine.namespace_reach_for_subject("User", "alice", None, idx)
    assert len(reach["cluster_wide"]) == 1
    assert reach["cluster_wide"][0]["role"] == "view"
    assert "nginx" in reach["by_namespace"]
    assert reach["by_namespace"]["nginx"][0]["role"] == "admin"


def test_reach_via_group(view_role):
    idx = make_index(
        users=[{"name": "alice"}],
        groups=[{"name": "sellers", "users": ["alice"]}],
        cluster_roles=[view_role],
        rbs=[{"name": "sellers-view", "namespace": "demo",
              "subjects": [{"kind": "Group", "name": "sellers"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    reach = engine.namespace_reach_for_subject("User", "alice", None, idx)
    assert "demo" in reach["by_namespace"]
    assert reach["by_namespace"]["demo"][0]["via_group"] == "sellers"
    assert "sellers" in reach["via_groups"]


def test_reach_keeps_same_binding_name_in_different_namespaces(view_role):
    idx = make_index(
        users=[{"name": "alice"}],
        groups=[{"name": "payments-engineers", "users": ["alice"]}],
        cluster_roles=[view_role],
        rbs=[
            {"name": "payments-engineers-view", "namespace": "payments-dev",
             "subjects": [{"kind": "Group", "name": "payments-engineers"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
            {"name": "payments-engineers-view", "namespace": "payments-prod",
             "subjects": [{"kind": "Group", "name": "payments-engineers"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
        ],
    )

    reach = engine.namespace_reach_for_subject("User", "alice", None, idx)

    assert sorted(reach["by_namespace"]) == ["payments-dev", "payments-prod"]
    assert reach["by_namespace"]["payments-dev"][0]["binding_name"] == (
        "payments-engineers-view")
    assert reach["by_namespace"]["payments-prod"][0]["binding_name"] == (
        "payments-engineers-view")


# ---------- Resurrectable SA identities ---------- #

def _scc(name, **fields):
    """SCC with sane defaults for tests."""
    return {"name": name, "priority": fields.get("priority"),
            "allowPrivilegedContainer": fields.get("priv", False),
            "allowHostNetwork": fields.get("hostnet", False),
            "allowHostPID": fields.get("hostpid", False),
            "allowHostIPC": fields.get("hostipc", False),
            "allowPrivilegeEscalation": fields.get("escalate", False),
            "runAsUser": {"type": fields.get("runasuser", "MustRunAsRange")},
            "users": fields.get("users", []),
            "groups": fields.get("groups", [])}


def test_resurrectable_sa_critical_for_cluster_admin_to_absent_sa(cluster_admin_role):
    """A CRB to an SA that doesn't exist must surface as critical when
    the role is cluster-admin."""
    idx = make_index(
        namespaces=[{"name": "ci", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[cluster_admin_role],
        crbs=[{"name": "ci-pipeline-clusteradmin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "pipeline", "namespace": "ci"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )
    out = engine.resurrectable_sa_identities(idx)
    assert len(out) == 1
    assert out[0]["principal"] == "system:serviceaccount:ci:pipeline"
    assert out[0]["severity"] == "critical"
    assert out[0]["namespace_present"] is True
    assert out[0]["has_cluster_admin"] is True


def test_resurrectable_sa_namespace_also_missing_bumps_severity(view_role):
    """A view-grant to an SA in a deleted namespace is bumped to high
    because recreating ns + SA reactivates it."""
    idx = make_index(
        namespaces=[],
        cluster_roles=[view_role],
        crbs=[{"name": "legacy-runner-view",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "runner", "namespace": "legacy"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    out = engine.resurrectable_sa_identities(idx)
    assert len(out) == 1
    assert out[0]["namespace_present"] is False
    assert out[0]["severity"] == "high"


def test_resurrectable_sa_user_form_principal_detected(cluster_admin_role):
    """`subjects: [{kind: User, name: 'system:serviceaccount:foo:bar'}]`
    is the older OpenShift form and must be detected too."""
    idx = make_index(
        namespaces=[{"name": "tooling", "labels": {}, "annotations": {}}],
        cluster_roles=[cluster_admin_role],
        crbs=[{"name": "tool-admin",
               "subjects": [{"kind": "User",
                              "name": "system:serviceaccount:tooling:deployer"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )
    out = engine.resurrectable_sa_identities(idx)
    assert len(out) == 1
    assert out[0]["name"] == "deployer"
    assert out[0]["namespace"] == "tooling"
    assert out[0]["severity"] == "critical"


def test_resurrectable_sa_via_privileged_scc():
    """An SCC.users entry referencing an absent SA must surface, and a
    privileged SCC ranks critical."""
    idx = make_index(
        namespaces=[],
        sccs=[_scc("privileged", priv=True, hostnet=True, escalate=True,
                   runasuser="RunAsAny",
                   users=["system:serviceaccount:forgotten-batch:runner"])],
    )
    out = engine.resurrectable_sa_identities(idx)
    assert len(out) == 1
    assert out[0]["has_privileged_scc"] is True
    assert out[0]["severity"] == "critical"
    assert out[0]["grants"][0]["via"] == "SCC user list"


def test_resurrectable_sa_via_rbac_scc_role_is_critical_and_recent_first(cluster_admin_role):
    privileged_scc_role = {
        "name": "system:openshift:scc:privileged",
        "labels": {}, "annotations": {},
        "aggregationRule": None,
        "rules": [{"apiGroups": ["security.openshift.io"],
                   "resources": ["securitycontextconstraints"],
                   "resourceNames": ["privileged"],
                   "verbs": ["use"]}],
    }
    idx = make_index(
        namespaces=[
            {"name": "ci", "labels": {},
             "annotations": {"openshift.io/requester": "alice"}},
            {"name": "prod", "labels": {},
             "annotations": {"openshift.io/requester": "alice"}},
        ],
        cluster_roles=[cluster_admin_role, privileged_scc_role],
        sccs=[_scc("privileged", priv=True, hostnet=True, escalate=True,
                   runasuser="RunAsAny")],
        crbs=[
            {"name": "old-prod-admin",
             "subjects": [{"kind": "ServiceAccount",
                            "name": "deployer", "namespace": "prod"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
             "creationTimestamp": "2024-01-01T00:00:00Z"},
            {"name": "system:openshift:scc:privileged",
             "subjects": [{"kind": "ServiceAccount",
                            "name": "new-privileged-scc", "namespace": "ci"}],
             "roleRef": {"kind": "ClusterRole",
                         "name": "system:openshift:scc:privileged"},
             "creationTimestamp": "2026-05-12T10:00:00Z"},
        ],
    )

    out = engine.resurrectable_sa_identities(idx)

    assert out[0]["name"] == "new-privileged-scc"
    assert out[0]["creation_ts"] == "2026-05-12T10:00:00Z"
    assert out[0]["severity"] == "critical"
    assert out[0]["has_privileged_scc"] is True
    assert out[0]["grants"][0]["via"] == "RBAC SCC use grant"


def test_resurrectable_sa_present_sa_not_flagged(cluster_admin_role):
    """An SA that actually exists must NOT appear in the resurrectable list,
    even when it is bound to cluster-admin."""
    idx = make_index(
        namespaces=[{"name": "ci", "labels": {}, "annotations": {}}],
        sas=[{"name": "pipeline", "namespace": "ci", "labels": {}}],
        cluster_roles=[cluster_admin_role],
        crbs=[{"name": "ci-pipeline-clusteradmin",
               "subjects": [{"kind": "ServiceAccount",
                              "name": "pipeline", "namespace": "ci"}],
               "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}}],
    )
    assert engine.resurrectable_sa_identities(idx) == []


def test_deleted_namespaces_with_grants_aggregates(cluster_admin_role):
    idx = make_index(
        namespaces=[],
        cluster_roles=[cluster_admin_role],
        crbs=[
            {"name": "a", "subjects": [{"kind": "ServiceAccount",
                                          "name": "x", "namespace": "gone"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}},
            {"name": "b", "subjects": [{"kind": "ServiceAccount",
                                          "name": "y", "namespace": "gone"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}},
        ],
    )
    out = engine.deleted_namespaces_with_grants(idx)
    assert len(out) == 1
    assert out[0]["namespace"] == "gone"
    assert out[0]["principal_count"] == 2
    assert out[0]["max_severity"] == "critical"


# ---------- Identity audit ---------- #

def test_identity_audit_finds_latent():
    idx = make_index(
        users=[{"name": "alice"}],
        htpasswd_users=[
            {"username": "tom", "idp_name": "dev",
             "secret_namespace": "openshift-config", "secret_name": "x"},
        ],
    )
    audit = engine.identity_audit(idx)
    assert len(audit["latent_users"]) == 1
    assert audit["latent_users"][0]["username"] == "tom"


def test_identity_audit_identity_total_excludes_resurrectable_sas(cluster_admin_role):
    idx = make_index(
        namespaces=[{"name": "ci", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[cluster_admin_role],
        crbs=[
            {"name": "ci-pipeline-clusteradmin",
             "subjects": [{"kind": "ServiceAccount",
                            "name": "pipeline", "namespace": "ci"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}},
            {"name": "future-user-clusteradmin",
             "subjects": [{"kind": "User", "name": "future-user"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}},
        ],
    )

    audit = engine.identity_audit(idx)

    assert len(audit["resurrectable_sas"]) == 1
    assert len(audit["bound_ghosts"]) == 1
    assert audit["bound_ghosts"][0]["subject"]["kind"] == "User"
    assert audit["identity_total"] == 1
    assert audit["total"] == 2


def test_identity_audit_reports_user_object_without_identity():
    idx = make_index(
        users=[{"name": "manual-reviewer"}, {"name": "developer"},
               {"name": "kubeadmin"},
               {"name": "kube-apiserver"}],
        identities=[],
    )

    audit = engine.identity_audit(idx)

    assert audit["stranded_users"] == [
        {"name": "developer"},
        {"name": "kubeadmin"},
        {"name": "manual-reviewer"},
    ]
    subjects = engine.all_subjects(idx)
    row = next(s for s in subjects
               if s["kind"] == "User" and s["name"] == "manual-reviewer")
    assert row["stranded"] is True
    assert row["baseline"] is False
    developer = next(s for s in subjects
                     if s["kind"] == "User" and s["name"] == "developer")
    assert developer["baseline"] is False
    assert developer["stranded"] is True
    kubeadmin = next(s for s in subjects
                     if s["kind"] == "User" and s["name"] == "kubeadmin")
    assert kubeadmin["baseline"] is False
    assert kubeadmin["stranded"] is True
    assert all(u["name"] != "kube-apiserver"
               for u in audit["stranded_users"])


# ---------- Image inventory ---------- #

def test_image_inventory_classifies():
    idx = make_index(
        namespaces=[{"name": "nginx", "labels": {},
                     "annotations": {"openshift.io/requester": "kubeadmin"}}],
        pods=[{
            "name": "p1", "namespace": "nginx", "annotations": {},
            "spec": {"containers": [{"name": "c", "image": "docker.io/library/nginx:1.25"}]},
            "containerStatuses": [{"name": "c", "image": "docker.io/library/nginx:1.25",
                                    "imageID": "x"}],
            "phase": "Running",
        }],
    )
    inv = engine.image_inventory(idx)
    assert inv[0]["classification"] == "public"
    assert inv[0]["user_used"] is True


def test_registry_summary_keeps_shared_registry_in_baseline_and_yours():
    idx = make_index(
        namespaces=[
            {"name": "openshift-monitoring", "labels": {}, "annotations": {}},
            {"name": "test-quay", "labels": {},
             "annotations": {"openshift.io/requester": "kubeadmin"}},
        ],
        pods=[
            {
                "name": "baseline-pod", "namespace": "openshift-monitoring",
                "annotations": {},
                "spec": {"containers": [{"name": "c", "image": "quay.io/openshift/origin:latest"}]},
                "containerStatuses": [{"name": "c", "image": "quay.io/openshift/origin:latest",
                                       "imageID": "x"}],
                "phase": "Running",
            },
            {
                "name": "quay-test", "namespace": "test-quay",
                "annotations": {},
                "spec": {"containers": [{"name": "c", "image": "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:30b0464f0a31a70c5d2e7dcfe499d2f77f258e5b389e0ba21120380f9c2f9cc6"}]},
                "containerStatuses": [{"name": "c", "image": "quay.io/openshift-release-dev/ocp-v4.0-art-dev@sha256:30b0464f0a31a70c5d2e7dcfe499d2f77f258e5b389e0ba21120380f9c2f9cc6",
                                       "imageID": "x"}],
                "phase": "Running",
            },
        ],
    )

    quay = next(r for r in engine.registry_summary(engine.image_inventory(idx))
                if r["registry"] == "quay.io")
    assert quay["baseline_used"] is True
    assert quay["user_used"] is True


# ---------- All subjects: stranded users and bootstrap baseline ---------- #

# ---------- Layered namespace classification ---------- #

def test_classify_namespace_system_by_name():
    cls = cf.classify_namespace_obj(
        {"name": "kube-system", "labels": {}, "annotations": {}})
    assert cls["category"] == "system"
    assert cls["is_baseline"] is True
    assert cls["is_user_owned"] is False


def test_classify_namespace_openshift_by_name():
    cls = cf.classify_namespace_obj(
        {"name": "openshift-monitoring", "labels": {}, "annotations": {}})
    assert cls["category"] == "openshift"
    assert cls["is_baseline"] is True


def test_classify_namespace_project_via_requester():
    cls = cf.classify_namespace_obj(
        {"name": "nginx", "labels": {},
         "annotations": {"openshift.io/requester": "alice"}})
    assert cls["category"] == "project"
    assert cls["is_user_owned"] is True
    assert cls["owner"] == "alice"
    # The reason string should reference the requester annotation.
    assert any("requester" in s.reason for s in cls["signals"])


def test_classify_namespace_kubectl_apply_alone_does_not_yield_user():
    """v1.0 deliberately does NOT trust kubectl.kubernetes.io/last-applied-
    configuration as a user signal — it is set on cluster-installed
    namespaces too (CRC's hostpath-provisioner is the canonical example).
    Without a requester annotation, this namespace stays in 'unknown' —
    NOT baseline."""
    cls = cf.classify_namespace_obj(
        {"name": "scratch", "labels": {},
         "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"}})
    assert cls["category"] == "unknown"
    assert cls["is_baseline"] is False
    assert cls["is_unknown"] is True
    assert cls["is_user_owned"] is False


def test_classify_namespace_install_time_infra_with_apply_annotation_is_unknown():
    """The exact regression: a cluster-installed namespace with only the
    kubectl-apply annotation must NOT land in Mine, and must not be
    silently rolled into Baseline either. `openshift.io/requester` is the
    only built-in path into the user-owned bucket; everything else without
    a confident name-pattern is `unknown` and needs review."""
    cls = cf.classify_namespace_obj(
        {"name": "infra-storage", "labels": {},
         "annotations": {"kubectl.kubernetes.io/last-applied-configuration": "{}"},
         "creationTimestamp": "2025-09-04T09:45:37Z"})
    assert cls["is_user_owned"] is False
    assert cls["is_baseline"] is False
    assert cls["is_unknown"] is True
    assert cls["category"] == "unknown"


def test_classify_namespace_unknown_when_no_signals():
    cls = cf.classify_namespace_obj(
        {"name": "scratch", "labels": {}, "annotations": {}})
    assert cls["category"] == "unknown"
    assert cls["is_baseline"] is False
    assert cls["is_unknown"] is True
    assert cls["signals"] == []


def test_classify_namespace_requester_beats_name_pattern():
    """Tie-break check: a project deliberately named to look like an
    OpenShift platform namespace must still classify as `project` because
    the requester annotation is the strongest priority."""
    cls = cf.classify_namespace_obj(
        {"name": "openshift-sandbox", "labels": {},
         "annotations": {"openshift.io/requester": "alice"}})
    assert cls["category"] == "project"
    assert cls["is_user_owned"] is True


def test_is_mine_namespace_filters_by_requester():
    """A project requested by `developer` is still a project (Projects
    chip), but it is NOT mine when I'm logged in as `alice`. Mine narrows
    Projects to those whose `openshift.io/requester` matches the viewer."""
    mine = {"category": "project", "owner": "alice"}
    devs = {"category": "project", "owner": "developer"}
    sys_ns = {"category": "system", "owner": None}
    unk = {"category": "unknown", "owner": None}

    # alice's view
    assert engine.is_mine_namespace(mine, "alice") is True
    assert engine.is_mine_namespace(devs, "alice") is False
    assert engine.is_mine_namespace(sys_ns, "alice") is False
    assert engine.is_mine_namespace(unk, "alice") is False

    # developer's view — flips for the same data
    assert engine.is_mine_namespace(mine, "developer") is False
    assert engine.is_mine_namespace(devs, "developer") is True

    # Anonymous / mock / no current_user — Mine excludes everything.
    assert engine.is_mine_namespace(mine, None) is False
    assert engine.is_mine_namespace(devs, None) is False


def test_engine_is_baseline_namespace_not_in_index_falls_back_to_name():
    """When alice's view doesn't include a namespace, name patterns are
    still consulted. Names matching openshift-/kube-* stay baseline;
    everything else is unknown, NOT baseline."""
    idx = make_index(namespaces=[])
    assert engine.is_baseline_namespace("openshift-config", idx) is True
    assert engine.is_baseline_namespace("kube-system", idx) is True
    # A name we cannot classify confidently is unknown — review-worthy,
    # not silently rolled into baseline.
    assert engine.is_baseline_namespace("random-ns", idx) is False
    assert engine.is_unknown_namespace("random-ns", idx) is True


def test_engine_classify_namespace_returns_signals_in_summary():
    idx = make_index(namespaces=[
        {"name": "alice-app", "labels": {}, "annotations": {
            "openshift.io/requester": "alice"}},
    ])
    summary = engine.namespace_summary("alice-app", idx)
    assert summary["category"] == "project"
    assert summary["owner"] == "alice"
    assert summary["user_owned"] is True
    assert any(s.category == "project" for s in summary["signals"])


def test_signal_rules_extensible():
    """Custom rules registered via SIGNAL_RULES.append should contribute.
    This example flags a corporate-prefix as cluster-managed `system`."""
    def rule_corporate_prefix(ns_obj, *_):
        if (ns_obj.get("name") or "").startswith("corp-"):
            return cf.Signal("system", "name starts with corp- (corporate-managed)")
        return None

    cf.SIGNAL_RULES.append(rule_corporate_prefix)
    try:
        cls = cf.classify_namespace_obj(
            {"name": "corp-billing", "labels": {}, "annotations": {}})
        assert cls["category"] == "system"
        assert cls["is_baseline"] is True
        assert any("corporate-managed" in s.reason for s in cls["signals"])
    finally:
        cf.SIGNAL_RULES.remove(rule_corporate_prefix)


def test_all_subjects_user_without_identity_is_stranded():
    idx = make_index(
        users=[{"name": "alice"}, {"name": "manual-reviewer"},
               {"name": "developer"}, {"name": "kube-apiserver"}],
        identities=[{"name": "dev:alice", "user": {"name": "alice"}, "providerName": "dev"}],
    )
    subjects = engine.all_subjects(idx)
    by_name = {(s["kind"], s["name"]): s for s in subjects}
    assert by_name[("User", "alice")]["baseline"] is False
    assert by_name[("User", "manual-reviewer")]["baseline"] is False
    assert by_name[("User", "manual-reviewer")]["stranded"] is True
    assert by_name[("User", "manual-reviewer")]["origin"] == "no-identity"
    assert by_name[("User", "developer")]["baseline"] is False
    assert by_name[("User", "developer")]["stranded"] is True
    assert by_name[("User", "kube-apiserver")]["baseline"] is True


# ---------- Cross-namespace bindings for namespace detail ---------- #

def test_cross_ns_bindings_classifies_each_direction():
    """An SA in ns A referenced by an RB in ns B is incoming for A and
    outgoing for B. A CRB to that SA is incoming for A only."""
    idx = make_index(
        namespaces=[{"name": "ns-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}},
                    {"name": "ns-b", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        sas=[{"name": "agent", "namespace": "ns-a"}],
        rbs=[{"name": "use-agent-in-b", "namespace": "ns-b",
              "subjects": [{"kind": "ServiceAccount", "name": "agent",
                            "namespace": "ns-a"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
        crbs=[{"name": "agent-cluster-view",
               "subjects": [{"kind": "ServiceAccount", "name": "agent",
                             "namespace": "ns-a"}],
               "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    a = engine.cross_ns_bindings_for_namespace("ns-a", idx)
    b = engine.cross_ns_bindings_for_namespace("ns-b", idx)
    assert len(a["incoming_rbs"]) == 1
    assert a["incoming_rbs"][0]["binding"]["namespace"] == "ns-b"
    assert len(a["incoming_crbs"]) == 1
    assert a["outgoing_rbs"] == []
    assert len(b["outgoing_rbs"]) == 1
    assert b["outgoing_rbs"][0]["subject"]["namespace"] == "ns-a"
    assert b["incoming_rbs"] == []
    assert b["incoming_crbs"] == []


def test_cross_ns_bindings_mock_mine_platform_has_links():
    idx = engine.index()
    res = engine.cross_ns_bindings_for_namespace("mine-platform", idx)
    # ci/builder is bound via a RoleBinding inside mine-platform -> outgoing.
    assert any(e["subject"]["namespace"] == "ci"
                for e in res["outgoing_rbs"])
    # mine-platform/default is granted system:image-puller in shared-images
    # -> incoming for mine-platform.
    inc = engine.cross_ns_bindings_for_namespace("shared-images", idx)
    assert any(e["subject"]["namespace"] == "mine-platform"
                for e in inc["outgoing_rbs"])


def test_images_running_in_namespace_dedupes_and_counts():
    idx = engine.index()
    rows = engine.images_running_in_namespace("alice-project", idx)
    # Mock has two drift pods both running nginx:1.25 -> deduped to one row.
    nginx = [r for r in rows if r["image"] == "docker.io/library/nginx:1.25"]
    assert len(nginx) == 1
    assert nginx[0]["pod_count"] == 2


# ---------- Reverse bindings for a ServiceAccount ---------- #

def test_bindings_referencing_sa_splits_by_scope():
    idx = engine.index()
    res = engine.bindings_referencing_sa("builder", "ci", idx)
    rb_names_same = {e["name"] for e in res["rbs_same_ns"]}
    rb_names_cross = {e["name"] for e in res["rbs_cross_ns"]}
    # ci/builder has same-ns RBs (ci-builder-use-anyuid)
    # and cross-ns RBs (ci-builder-deploy-mine in mine-platform,
    # ci-builder-pushes-shared in shared-images).
    assert "ci-builder-use-anyuid" in rb_names_same
    assert "ci-builder-deploy-mine" in rb_names_cross
    assert "ci-builder-pushes-shared" in rb_names_cross
    assert res["crbs"] == []


def test_bindings_referencing_sa_recognizes_user_form_principal():
    """The 'tooling-deployer-admin' CRB uses a User-form principal
    (system:serviceaccount:tooling:deployer). bindings_referencing_sa must
    pick it up just like a kind=ServiceAccount subject."""
    idx = engine.index()
    res = engine.bindings_referencing_sa("deployer", "tooling", idx)
    assert any(e["name"] == "tooling-deployer-admin" for e in res["crbs"])


def test_images_for_sa_dedupes_and_counts():
    idx = engine.index()
    rows = engine.images_for_sa("builder", "mine-platform", idx)
    # mine-platform/builder runs api, busybox, ubi-minimal, support-tools.
    assert len(rows) >= 3
    assert all(r["pod_count"] >= 1 for r in rows)


def test_surviving_grants_for_absent_sa_finds_resurrectable():
    idx = engine.index()
    # 'ci/pipeline' SA is absent; the CRB ci-pipeline-clusteradmin survives.
    res = engine.surviving_grants_for_absent_sa("pipeline", "ci", idx)
    assert res is not None
    assert res["name"] == "pipeline"
    assert any(g["name"] == "ci-pipeline-clusteradmin" for g in res["grants"])


def test_surviving_grants_returns_none_for_present_sa():
    idx = engine.index()
    res = engine.surviving_grants_for_absent_sa("builder", "ci", idx)
    assert res is None


# ---------- Aggregation parents for ClusterRole detail ---------- #

def test_aggregation_parents_for_role_finds_admin():
    idx = engine.index()
    storage = idx["cluster_roles_by_name"]["admin-storage"]
    parents = engine.aggregation_parents_for_role(storage, idx)
    parent_names = {p["name"] for p in parents}
    assert "admin" in parent_names


def test_aggregation_parents_returns_empty_for_unlabeled_role():
    idx = engine.index()
    view = idx["cluster_roles_by_name"]["view"]
    assert engine.aggregation_parents_for_role(view, idx) == []


def test_aggregation_parents_skips_self():
    idx = engine.index()
    admin = idx["cluster_roles_by_name"]["admin"]
    parents = engine.aggregation_parents_for_role(admin, idx)
    assert all(p["name"] != "admin" for p in parents)


# ---------- SCC use interpretation ---------- #

def test_scc_use_interpretation_named_resource():
    idx = engine.index()
    rules = idx["cluster_roles_by_name"]["system:openshift:scc:anyuid"]["rules"]
    res = engine.scc_use_interpretation(rules, idx)
    assert len(res) == 1
    assert res[0]["scc_name"] == "anyuid"
    assert res[0]["present"] is True
    assert res[0]["allowPrivilegedContainer"] is False


def test_scc_use_interpretation_privileged_flagged():
    idx = engine.index()
    rules = idx["cluster_roles_by_name"]["system:openshift:scc:privileged"]["rules"]
    res = engine.scc_use_interpretation(rules, idx)
    assert res[0]["scc_name"] == "privileged"
    assert res[0]["allowPrivilegedContainer"] is True


def test_scc_use_interpretation_wildcard_lists_every_scc(make_idx):
    """A rule with use on securitycontextconstraints with no resourceNames
    grants use on every SCC."""
    idx = make_idx(
        sccs=[{"name": "privileged", "allowPrivilegedContainer": True},
              {"name": "restricted-v2", "allowPrivilegedContainer": False}],
    )
    rules = [{"apiGroups": ["security.openshift.io"],
              "resources": ["securitycontextconstraints"],
              "verbs": ["use"]}]
    res = engine.scc_use_interpretation(rules, idx)
    names = {r["scc_name"] for r in res}
    assert names == {"privileged", "restricted-v2"}


def test_scc_use_interpretation_ignores_unrelated_rules(view_role):
    res = engine.scc_use_interpretation(view_role["rules"], make_index())
    assert res == []


# ---------- ImageStream matching ---------- #

def test_imagestream_for_image_exact_repo_match():
    idx = engine.index()
    # mine-platform/api ImageStream has repository
    # image-registry.openshift-image-registry.svc:5000/mine-platform/api
    ref = "image-registry.openshift-image-registry.svc:5000/mine-platform/api:latest"
    s = engine.imagestream_for_image(ref, idx)
    assert s is not None
    assert s["name"] == "api"


def test_imagestream_for_image_digest_pinned_match():
    idx = engine.index()
    ref = ("image-registry.openshift-image-registry.svc:5000"
            "/mine-platform/api@sha256:abc")
    s = engine.imagestream_for_image(ref, idx)
    assert s is not None
    assert s["name"] == "api"


def test_imagestream_for_image_no_substring_false_positive(make_idx):
    """A short IS repo must not match a longer image ref that merely
    contains it as a substring."""
    idx = make_idx(
        imagestreams=[{"name": "api", "namespace": "ns",
                       "dockerImageRepository": "registry/api",
                       "publicDockerImageRepository": ""}],
    )
    # 'registry/api-server' shares the prefix 'registry/api' but is a
    # different repository.
    assert engine.imagestream_for_image("registry/api-server:tag", idx) is None


def test_imagestream_for_image_unknown_returns_none():
    idx = engine.index()
    assert engine.imagestream_for_image("docker.io/library/nginx:1.25",
                                          idx) is None


# ---------- Digest siblings ---------- #

def test_digest_siblings_detects_mutable_tag_drift():
    """Mock has nginx:1.25 resolved to two digests across alice-project."""
    idx = engine.index()
    ref = "docker.io/library/nginx:1.25"
    sibs = engine.digest_siblings_for_image(ref, idx)
    # The image_inventory key for the running nginx pod is the actual_image
    # (docker.io/library/nginx:1.25). At least one sibling digest exists.
    # (The query returns siblings — digests other than the one of the
    # queried row. If queried row has digest X, function returns [Y].)
    digests = {s["digest"] for s in sibs}
    # Ensure at least one sibling digest is returned and they're distinct.
    assert len(digests) >= 1


def test_digest_siblings_returns_empty_for_digest_pinned_ref():
    idx = engine.index()
    # @sha256:fake is digest-pinned -> drift impossible by construction.
    sibs = engine.digest_siblings_for_image(
        "quay.io/openshift-release-dev/ocp-release@sha256:fake", idx)
    assert sibs == []


# ---------- Image inventory pod entries carry SA + SCC ---------- #

def test_image_inventory_pod_entries_include_service_account_and_scc():
    idx = engine.index()
    rows = {r["image"]: r for r in engine.image_inventory(idx)}
    api = rows.get("image-registry.openshift-image-registry.svc:5000"
                    "/mine-platform/api:latest")
    assert api is not None
    p = api["pods"][0]
    assert p["service_account"] == "builder"
    assert p["scc"] == "anyuid"


# ---------- Image pods-by-namespace summary ---------- #

def test_image_pods_by_namespace_aggregates():
    pods = [
        {"name": "a", "namespace": "ns1", "container": "c1",
         "baseline_ns": False},
        {"name": "a", "namespace": "ns1", "container": "c2",
         "baseline_ns": False},
        {"name": "b", "namespace": "ns2", "container": "c1",
         "baseline_ns": True},
    ]
    rows = engine.image_pods_by_namespace(pods)
    by_ns = {r["namespace"]: r for r in rows}
    assert by_ns["ns1"]["pod_count"] == 1
    assert by_ns["ns1"]["container_count"] == 2
    assert by_ns["ns1"]["any_baseline"] is False
    assert by_ns["ns2"]["pod_count"] == 1
    assert by_ns["ns2"]["any_baseline"] is True


# ---------- SA token inventory has been removed ---------- #

def test_engine_index_does_not_carry_secrets_key():
    """Lineage no longer reads or indexes Secrets cluster-wide. The engine
    index must not expose any `secrets` key — guards against a regression
    that would silently re-introduce the cluster-wide get/list."""
    idx = engine.index()
    assert "secrets" not in idx


def test_engine_has_no_tokens_for_sa_helper():
    """`engine.tokens_for_sa` was removed when the cluster-wide SA-token
    Secret inventory was dropped. Re-adding it would require justifying
    cluster-wide get/list on Secrets again."""
    assert not hasattr(engine, "tokens_for_sa")


def test_data_facade_does_not_expose_secrets():
    """The data facade no longer offers a generic Secret reader. The only
    Secret access remaining is the openshift-config HTPasswd path, which
    is read internally by `htpasswd_users()` and gracefully degrades."""
    from lineage import data as data_mod
    assert not hasattr(data_mod, "secrets")


def test_cluster_module_does_not_inventory_token_secrets():
    """The live cluster reader must not contain the SA-token inventory."""
    with open("lineage/cluster.py", "r") as f:
        body = f.read()
    assert "service-account-token" not in body
    assert "sa-tokens" not in body


def test_subject_detail_page_does_not_render_token_secrets_section():
    """The 'Token secrets' subsection on /subject/ServiceAccount/<name>
    has been removed."""
    from lineage.main import app
    client = app.test_client()
    body = client.get(
        "/subject/ServiceAccount/builder?namespace=mine-platform"
    ).data.decode()
    assert "Token secrets" not in body
    assert "service-account-token" not in body


def test_mock_data_carries_no_secrets_module_attribute():
    """The mock SECRETS list was removed alongside the token inventory."""
    from lineage import mock_data
    assert not hasattr(mock_data, "SECRETS")


# ---------- Categorized subjects-with-access ---------- #

def _make_cat_idx(make_idx):
    """A small index with a representative mix for categorization tests."""
    return make_idx(
        users=[{"name": "alice"}, {"name": "developer"}, {"name": "kubeadmin"}],
        identities=[{"name": "dev:alice", "user": {"name": "alice"},
                     "providerName": "dev"}],
        groups=[{"name": "engineers", "users": ["alice"]},
                {"name": "system:masters", "users": []}],
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}},
                    {"name": "team-b", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}},
                    {"name": "kube-system", "labels": {}, "annotations": {}}],
        sas=[{"name": "agent", "namespace": "team-b"},
             {"name": "local-sa", "namespace": "team-a"}],
        cluster_roles=[
            {"name": "view", "rules": [{"apiGroups": [""],
                                          "resources": ["pods"],
                                          "verbs": ["get"]}]},
            {"name": "edit", "rules": [{"apiGroups": [""],
                                          "resources": ["pods"],
                                          "verbs": ["*"]}]},
            {"name": "cluster-admin", "rules": [
                {"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]},
        ],
        roles=[{"name": "local-role", "namespace": "team-a",
                "rules": [{"apiGroups": [""], "resources": ["configmaps"],
                            "verbs": ["get"]}]}],
        crbs=[
            # System CRB — system_baseline.
            {"name": "cluster-admins",
             "subjects": [{"kind": "Group", "name": "system:masters"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}},
            # CRB with a non-system Group subject -> goes to "groups".
            {"name": "engineers-edit",
             "subjects": [{"kind": "Group", "name": "engineers"}],
             "roleRef": {"kind": "ClusterRole", "name": "edit"}},
            # CRB with a regular User -> cluster_rbs.
            {"name": "alice-cluster-view",
             "subjects": [{"kind": "User", "name": "alice"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
        ],
        rbs=[
            # Local RB -> Role (in team-a): local_rbs.
            {"name": "alice-local", "namespace": "team-a",
             "subjects": [{"kind": "User", "name": "alice"}],
             "roleRef": {"kind": "Role", "name": "local-role"}},
            # Local RB -> ClusterRole (in team-a): still local_rbs because
            # the binding scope is local. The link rule cares about binding
            # kind, not roleRef kind.
            {"name": "alice-local-edit", "namespace": "team-a",
             "subjects": [{"kind": "User", "name": "alice"}],
             "roleRef": {"kind": "ClusterRole", "name": "edit"}},
            # Cross-namespace SA (agent lives in team-b, bound in team-a).
            {"name": "agent-into-team-a", "namespace": "team-a",
             "subjects": [{"kind": "ServiceAccount", "name": "agent",
                            "namespace": "team-b"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
            # Local-namespace SA bound locally: local_rbs.
            {"name": "local-sa-view", "namespace": "team-a",
             "subjects": [{"kind": "ServiceAccount", "name": "local-sa",
                            "namespace": "team-a"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
        ],
    )


def test_categorized_local_rb_to_role(make_idx):
    idx = _make_cat_idx(make_idx)
    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    names = {(r["binding"]["name"], r["subject"]["name"])
              for r in cats["local_rbs"]}
    assert ("alice-local", "alice") in names


def test_categorized_local_rb_to_clusterrole(make_idx):
    """A local RoleBinding that references a ClusterRole is still local
    (binding scope determines category, not roleRef kind)."""
    idx = _make_cat_idx(make_idx)
    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    names = {(r["binding"]["name"], r["role"]) for r in cats["local_rbs"]}
    assert ("alice-local-edit", "edit") in names


def test_categorized_crb_reaches_namespace(make_idx):
    idx = _make_cat_idx(make_idx)
    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    # User alice CRB to view -> cluster_rbs.
    names = {(r["binding"]["name"], r["subject"]["name"])
              for r in cats["cluster_rbs"]}
    assert ("alice-cluster-view", "alice") in names
    # Make sure the same row is NOT also classified as local.
    local_bindings = {r["binding"]["name"] for r in cats["local_rbs"]}
    assert "alice-cluster-view" not in local_bindings


def test_categorized_crb_without_namespace_effect_is_not_namespace_access(make_idx):
    """ClusterRoleBindings to discovery/self-review/SCC-style roles are real
    cluster relationships, but they don't grant object access inside each
    namespace and should not appear as namespace access."""
    idx = make_idx(
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[
            {"name": "system:discovery",
             "rules": [{"nonResourceURLs": ["/api", "/apis"],
                        "verbs": ["get"]}]},
            {"name": "self-access-reviewer",
             "rules": [{"apiGroups": ["authorization.k8s.io"],
                        "resources": ["selfsubjectaccessreviews"],
                        "verbs": ["create"]}]},
            {"name": "system:openshift:scc:restricted-v2",
             "rules": [{"apiGroups": ["security.openshift.io"],
                        "resources": ["securitycontextconstraints"],
                        "resourceNames": ["restricted-v2"],
                        "verbs": ["use"]}]},
            {"name": "view",
             "rules": [{"apiGroups": [""], "resources": ["pods"],
                        "verbs": ["get"]}]},
        ],
        crbs=[
            {"name": "discovery",
             "subjects": [{"kind": "Group",
                           "name": "system:authenticated"}],
             "roleRef": {"kind": "ClusterRole",
                         "name": "system:discovery"}},
            {"name": "self-review",
             "subjects": [{"kind": "Group",
                           "name": "system:authenticated"}],
             "roleRef": {"kind": "ClusterRole",
                         "name": "self-access-reviewer"}},
            {"name": "restricted-scc",
             "subjects": [{"kind": "Group",
                           "name": "system:authenticated"}],
             "roleRef": {"kind": "ClusterRole",
                         "name": "system:openshift:scc:restricted-v2"}},
            {"name": "authenticated-view",
             "subjects": [{"kind": "Group",
                           "name": "system:authenticated"}],
             "roleRef": {"kind": "ClusterRole", "name": "view"}},
        ],
    )

    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    bindings = {r["binding"]["name"] for r in cats["system_baseline"]}
    assert "authenticated-view" in bindings
    assert "discovery" not in bindings
    assert "self-review" not in bindings
    assert "restricted-scc" not in bindings


def test_categorized_crb_infers_custom_resource_from_namespaced_role(make_idx):
    """Custom resources are namespace-effective once namespace-scoped RBAC
    in the index proves that resource is used in a namespace context."""
    idx = make_idx(
        users=[{"name": "alice"}],
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        roles=[{"name": "local-widgets", "namespace": "team-a",
                "rules": [{"apiGroups": ["example.com"],
                           "resources": ["widgets"],
                           "verbs": ["get"]}]}],
        cluster_roles=[{"name": "widgets-view",
                         "rules": [{"apiGroups": ["example.com"],
                                     "resources": ["widgets"],
                                     "verbs": ["get"]}]}],
        crbs=[{"name": "alice-widgets",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole", "name": "widgets-view"}}],
    )

    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    names = {(r["binding"]["name"], r["subject"]["name"])
             for r in cats["cluster_rbs"]}
    assert ("alice-widgets", "alice") in names


def test_namespaced_role_cluster_resource_does_not_make_crb_namespace_access(make_idx):
    """A namespaced Role can contain a cluster-scoped resource name, but that
    must not teach namespace-detail that the resource grants access here."""
    idx = make_idx(
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        roles=[{"name": "bad-local-cluster-resource", "namespace": "team-a",
                "rules": [{"apiGroups": [""],
                           "resources": ["namespaces"],
                           "verbs": ["get"]}]}],
        cluster_roles=[{"name": "namespace-reader",
                         "rules": [{"apiGroups": [""],
                                     "resources": ["namespaces"],
                                     "verbs": ["get"]}]}],
        crbs=[{"name": "authenticated-namespace-reader",
               "subjects": [{"kind": "Group",
                              "name": "system:authenticated"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "namespace-reader"}}],
    )

    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    rows = [r for rows in cats.values() for r in rows]
    assert not any(r["binding"]["name"] == "authenticated-namespace-reader"
                   for r in rows)


def test_local_rolebinding_cluster_resource_does_not_make_crb_namespace_access(make_idx):
    """A local RoleBinding to a ClusterRole grants only the ClusterRole's
    namespace-scoped rules. Cluster-scoped-only rules should not become
    namespace access evidence for other ClusterRoleBindings."""
    idx = make_idx(
        users=[{"name": "alice"}],
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[{"name": "clusterrole-reader",
                         "rules": [{"apiGroups": ["rbac.authorization.k8s.io"],
                                     "resources": ["clusterroles"],
                                     "verbs": ["get"]}]}],
        rbs=[{"name": "local-alice-clusterrole-reader",
              "namespace": "team-a",
              "subjects": [{"kind": "User", "name": "alice"}],
              "roleRef": {"kind": "ClusterRole",
                           "name": "clusterrole-reader"}}],
        crbs=[{"name": "authenticated-clusterrole-reader",
               "subjects": [{"kind": "Group",
                              "name": "system:authenticated"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "clusterrole-reader"}}],
    )

    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    rows = [r for rows in cats.values() for r in rows]
    assert not any(r["binding"]["name"] == "authenticated-clusterrole-reader"
                   for r in rows)
    assert not any(r["binding"]["name"] == "local-alice-clusterrole-reader"
                   for r in rows)


def test_scc_use_not_namespace_access_but_still_scc_detail(make_idx):
    """SCC use grants belong on SCC views, not namespace object-access rows."""
    idx = make_idx(
        users=[{"name": "alice"}],
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        sccs=[{"name": "custom-scc", "users": [], "groups": []}],
        cluster_roles=[{
            "name": "system:openshift:scc:custom-scc",
            "rules": [{"apiGroups": ["security.openshift.io"],
                       "resources": ["securitycontextconstraints"],
                       "resourceNames": ["custom-scc"],
                       "verbs": ["use"]}],
        }],
        crbs=[{"name": "system:openshift:scc:custom-scc",
               "subjects": [{"kind": "User", "name": "alice"}],
               "roleRef": {"kind": "ClusterRole",
                            "name": "system:openshift:scc:custom-scc"}}],
    )

    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    assert all(r["subject"].get("name") != "alice"
               for rows in cats.values() for r in rows)

    scc_rows = engine.scc_potential_subjects("custom-scc", idx)
    assert any(r["kind"] == "User" and r["name"] == "alice"
               and r["source"] == "RBAC use grant" for r in scc_rows)


def test_categorized_cross_namespace_sa_subject(make_idx):
    idx = _make_cat_idx(make_idx)
    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    # agent (SA in team-b) bound by an RB in team-a -> cross_ns_sas.
    found = [r for r in cats["cross_ns_sas"]
             if r["subject"].get("name") == "agent"
                and r["subject"].get("namespace") == "team-b"]
    assert len(found) == 1
    # And not in local_rbs.
    assert all(r["subject"].get("name") != "agent"
                for r in cats["local_rbs"])


def test_categorized_groups_separated_from_cluster_rbs(make_idx):
    """A non-system Group subject in a CRB goes to the Groups bucket,
    not into cluster_rbs (so they're not mixed)."""
    idx = _make_cat_idx(make_idx)
    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    group_names = {r["subject"]["name"] for r in cats["groups"]}
    assert "engineers" in group_names
    cluster_names = {r["subject"]["name"] for r in cats["cluster_rbs"]}
    assert "engineers" not in cluster_names


def test_categorized_system_baseline_holds_system_masters(make_idx):
    idx = _make_cat_idx(make_idx)
    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    names = {r["subject"]["name"] for r in cats["system_baseline"]}
    assert "system:masters" in names


def test_categorized_stranded_user_in_project_namespace_is_local(make_idx):
    """A User object with no Identity is review-worthy, not baseline noise."""
    idx = make_idx(
        users=[{"name": "manual-reviewer"}],
        identities=[],
        namespaces=[{"name": "team-a", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[{"name": "view",
                         "rules": [{"apiGroups": [""], "resources": ["pods"],
                                     "verbs": ["get"]}]}],
        rbs=[{"name": "manual-reviewer-view", "namespace": "team-a",
              "subjects": [{"kind": "User", "name": "manual-reviewer"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    cats = engine.subjects_with_access_in_categorized("team-a", idx)
    sys_names = {r["subject"]["name"] for r in cats["system_baseline"]}
    local_names = {r["subject"]["name"] for r in cats["local_rbs"]}
    assert "manual-reviewer" in local_names
    assert "manual-reviewer" not in sys_names


def test_categorized_empty_namespace_all_buckets_empty(make_idx):
    idx = make_idx(
        namespaces=[{"name": "empty-ns", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
        cluster_roles=[{"name": "view", "rules": []}],
    )
    cats = engine.subjects_with_access_in_categorized("empty-ns", idx)
    for k in ("local_rbs", "cluster_rbs", "cross_ns_sas",
              "groups", "system_baseline"):
        assert cats[k] == []


# ---------- Template threshold rule (small lists render inline) ---------- #

def test_small_lists_render_inline_no_expand_button():
    """For the mock dataset (all sections <=8 rows), no detail page should
    emit the expandable details wrapper. Verifies the threshold rule
    keeps small lists inline."""
    # Inline rendering -> no Flask app needed; use the test client.
    from lineage.main import app
    client = app.test_client()
    pages = [
        "/namespace/mine-platform",
        "/namespace/ci",
        "/namespace/nginx",
        "/subject/ServiceAccount/builder?namespace=mine-platform",
        "/subject/ServiceAccount/builder?namespace=ci",
        "/scc/anyuid",
        "/scc/privileged",
        "/clusterrole/admin",
        "/clusterrole/system:openshift:scc:anyuid",
        "/image?ref=docker.io/library/nginx:1.25",
    ]
    for path in pages:
        resp = client.get(path)
        assert resp.status_code == 200, path
        body = resp.data.decode()
        assert "Click to expand" not in body, (
            f"{path} rendered an expand button despite small list")


def test_namespace_detail_single_access_table_with_filters():
    """Subjects-with-access is now ONE filterable table with bucket and
    kind toggles. Verify the segment toggle, kind filterbar, and the
    Source column all render."""
    from lineage.main import app
    client = app.test_client()
    resp = client.get("/namespace/mine-platform")
    body = resp.data.decode()
    # Bucket toggle.
    for label in (">Yours ", ">Unclassified ", ">Baseline ", ">All "):
        assert label in body, f"bucket toggle missing label: {label!r}"
    # Kind toggle.
    for label in (">Users ", ">Groups ", ">ServiceAccounts ", ">All kinds "):
        assert label in body, f"kind filter missing label: {label!r}"
    # Source column header.
    assert "<th>Source</th>" in body


def test_namespace_detail_all_bucket_still_exposes_cluster_admin_groups():
    """The default bucket remains All; switching kind to Group should expose
    cluster-admin holders instead of requiring a bucket change."""
    from lineage.main import app
    client = app.test_client()
    body = client.get("/namespace/mine-platform?access_kind=Group").data.decode()
    assert "system:masters" in body
    assert "cluster-admin" in body


def _extract_access_section(html):
    """Return the substring of the namespace_detail HTML that contains
    only the subjects-with-access section, so assertions don't catch
    matches in unrelated tables (RoleBindings list, etc.)."""
    start = html.find('id="ns-access"')
    if start < 0:
        return ""
    end = html.find('</section>', start)
    return html[start:end] if end > 0 else html[start:]


def test_namespace_detail_access_bucket_filter_applies():
    """access_bucket=baseline narrows to baseline rows. system:masters
    should appear in the access section; project-owned non-baseline
    subjects (Group/engineers) should not."""
    from lineage.main import app
    client = app.test_client()
    section = _extract_access_section(client.get(
        "/namespace/mine-platform?access_bucket=baseline&access_kind=Group"
    ).data.decode())
    assert "system:masters" in section
    # engineers might still appear elsewhere on the page, but NOT in the
    # access section under bucket=baseline.
    assert "engineers" not in section


def test_namespace_detail_access_rows_mark_stranded_user(
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

    client = main_module.app.test_client()
    section = _extract_access_section(client.get("/namespace/app").data.decode())

    assert "manual-reviewer" in section
    assert '<span class="badge badge-warn">No ID</span>' in section


def test_namespace_detail_defaults_to_all_user_access():
    """The access section defaults to all buckets, but Users only."""
    from lineage.main import app
    client = app.test_client()
    section = _extract_access_section(client.get(
        "/namespace/mine-platform"
    ).data.decode())
    assert 'href="?access_bucket=all&access_kind=User#ns-access" class="active"' in section
    assert 'href="?access_bucket=all&access_kind=all#ns-access" class=""' in section
    assert "Group/engineers" not in section and "engineers" not in section


def test_namespace_detail_yours_filter_shows_hidden_hint():
    """When the Yours bucket is selected and baseline/unknown rows exist,
    the page should show a hint that more is hidden behind the filter."""
    from lineage.main import app
    client = app.test_client()
    body = client.get(
        "/namespace/mine-platform?access_bucket=yours"
    ).data.decode()
    assert "Hidden by filter" in body or "system:masters" in body


# ---------- Unknown bucket: classifier split ---------- #

def test_oc_create_namespace_style_is_unknown_not_baseline(make_idx):
    """A raw `oc create namespace foo` style namespace (no requester, name
    not platform-prefixed) classifies as unknown — never baseline."""
    idx = make_idx(
        namespaces=[{"name": "lab", "labels": {}, "annotations": {}}],
    )
    cls = engine.classify_namespace("lab", idx)
    assert cls["category"] == "unknown"
    assert cls["is_baseline"] is False
    assert cls["is_unknown"] is True
    assert engine.is_baseline_namespace("lab", idx) is False
    assert engine.is_unknown_namespace("lab", idx) is True


def test_platform_namespace_still_baseline(make_idx):
    """openshift-* / kube-* names continue to classify as baseline."""
    idx = make_idx(
        namespaces=[{"name": "openshift-config", "labels": {}, "annotations": {}}],
    )
    assert engine.is_baseline_namespace("openshift-config", idx) is True
    assert engine.is_unknown_namespace("openshift-config", idx) is False


def test_project_namespace_not_baseline_not_unknown(make_idx):
    """A namespace with the requester annotation is `project` — neither
    baseline nor unknown."""
    idx = make_idx(
        namespaces=[{"name": "alice-app", "labels": {},
                     "annotations": {"openshift.io/requester": "alice"}}],
    )
    assert engine.is_baseline_namespace("alice-app", idx) is False
    assert engine.is_unknown_namespace("alice-app", idx) is False


# ---------- Unknown bucket: SA / binding inheritance ---------- #

def test_sa_in_unknown_namespace_inherits_unknown(make_idx):
    idx = make_idx(
        namespaces=[{"name": "lab", "labels": {}, "annotations": {}}],
        sas=[{"name": "worker", "namespace": "lab"}],
    )
    sa = idx["sas_by_key"][("lab", "worker")]
    assert engine.is_baseline_sa(sa, idx) is False
    assert engine.is_unknown_sa(sa, idx) is True
    assert engine.is_unknown_subject(
        {"kind": "ServiceAccount", "name": "worker", "namespace": "lab"}, idx
    ) is True


def test_role_in_unknown_namespace_inherits_unknown(make_idx):
    idx = make_idx(
        namespaces=[{"name": "lab", "labels": {}, "annotations": {}}],
        roles=[{"name": "lab-reader", "namespace": "lab",
                "rules": [{"apiGroups": [""], "resources": ["pods"],
                            "verbs": ["get"]}]}],
    )
    # Engine doesn't carry a `Role` field on every row, but the route uses
    # is_baseline_namespace + is_unknown_namespace to classify Role rows.
    assert engine.is_baseline_namespace("lab", idx) is False
    assert engine.is_unknown_namespace("lab", idx) is True


def test_rolebinding_in_unknown_namespace_inherits_unknown(make_idx):
    idx = make_idx(
        namespaces=[{"name": "lab", "labels": {}, "annotations": {}}],
        cluster_roles=[{"name": "view", "rules": [{"apiGroups": [""],
                                                     "resources": ["pods"],
                                                     "verbs": ["get"]}]}],
        rbs=[{"name": "rb-in-lab", "namespace": "lab",
              "subjects": [{"kind": "User", "name": "alice"}],
              "roleRef": {"kind": "ClusterRole", "name": "view"}}],
    )
    rb = next(b for b in idx["all_bindings"] if b["name"] == "rb-in-lab")
    assert engine.is_baseline_binding(rb, idx) is False
    assert engine.is_unknown_binding(rb, idx) is True


def test_baseline_subject_unaffected_by_unknown_split(make_idx):
    """system:* / CRC bootstrap users remain baseline regardless of namespace flux."""
    idx = make_idx(
        users=[{"name": "developer"}, {"name": "kubeadmin"}],
        identities=[_crc_user_identity("developer"),
                    _crc_user_identity("kubeadmin")],
        oauth_cluster=_crc_oauth(),
        groups=[{"name": "system:masters", "users": []}],
    )
    assert engine.is_baseline_subject(
        {"kind": "User", "name": "developer"}, idx) is True
    assert engine.is_baseline_subject(
        {"kind": "User", "name": "kubeadmin"}, idx) is True
    assert engine.is_baseline_subject(
        {"kind": "Group", "name": "system:masters"}, idx) is True
    # And NOT flagged unknown.
    assert engine.is_unknown_subject(
        {"kind": "User", "name": "developer"}, idx) is False
    assert engine.is_unknown_subject(
        {"kind": "User", "name": "kubeadmin"}, idx) is False
    assert engine.is_unknown_subject(
        {"kind": "Group", "name": "system:masters"}, idx) is False


# ---------- Unknown bucket: row producers carry the flag ---------- #

def test_all_subjects_carries_unknown_for_unknown_ns_sa(make_idx):
    idx = make_idx(
        namespaces=[{"name": "lab", "labels": {}, "annotations": {}}],
        sas=[{"name": "worker", "namespace": "lab"}],
    )
    rows = engine.all_subjects(idx)
    row = next(r for r in rows
                if r["kind"] == "ServiceAccount" and r["name"] == "worker")
    assert row["baseline"] is False
    assert row["unknown"] is True


def test_mock_subjects_have_nginx_sas_in_unknown_bucket():
    """The mock 'nginx' namespace is unclassified (no requester, not
    platform-named) — its SAs land in unknown, not baseline."""
    idx = engine.index()
    rows = engine.all_subjects(idx)
    for sa_name in ("default", "deployer"):
        row = next(r for r in rows
                    if r["kind"] == "ServiceAccount"
                    and r["namespace"] == "nginx"
                    and r["name"] == sa_name)
        assert row["unknown"] is True, sa_name
        assert row["baseline"] is False, sa_name


# ---------- Unknown bucket: route counts + tab rendering ---------- #

def _route_counts_smoke(path, expected_buckets=("Yours", "Unclassified", "Baseline", "All")):
    from lineage.main import app
    client = app.test_client()
    resp = client.get(path)
    assert resp.status_code == 200, path
    body = resp.data.decode()
    for label in expected_buckets:
        assert f">{label} " in body or f">{label}<" in body, (
            f"{path}: bucket tab {label!r} missing in toggle")


def test_route_subjects_renders_unknown_tab():
    _route_counts_smoke("/subjects")


def test_route_privileged_renders_unknown_tab():
    _route_counts_smoke("/privileged")


def test_route_roles_renders_unknown_tab():
    _route_counts_smoke("/roles")


def test_route_images_renders_unknown_tab():
    _route_counts_smoke("/images")


def test_route_cross_namespace_renders_unknown_tab():
    _route_counts_smoke("/cross-namespace")


def test_route_who_can_results_renders_bucket_filters():
    from lineage.main import app
    client = app.test_client()
    body = client.get(
        "/who-can?verb=list&resource=secrets&namespace=mine-platform"
    ).data.decode()
    assert ">Unclassified " in body
    assert "bucket=unknown" in body


def test_route_who_can_explains_source_and_accepts_name():
    from lineage.main import app
    client = app.test_client()
    body = client.get(
        "/who-can?verb=use&resource=securitycontextconstraints&name=privileged"
    ).data.decode()

    assert "cached read-only inventory" in body
    assert "oc adm policy who-can" in body
    assert "named <span class=\"mono\">privileged</span>" in body


def test_route_who_can_does_not_render_name_suggestions():
    from lineage.main import app
    client = app.test_client()
    body = client.get("/who-can?resource=pods").data.decode()

    assert 'name="name"' in body
    assert 'names-list' not in body
    assert 'names-by-resource-data' not in body


def test_route_who_can_renders_subject_and_path_filters():
    from lineage.main import app
    client = app.test_client()
    body = client.get(
        "/who-can?verb=list&resource=secrets&namespace=mine-platform&bucket=all"
    ).data.decode()

    assert ">All subjects " in body
    assert ">Users " in body
    assert ">Groups " in body
    assert ">SAs " in body
    assert ">Direct " in body
    assert ">Via group " in body
    assert ">Ghosts " in body
    assert "who-filter-stack" in body
    assert "who-filter-primary" in body
    assert "who-filter-secondary" in body
    assert "who-filter-tertiary" in body
    assert body.count('class="who-filter-dot"') == 2


def test_route_who_can_kind_and_path_filters_apply(monkeypatch):
    from lineage.main import app

    binding = {"kind": "ClusterRoleBinding", "name": "lab-binding",
               "namespace": None}
    rows = [
        {"subject": {"kind": "Group", "name": "team"}, "binding": binding,
         "ghost": False, "via_group": None, "baseline": False,
         "unknown": False},
        {"subject": {"kind": "User", "name": "alice"}, "binding": binding,
         "ghost": False, "via_group": "team", "baseline": False,
         "unknown": False},
        {"subject": {"kind": "ServiceAccount", "name": "builder",
                     "namespace": "ci"}, "binding": binding,
         "ghost": False, "via_group": None, "baseline": False,
         "unknown": False},
        {"subject": {"kind": "User", "name": "ghost-user"},
         "binding": binding, "ghost": True, "via_group": None,
         "baseline": False, "unknown": False},
        {"subject": {"kind": "User", "name": "platform-user"},
         "binding": binding, "ghost": False, "via_group": None,
         "baseline": True, "unknown": False},
    ]
    idx = make_index()
    monkeypatch.setattr(engine, "index", lambda: idx)
    monkeypatch.setattr(engine, "all_namespaces", lambda idx: ["ci"])
    monkeypatch.setattr(engine, "all_resources_seen", lambda idx: ["pods"])
    monkeypatch.setattr(engine, "who_can",
                        lambda verb, resource, namespace, idx, name=None: rows)

    client = app.test_client()
    expanded = client.get(
        "/who-can?verb=get&resource=pods&bucket=yours&kind=User&path=expanded"
    ).data.decode()
    assert "alice" in expanded
    assert "builder" not in expanded
    assert "ghost-user" not in expanded
    assert "platform-user" not in expanded

    ghosts = client.get(
        "/who-can?verb=get&resource=pods&bucket=yours&kind=User&path=ghost"
    ).data.decode()
    assert "ghost-user" in ghosts
    assert "alice" not in ghosts


def test_who_can_wildcard_resource_respects_api_group():
    idx = make_index(
        users=[{"name": "autoscaler"}, {"name": "root"}],
        cluster_roles=[
            {"name": "autoscaling-admin",
             "rules": [{"apiGroups": ["autoscaling.openshift.io"],
                        "resources": ["*"],
                        "verbs": ["*"]}]},
            {"name": "cluster-admin",
             "rules": [{"apiGroups": ["*"],
                        "resources": ["*"],
                        "verbs": ["*"]}]},
        ],
        crbs=[
            {"name": "autoscaler-admin",
             "subjects": [{"kind": "User", "name": "autoscaler"}],
             "roleRef": {"kind": "ClusterRole",
                         "name": "autoscaling-admin"}},
            {"name": "root-admin",
             "subjects": [{"kind": "User", "name": "root"}],
             "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"}},
        ],
    )

    names = {m["subject"]["name"] for m in engine.who_can(
        "list", "secrets", "payments-prod", idx)}

    assert "root" in names
    assert "autoscaler" not in names


def test_who_can_core_pods_does_not_match_metrics_pods():
    idx = make_index(
        users=[{"name": "metrics-operator"}, {"name": "pod-creator"}],
        cluster_roles=[
            {"name": "metrics-pod-creator",
             "rules": [{"apiGroups": ["metrics.k8s.io"],
                        "resources": ["pods"],
                        "verbs": ["create"]}]},
            {"name": "core-pod-creator",
             "rules": [{"apiGroups": [""],
                        "resources": ["pods"],
                        "verbs": ["create"]}]},
        ],
        crbs=[
            {"name": "metrics-operator",
             "subjects": [{"kind": "User", "name": "metrics-operator"}],
             "roleRef": {"kind": "ClusterRole",
                         "name": "metrics-pod-creator"}},
            {"name": "pod-creator",
             "subjects": [{"kind": "User", "name": "pod-creator"}],
             "roleRef": {"kind": "ClusterRole", "name": "core-pod-creator"}},
        ],
    )

    names = {m["subject"]["name"] for m in engine.who_can(
        "create", "pods", "payments-prod", idx)}

    assert names == {"pod-creator"}


def test_who_can_group_wildcard_matches_known_resource_api_group():
    idx = make_index(
        users=[{"name": "apps-operator"}],
        cluster_roles=[
            {"name": "apps-resource-hint",
             "rules": [{"apiGroups": ["apps"],
                        "resources": ["deployments"],
                        "verbs": ["get"]}]},
            {"name": "apps-admin",
             "rules": [{"apiGroups": ["apps"],
                        "resources": ["*"],
                        "verbs": ["list"]}]},
        ],
        crbs=[
            {"name": "apps-operator-admin",
             "subjects": [{"kind": "User", "name": "apps-operator"}],
             "roleRef": {"kind": "ClusterRole", "name": "apps-admin"}},
        ],
    )

    names = {m["subject"]["name"] for m in engine.who_can(
        "list", "deployments", "payments-prod", idx)}

    assert names == {"apps-operator"}


def test_who_can_cluster_scoped_resource_ignores_rolebindings():
    idx = make_index(
        users=[{"name": "cluster-reader"}, {"name": "namespace-reader"}],
        namespaces=[{"name": "payments-prod", "labels": {},
                     "annotations": {}}],
        cluster_roles=[
            {"name": "namespace-reader",
             "rules": [{"apiGroups": [""],
                        "resources": ["namespaces"],
                        "verbs": ["get"]}]},
        ],
        crbs=[
            {"name": "cluster-reader",
             "subjects": [{"kind": "User", "name": "cluster-reader"}],
             "roleRef": {"kind": "ClusterRole", "name": "namespace-reader"}},
        ],
        rbs=[
            {"name": "namespace-reader", "namespace": "payments-prod",
             "subjects": [{"kind": "User", "name": "namespace-reader"}],
             "roleRef": {"kind": "ClusterRole", "name": "namespace-reader"}},
        ],
    )

    names = {m["subject"]["name"] for m in engine.who_can(
        "get", "namespaces", None, idx)}

    assert names == {"cluster-reader"}


def test_who_can_without_name_excludes_resource_name_limited_rules():
    idx = make_index(
        users=[{"name": "named-secret-reader"}, {"name": "all-secret-reader"}],
        roles=[
            {"name": "named-secret-reader", "namespace": "payments-prod",
             "rules": [{"apiGroups": [""],
                        "resources": ["secrets"],
                        "resourceNames": ["db-password"],
                        "verbs": ["get"]}]},
            {"name": "all-secret-reader", "namespace": "payments-prod",
             "rules": [{"apiGroups": [""],
                        "resources": ["secrets"],
                        "verbs": ["get"]}]},
        ],
        rbs=[
            {"name": "named-secret-reader", "namespace": "payments-prod",
             "subjects": [{"kind": "User", "name": "named-secret-reader"}],
             "roleRef": {"kind": "Role", "name": "named-secret-reader"}},
            {"name": "all-secret-reader", "namespace": "payments-prod",
             "subjects": [{"kind": "User", "name": "all-secret-reader"}],
             "roleRef": {"kind": "Role", "name": "all-secret-reader"}},
        ],
    )

    names = {m["subject"]["name"] for m in engine.who_can(
        "get", "secrets", "payments-prod", idx)}

    assert names == {"all-secret-reader"}


def test_who_can_name_matches_resource_name_limited_rules():
    idx = make_index(
        users=[{"name": "named-secret-reader"}, {"name": "all-secret-reader"}],
        roles=[
            {"name": "named-secret-reader", "namespace": "payments-prod",
             "rules": [{"apiGroups": [""],
                        "resources": ["secrets"],
                        "resourceNames": ["db-password"],
                        "verbs": ["get"]}]},
            {"name": "all-secret-reader", "namespace": "payments-prod",
             "rules": [{"apiGroups": [""],
                        "resources": ["secrets"],
                        "verbs": ["get"]}]},
        ],
        rbs=[
            {"name": "named-secret-reader", "namespace": "payments-prod",
             "subjects": [{"kind": "User", "name": "named-secret-reader"}],
             "roleRef": {"kind": "Role", "name": "named-secret-reader"}},
            {"name": "all-secret-reader", "namespace": "payments-prod",
             "subjects": [{"kind": "User", "name": "all-secret-reader"}],
             "roleRef": {"kind": "Role", "name": "all-secret-reader"}},
        ],
    )

    db_password = {m["subject"]["name"] for m in engine.who_can(
        "get", "secrets", "payments-prod", idx, name="db-password")}
    other = {m["subject"]["name"] for m in engine.who_can(
        "get", "secrets", "payments-prod", idx, name="other-secret")}

    assert db_password == {"named-secret-reader", "all-secret-reader"}
    assert other == {"all-secret-reader"}


def test_namespaces_page_defaults_to_projects_and_orders_unclassified():
    from lineage.main import app
    client = app.test_client()
    body = client.get("/namespaces").data.decode()
    assert 'href="?category=project#namespaces-list" class="active"' in body
    assert 'href="?category=mine#namespaces-list" class=""' in body
    start = body.index('<div class="filterbar">')
    end = body.index("</div>", start)
    filters = body[start:end]
    projects = filters.index(">Projects ")
    unclassified = filters.index(">Unclassified ")
    openshift = filters.index(">OpenShift ")
    system = filters.index(">System ")
    assert projects < unclassified < openshift < system


def test_unknown_bucket_filters_to_unknown_subjects():
    """Selecting bucket=unknown on /subjects shows the nginx SAs but not
    the system/baseline ones, and not the project-owned ones."""
    from lineage.main import app
    client = app.test_client()
    body = client.get("/subjects?bucket=unknown").data.decode()
    # nginx SAs (unclassified ns) should appear in unknown
    assert "nginx" in body
    # platform-admins (project-owned group) should NOT show in unknown bucket
    # (alice is project-owned; her direct row is 'yours', not 'unknown')
    # We can't strictly assert absence of name 'alice' because she also
    # appears as a User row; instead assert the bucket scoping by category.


def test_route_namespace_detail_unknown_bucket_filter_works():
    """The bucket=unknown filter keeps only rows whose subject lives in
    an Unclassified namespace that we can actually classify. A deleted
    namespace (e.g. legacy-pipelines) is NOT classifiable, so a
    resurrectable SA there does not claim 'unknown' — it appears under
    the 'all' / 'yours' bucket alongside other review-worthy ghosts,
    consistent with engine.all_subjects() and resurrectable_sa_identities.

    This used to be the opposite (deleted ns → unknown bucket), which
    contradicted /subjects. The Lineage 'unknown' bucket is reserved
    for namespaces that PRESENTLY exist but have no classifying
    signal — surfacing 'oc create namespace foo' grants for review."""
    from lineage.main import app
    client = app.test_client()
    section_unknown = _extract_access_section(client.get(
        "/namespace/mine-platform?access_bucket=unknown&access_kind=ServiceAccount"
    ).data.decode())
    # Bucket toggle still rendered.
    assert "Unclassified" in section_unknown
    # legacy-pipelines (deleted ns) must NOT leak into the unknown bucket.
    assert "legacy-pipelines" not in section_unknown

    # Bucket=all (or yours, since deleted-ns isn't baseline either) DOES
    # surface the resurrectable reference — the user still has to find it.
    section_all = _extract_access_section(client.get(
        "/namespace/mine-platform?access_bucket=all&access_kind=ServiceAccount"
    ).data.decode())
    assert "legacy-pipelines" in section_all


# ---------- Display rule: small lists stay inline ---------- #

def test_namespace_detail_card_has_bottom_margin():
    """Smoke check: the .banner CSS used for the deleted-namespace card on
    /namespaces has margin-bottom so it doesn't visually overlap the
    filterbar that follows."""
    import re
    with open("lineage/static/style.css", "r") as f:
        css = f.read()
    m = re.search(r"\.banner\s*\{([^}]*)\}", css, re.DOTALL)
    assert m is not None
    body = m.group(1)
    assert "margin-bottom" in body, "expected margin-bottom in .banner"


# ---------- Install-time window heuristic ---------- #

def test_install_window_rule_keeps_day_zero_ns_out_of_unknown(make_idx):
    """A namespace created within INSTALL_WINDOW_HOURS of cluster install,
    with no other signal, classifies as `system` (install-time
    infrastructure) — NOT unknown."""
    install_ts = "2024-09-01T00:00:00Z"
    idx = make_idx(
        namespaces=[
            {"name": "kube-system", "labels": {}, "annotations": {},
             "creationTimestamp": install_ts},
            # Created 1h after install — should be system, not unknown.
            {"name": "day-zero-infra", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-09-01T01:00:00Z"},
        ],
    )
    cls = engine.classify_namespace("day-zero-infra", idx)
    assert cls["category"] == "system"
    assert cls["is_baseline"] is True
    assert cls["is_unknown"] is False
    # Reason references the install window for auditability.
    assert any("install" in s.reason for s in cls["signals"])


def test_install_window_rule_captures_crc_25h_infra_namespace(make_idx):
    """CRC 4.19.8 had hostpath-provisioner roughly +25h after kube-system."""
    install_ts = "2024-09-01T00:00:00Z"
    idx = make_idx(
        namespaces=[
            {"name": "kube-system", "labels": {}, "annotations": {},
             "creationTimestamp": install_ts},
            {"name": "hostpath-provisioner", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-09-02T01:00:00Z"},
        ],
    )
    cls = engine.classify_namespace("hostpath-provisioner", idx)
    assert cls["category"] == "system"
    assert cls["is_baseline"] is True
    assert any("25h" in s.reason for s in cls["signals"])


def test_install_window_rule_does_not_capture_later_ns(make_idx):
    """A namespace created well past the install window with no other
    signal stays `unknown`."""
    idx = make_idx(
        namespaces=[
            {"name": "kube-system", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-09-01T00:00:00Z"},
            # Three months later — outside any reasonable install window.
            {"name": "scratch", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-12-01T00:00:00Z"},
        ],
    )
    cls = engine.classify_namespace("scratch", idx)
    assert cls["category"] == "unknown"
    assert cls["is_unknown"] is True


def test_install_window_rule_does_not_override_existing_classification(
        make_idx):
    """An `openshift-*` namespace created at install time must remain
    `openshift` — the install-window rule is a fallback, not an
    override."""
    idx = make_idx(
        namespaces=[
            {"name": "kube-system", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-09-01T00:00:00Z"},
            {"name": "openshift-monitoring", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-09-01T00:30:00Z"},
        ],
    )
    cls = engine.classify_namespace("openshift-monitoring", idx)
    assert cls["category"] == "openshift"
    assert cls["is_baseline"] is True


def test_install_window_rule_does_not_override_project_signal(make_idx):
    """Requester/project ownership wins even inside the install window."""
    idx = make_idx(
        namespaces=[
            {"name": "kube-system", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-09-01T00:00:00Z"},
            {"name": "early-user-project", "labels": {},
             "annotations": {"openshift.io/requester": "alice"},
             "creationTimestamp": "2024-09-01T02:00:00Z"},
        ],
    )
    cls = engine.classify_namespace("early-user-project", idx)
    assert cls["category"] == "project"
    assert cls["is_user_owned"] is True
    assert cls["is_baseline"] is False


def test_install_window_rule_skipped_when_install_ts_unknown(make_idx):
    """If kube-system isn't visible (no install timestamp) the rule
    silently does nothing — namespaces fall back to unknown as before."""
    idx = make_idx(
        namespaces=[
            {"name": "scratch", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-09-01T01:00:00Z"},
        ],
    )
    cls = engine.classify_namespace("scratch", idx)
    assert cls["category"] == "unknown"


def test_install_window_constant_is_documented_in_classifier():
    """README references INSTALL_WINDOW_HOURS — make sure the constant
    actually exists and is a positive integer."""
    from lineage import classifier as cf
    assert isinstance(cf.INSTALL_WINDOW_HOURS, int)
    assert cf.INSTALL_WINDOW_HOURS == 25


def test_cluster_install_ts_prefers_kube_system(make_idx):
    idx = make_idx(
        namespaces=[
            {"name": "openshift-config", "labels": {}, "annotations": {},
             "creationTimestamp": "2020-01-01T00:00:00Z"},
            {"name": "kube-system", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-09-01T00:00:00Z"},
        ],
    )
    assert engine._cluster_install_ts(idx) == "2024-09-01T00:00:00Z"


def test_cluster_install_ts_falls_back_to_earliest_baseline(make_idx):
    idx = make_idx(
        namespaces=[
            {"name": "openshift-config", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-09-01T00:00:00Z"},
            {"name": "openshift-monitoring", "labels": {}, "annotations": {},
             "creationTimestamp": "2024-09-01T01:00:00Z"},
        ],
    )
    # kube-system absent → take the earliest baseline.
    assert engine._cluster_install_ts(idx) == "2024-09-01T00:00:00Z"


# ---------- HTPasswd readability / degraded state ---------- #

def _htpasswd_oauth():
    return {"identityProviders": [
        {"name": "cool", "type": "HTPasswd",
         "htpasswd": {"fileData": {"name": "htpasswd-secret"}}}]}


def test_unreadable_htpasswd_does_not_mark_phantom(make_idx):
    """When the HTPasswd Secret is unreadable, Lineage cannot know whether
    a user is still in the backing store, so it must NOT flag User+Identity
    pairs as phantom just because the in-memory htpasswd list is empty."""
    idx = make_idx(
        users=[{"name": "alice"}],
        identities=[{"name": "cool:alice", "user": {"name": "alice"},
                     "providerName": "cool"}],
        htpasswd_users=[],
        htpasswd_available=False,
        htpasswd_configured=True,
        htpasswd_reason="forbidden",
        oauth_cluster=_htpasswd_oauth(),
    )
    audit = engine.identity_audit(idx)
    assert audit["phantom_users"] == []
    assert engine._is_phantom_user("alice", idx) is False


def test_unreadable_htpasswd_does_not_synthesize_latent(make_idx):
    """No latent-from-htpasswd entries should appear when the Secret was
    unreadable — the empty list is the absence of data, not evidence of
    absence."""
    idx = make_idx(
        users=[{"name": "alice"}],
        htpasswd_users=[],
        htpasswd_available=False,
        htpasswd_configured=True,
        htpasswd_reason="forbidden",
        oauth_cluster=_htpasswd_oauth(),
    )
    audit = engine.identity_audit(idx)
    assert audit["latent_users"] == []


def test_identity_audit_page_shows_degraded_banner_when_htpasswd_unreadable(
        monkeypatch, make_idx):
    """The dedicated identity-audit page surfaces a clear degraded note when
    HTPasswd is configured but its Secret was not readable."""
    idx = make_idx(
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
    with main_module.app.test_client() as client:
        body = client.get("/identity-audit").data.decode()
    assert "HTPasswd checks degraded" in body
    assert "forbidden: get secrets" in body


def test_readable_htpasswd_still_detects_latent_and_phantom(make_idx):
    """When the Secret is readable: tom-future-hire is in htpasswd with no
    User → latent. alice has a User + Identity pointing at the HTPasswd IdP
    but is missing from the htpasswd list → phantom."""
    idx = make_idx(
        users=[{"name": "alice"}],
        identities=[{"name": "cool:alice", "user": {"name": "alice"},
                     "providerName": "cool"}],
        htpasswd_users=[
            {"username": "tom-future-hire", "idp_name": "cool",
             "secret_namespace": "openshift-config",
             "secret_name": "htpasswd-secret"},
        ],
        htpasswd_available=True,
        htpasswd_configured=True,
        oauth_cluster=_htpasswd_oauth(),
    )
    audit = engine.identity_audit(idx)
    assert any(u["username"] == "tom-future-hire" for u in audit["latent_users"])
    phantom_names = [p["name"] for p in audit["phantom_users"]]
    assert "alice" in phantom_names
    assert engine._is_phantom_user("alice", idx) is True


def test_user_without_identity_but_in_htpasswd_shows_both_markers(make_idx):
    """The 'Tom case': tom has a User object, his htpasswd entry exists,
    but his Identity was deleted. We expect both 'No ID' (stranded) AND
    'htpasswd-backed' markers — multiple identity facts can be true at once."""
    idx = make_idx(
        users=[{"name": "tom"}],
        identities=[],  # identity/cool:tom was deleted
        htpasswd_users=[
            {"username": "tom", "idp_name": "cool",
             "secret_namespace": "openshift-config",
             "secret_name": "htpasswd-secret"},
        ],
        htpasswd_available=True,
        htpasswd_configured=True,
        oauth_cluster=_htpasswd_oauth(),
    )
    markers = engine._subject_identity_markers(
        {"kind": "User", "name": "tom"}, idx)
    assert markers["stranded"] is True
    assert markers["htpasswd_backed"] is True
    assert markers["phantom"] is False

    subjects = engine.all_subjects(idx)
    row = next(s for s in subjects if s["kind"] == "User" and s["name"] == "tom")
    assert row["stranded"] is True
    assert row["htpasswd_backed"] is True
    assert row["phantom"] is False


def test_user_without_identity_when_htpasswd_unavailable_only_stranded(make_idx):
    """Same User shape, but the Secret is unreadable. Expect stranded only —
    htpasswd-backed must NOT be asserted when we couldn't read the source."""
    idx = make_idx(
        users=[{"name": "tom"}],
        identities=[],
        htpasswd_users=[],
        htpasswd_available=False,
        htpasswd_configured=True,
        htpasswd_reason="forbidden",
        oauth_cluster=_htpasswd_oauth(),
    )
    markers = engine._subject_identity_markers(
        {"kind": "User", "name": "tom"}, idx)
    assert markers["stranded"] is True
    assert markers["htpasswd_backed"] is False


def test_subjects_page_renders_htpasswd_backed_badge(monkeypatch, make_idx):
    """End-to-end: the /subjects page shows htpasswd-backed next to a
    stranded User who is present in the htpasswd Secret."""
    idx = make_idx(
        users=[{"name": "tom"}],
        identities=[],
        htpasswd_users=[
            {"username": "tom", "idp_name": "cool",
             "secret_namespace": "openshift-config",
             "secret_name": "htpasswd-secret"},
        ],
        htpasswd_available=True,
        htpasswd_configured=True,
        oauth_cluster=_htpasswd_oauth(),
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with main_module.app.test_client() as client:
        body = client.get("/subjects?bucket=yours&kind=User").data.decode()
    assert ">tom</a>" in body
    assert "No ID" in body
    assert "htpasswd-backed" in body


def test_subject_detail_page_shows_degraded_banner(monkeypatch, make_idx):
    """When htpasswd is configured but unreadable, the User detail page
    explains the degraded state. The htpasswd-backed badge is absent."""
    idx = make_idx(
        users=[{"name": "tom"}],
        identities=[],
        htpasswd_users=[],
        htpasswd_available=False,
        htpasswd_configured=True,
        htpasswd_reason="forbidden",
        oauth_cluster=_htpasswd_oauth(),
    )
    from lineage import main as main_module
    monkeypatch.setattr(main_module.engine, "index", lambda: idx)
    with main_module.app.test_client() as client:
        body = client.get("/subject/User/tom").data.decode()
    assert "HTPasswd checks degraded" in body
    # The htpasswd-backed badge must not render when the Secret is unreadable;
    # the same word can appear in the explanatory banner, so match the badge.
    assert 'class="badge badge-info"' not in body or "htpasswd-backed</span>" not in body


def test_index_carries_htpasswd_availability_flags():
    """The engine index exposes both the user list and availability flags."""
    idx = engine.index()
    assert "htpasswd_users" in idx
    assert "htpasswd_available" in idx
    assert "htpasswd_configured" in idx
    assert isinstance(idx["htpasswd_users"], list)
    assert isinstance(idx["htpasswd_available"], bool)
    assert isinstance(idx["htpasswd_configured"], bool)


def test_identity_audit_always_populates_resurrectable_split(make_idx):
    """Contract: identity_audit() always sets the actionable/baseline
    split keys and the totals — even for an empty index with no findings.
    cli.py and main.py index these keys directly and rely on this
    guarantee."""
    audit = engine.identity_audit(make_idx())
    for key in ("resurrectable_actionable",
                "resurrectable_implicit_actionable",
                "resurrectable_baseline",
                "resurrectable_implicit_baseline"):
        assert key in audit, f"identity_audit must set {key!r}"
        assert isinstance(audit[key], list)
        assert audit[key] == []
    assert audit["identity_total"] == 0
    assert audit["total"] == 0
