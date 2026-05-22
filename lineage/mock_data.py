"""
Mock dataset for offline demos and tests.
LINEAGE_MOCK=1 to use.
"""

INSTALL_TIME = "2024-09-01T00:00:00Z"

USERS = [
    {"name": "alice", "fullName": "Alice Anderson",
     "creationTimestamp": "2024-12-01T10:00:00Z", "identities": ["dev:alice"]},
    {"name": "bob", "fullName": "Bob Brown",
     "creationTimestamp": "2024-12-01T10:05:00Z", "identities": ["dev:bob"]},
    {"name": "eve", "fullName": "Eve Engineer",
     "creationTimestamp": "2025-01-12T09:00:00Z", "identities": ["dev:eve"]},
    {"name": "dana", "fullName": "Dana Reviewer",
     "creationTimestamp": "2025-01-12T09:05:00Z", "identities": ["dev:dana"]},
    # User and Identity exist, but the backing htpasswd entry is absent.
    {"name": "mallory", "fullName": "Mallory Former",
     "creationTimestamp": "2025-01-20T10:00:00Z", "identities": ["dev:mallory"]},
    # User object exists and has a grant, but no Identity links it to an IdP.
    {"name": "manual-approver", "fullName": "Manual Approver",
     "creationTimestamp": "2025-02-01T10:00:00Z", "identities": []},
    # No Identity, but the username IS in the htpasswd backing Secret. The
    # Subjects table should surface BOTH 'No ID' and 'htpasswd-backed'
    # badges — multiple identity facts true at once.
    {"name": "rhea-rehire", "fullName": "Rhea Rehire",
     "creationTimestamp": "2025-02-15T10:00:00Z", "identities": []},
    {"name": "kubeadmin", "fullName": "",
     "creationTimestamp": INSTALL_TIME, "identities": []},
]

IDENTITIES = [
    {"name": "dev:alice", "providerName": "dev", "providerUserName": "alice",
     "user": {"name": "alice"}, "creationTimestamp": "2024-12-01T10:00:00Z"},
    {"name": "dev:bob", "providerName": "dev", "providerUserName": "bob",
     "user": {"name": "bob"}, "creationTimestamp": "2024-12-01T10:05:00Z"},
    {"name": "dev:eve", "providerName": "dev", "providerUserName": "eve",
     "user": {"name": "eve"}, "creationTimestamp": "2025-01-12T09:00:00Z"},
    {"name": "dev:dana", "providerName": "dev", "providerUserName": "dana",
     "user": {"name": "dana"}, "creationTimestamp": "2025-01-12T09:05:00Z"},
    {"name": "dev:mallory", "providerName": "dev", "providerUserName": "mallory",
     "user": {"name": "mallory"}, "creationTimestamp": "2025-01-20T10:00:00Z"},
    # Identity points at a User object that no longer exists.
    {"name": "dev:orphaned-employee", "providerName": "dev",
     "providerUserName": "orphaned-employee",
     "user": {"name": "orphaned-employee"},
     "creationTimestamp": "2025-02-03T10:00:00Z"},
]

GROUPS = [
    {"name": "platform-admins", "users": ["alice"],
     "creationTimestamp": "2024-12-01T10:10:00Z"},
    {"name": "engineers", "users": ["alice", "eve", "nina-onboarding"],
     "creationTimestamp": "2025-01-12T09:10:00Z"},
    {"name": "qa-team", "users": ["dana"],
     "creationTimestamp": "2025-01-12T09:12:00Z"},
]

NAMESPACES = [
    # Kubernetes core (system)
    {"name": "default", "labels": {}, "annotations": {},
     "creationTimestamp": INSTALL_TIME},
    {"name": "kube-system", "labels": {}, "annotations": {},
     "creationTimestamp": INSTALL_TIME},
    {"name": "kube-public", "labels": {}, "annotations": {},
     "creationTimestamp": INSTALL_TIME},
    # OpenShift platform — bootstrap anchors + cluster monitoring
    {"name": "openshift-config", "labels": {}, "annotations": {},
     "creationTimestamp": INSTALL_TIME},
    {"name": "openshift-gitops", "labels": {}, "annotations": {},
     "creationTimestamp": INSTALL_TIME},
    {"name": "openshift-authentication", "labels": {},
     "annotations": {"openshift.io/sa.scc.uid-range": "1000050000/10000"},
     "creationTimestamp": INSTALL_TIME},
    {"name": "openshift-monitoring", "labels": {}, "annotations": {},
     "creationTimestamp": INSTALL_TIME},
    # OpenShift Project — created via `oc new-project` (carries requester)
    {"name": "alice-project", "labels": {},
     "annotations": {"openshift.io/requester": "alice",
                     "openshift.io/display-name": "Alice's project"},
     "creationTimestamp": "2024-12-01T11:00:00Z"},
    {"name": "mine-platform", "labels": {"app.kubernetes.io/part-of": "mine-platform"},
     "annotations": {"openshift.io/requester": "alice",
                     "openshift.io/display-name": "Mine Platform"},
     "creationTimestamp": "2025-01-12T09:20:00Z"},
    # Second OpenShift Project — different requester, demonstrates Mine.
    {"name": "demo", "labels": {},
     "annotations": {"openshift.io/requester": "bob"},
     "creationTimestamp": "2024-12-01T11:05:00Z"},
    {"name": "shared-images", "labels": {},
     "annotations": {"openshift.io/requester": "image-admin"},
     "creationTimestamp": "2025-01-15T13:00:00Z"},
    # The flagship path: engineers group has a namespaced Role here that lets
    # group members read secrets. alice is in engineers, so the README's
    # `alice -> engineers -> secret-readers -> read-secrets -> payments-prod`
    # example resolves to real objects in this dataset.
    {"name": "payments-prod",
     "labels": {"app.kubernetes.io/part-of": "payments"},
     "annotations": {"openshift.io/requester": "alice",
                     "openshift.io/display-name": "Payments (prod)"},
     "creationTimestamp": "2025-03-10T09:00:00Z"},
    {"name": "team-gitops", "labels": {"app.kubernetes.io/managed-by": "ArgoCD"},
     "annotations": {"openshift.io/requester": "alice"},
     "creationTimestamp": "2025-01-18T11:00:00Z"},
    # Bare namespace, no positive markers — demonstrates the `unknown` chip.
    # Could be `oc create ns` by a human, could be install-time infra. Lineage
    # leaves the call to the user rather than guessing it into Mine.
    {"name": "nginx", "labels": {}, "annotations": {},
     "creationTimestamp": "2024-12-01T11:00:00Z"},
    # Operator-looking namespace with no requester annotation. In v1 it stays
    # unknown until the classifier has a dependable ownership signal.
    {"name": "cert-manager-operator", "labels": {"olm.managed": "true"},
     "annotations": {},
     "creationTimestamp": "2025-01-21T08:00:00Z"},
    # `ci` namespace exists, but its `pipeline` SA was deleted while a
    # cluster-admin CRB still references it. Recreating the SA reactivates.
    {"name": "ci", "labels": {},
     "annotations": {"openshift.io/requester": "alice"},
     "creationTimestamp": "2025-02-14T09:00:00Z"},
    # `tooling` exists; its `deployer` SA is gone but the `admin` binding
    # (User-form principal) survives.
    {"name": "tooling", "labels": {},
     "annotations": {"openshift.io/requester": "alice"},
     "creationTimestamp": "2025-01-09T08:00:00Z"},
    # NOTE: `legacy-pipelines` is intentionally absent from this list —
    # the namespace was deleted but a CRB still references its SA.
    # NOTE: `forgotten-batch` is absent for the same reason — referenced by
    # the privileged SCC user list below.
    # NOTE: `retired-pipeline-ns` is also intentionally absent — its
    # implicit `system:serviceaccounts:retired-pipeline-ns` group still
    # shows up under the privileged SCC. Recreating the namespace
    # silently re-establishes the SCC grant for every SA in it.
    {"name": "image-drift-demo", "labels": {},
     "annotations": {"openshift.io/requester": "alice",
                     "openshift.io/display-name": "Image-drift showcase"},
     "creationTimestamp": "2026-03-10T09:00:00Z"},
]

SERVICE_ACCOUNTS = [
    {"name": "default", "namespace": "default", "labels": {},
     "creationTimestamp": INSTALL_TIME, "ownerReferences": []},
    {"name": "default", "namespace": "nginx", "labels": {},
     "creationTimestamp": "2024-12-01T11:00:00Z", "ownerReferences": []},
    {"name": "deployer", "namespace": "nginx", "labels": {},
     "creationTimestamp": "2024-12-01T11:00:30Z", "ownerReferences": []},
    {"name": "default", "namespace": "demo", "labels": {},
     "creationTimestamp": "2024-12-01T11:05:00Z", "ownerReferences": []},
    {"name": "default", "namespace": "mine-platform", "labels": {},
     "creationTimestamp": "2025-01-12T09:20:00Z", "ownerReferences": []},
    {"name": "builder", "namespace": "mine-platform", "labels": {"app": "build"},
     "creationTimestamp": "2025-01-12T09:25:00Z", "ownerReferences": []},
    {"name": "default", "namespace": "ci", "labels": {},
     "creationTimestamp": "2025-02-14T09:00:00Z", "ownerReferences": []},
    {"name": "builder", "namespace": "ci", "labels": {"app": "pipeline"},
     "creationTimestamp": "2025-02-14T09:05:00Z", "ownerReferences": []},
    {"name": "default", "namespace": "shared-images", "labels": {},
     "creationTimestamp": "2025-01-15T13:00:00Z", "ownerReferences": []},
    {"name": "default", "namespace": "image-drift-demo", "labels": {},
     "creationTimestamp": "2026-03-10T09:00:00Z", "ownerReferences": []},
]

CLUSTER_ROLES = [
    {"name": "cluster-admin", "labels": {}, "annotations": {},
     "aggregationRule": None,
     "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
     "creationTimestamp": INSTALL_TIME},
    {"name": "admin", "labels": {}, "annotations": {},
     "aggregationRule": {
         "clusterRoleSelectors": [
             {"matchLabels": {"rbac.authorization.k8s.io/aggregate-to-admin": "true"}}
         ]
     },
     "rules": [], "creationTimestamp": INSTALL_TIME},
    {"name": "admin-storage",
     "labels": {"rbac.authorization.k8s.io/aggregate-to-admin": "true"},
     "annotations": {}, "aggregationRule": None,
     "rules": [{"apiGroups": [""], "resources": ["persistentvolumeclaims"], "verbs": ["*"]}],
     "creationTimestamp": INSTALL_TIME},
    {"name": "admin-workloads",
     "labels": {"rbac.authorization.k8s.io/aggregate-to-admin": "true"},
     "annotations": {}, "aggregationRule": None,
     "rules": [
         {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["*"]},
         {"apiGroups": [""], "resources": ["pods", "secrets", "configmaps"], "verbs": ["*"]},
     ],
     "creationTimestamp": INSTALL_TIME},
    {"name": "admin-rbac",
     "labels": {"rbac.authorization.k8s.io/aggregate-to-admin": "true"},
     "annotations": {}, "aggregationRule": None,
     "rules": [
         {"apiGroups": ["rbac.authorization.k8s.io"],
          "resources": ["roles", "rolebindings"], "verbs": ["get", "list", "watch", "create", "update", "patch", "delete"]},
     ],
     "creationTimestamp": INSTALL_TIME},
    {"name": "edit", "labels": {}, "annotations": {},
     "aggregationRule": None,
     "rules": [
         {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "list", "watch", "create", "update", "patch"]},
         {"apiGroups": [""], "resources": ["pods", "services", "configmaps"], "verbs": ["get", "list", "watch", "create", "update", "patch"]},
     ],
     "creationTimestamp": INSTALL_TIME},
    {"name": "view", "labels": {}, "annotations": {},
     "aggregationRule": None,
     "rules": [{"apiGroups": [""], "resources": ["pods", "services"],
                "verbs": ["get", "list", "watch"]}],
     "creationTimestamp": INSTALL_TIME},
    {"name": "system:image-puller", "labels": {}, "annotations": {},
     "aggregationRule": None,
     "rules": [{"apiGroups": ["image.openshift.io"],
                "resources": ["imagestreams/layers"], "verbs": ["get"]}],
     "creationTimestamp": INSTALL_TIME},
    {"name": "system:image-builder", "labels": {}, "annotations": {},
     "aggregationRule": None,
     "rules": [{"apiGroups": ["image.openshift.io"],
                "resources": ["imagestreams/layers"], "verbs": ["get", "update"]}],
     "creationTimestamp": INSTALL_TIME},
    {"name": "system:openshift:scc:anyuid", "labels": {}, "annotations": {},
     "aggregationRule": None,
     "rules": [{"apiGroups": ["security.openshift.io"],
                "resources": ["securitycontextconstraints"],
                "resourceNames": ["anyuid"], "verbs": ["use"]}],
     "creationTimestamp": INSTALL_TIME},
    {"name": "system:openshift:scc:privileged", "labels": {}, "annotations": {},
     "aggregationRule": None,
     "rules": [{"apiGroups": ["security.openshift.io"],
                "resources": ["securitycontextconstraints"],
                "resourceNames": ["privileged"], "verbs": ["use"]}],
     "creationTimestamp": INSTALL_TIME},
]

ROLES = [
    {"name": "config-reader", "namespace": "mine-platform",
     "labels": {}, "annotations": {},
     "rules": [{"apiGroups": [""],
                "resources": ["configmaps", "secrets"],
                "verbs": ["get", "list", "watch"]}],
     "creationTimestamp": "2025-01-12T09:30:00Z"},
    {"name": "deployment-restarter", "namespace": "mine-platform",
     "labels": {}, "annotations": {},
     "rules": [{"apiGroups": ["apps"],
                "resources": ["deployments"], "verbs": ["get", "patch"]}],
     "creationTimestamp": "2025-01-12T09:31:00Z"},
    {"name": "job-reader", "namespace": "ci",
     "labels": {}, "annotations": {},
     "rules": [{"apiGroups": ["batch"],
                "resources": ["jobs", "cronjobs"], "verbs": ["get", "list", "watch"]}],
     "creationTimestamp": "2025-02-14T09:10:00Z"},
    {"name": "read-secrets", "namespace": "payments-prod",
     "labels": {}, "annotations": {},
     "rules": [{"apiGroups": [""],
                "resources": ["secrets"], "verbs": ["get", "list"]}],
     "creationTimestamp": "2025-03-10T09:05:00Z"},
]

CLUSTER_ROLE_BINDINGS = [
    {"name": "cluster-admin", "labels": {}, "annotations": {},
     "subjects": [{"kind": "Group", "name": "system:masters"}],
     "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
     "creationTimestamp": INSTALL_TIME},
    {"name": "platform-admins-cluster-admin", "labels": {}, "annotations": {},
     "subjects": [{"kind": "Group", "name": "platform-admins"}],
     "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
     "creationTimestamp": "2024-12-01T11:30:00Z"},
    {"name": "ghost-future-employee", "labels": {}, "annotations": {},
     "subjects": [{"kind": "User", "name": "future-hire@company.com"}],
     "roleRef": {"kind": "ClusterRole", "name": "admin"},
     "creationTimestamp": "2024-12-01T11:35:00Z"},
    {"name": "ghost-contractors-view", "labels": {}, "annotations": {},
     "subjects": [{"kind": "Group", "name": "contractors"}],
     "roleRef": {"kind": "ClusterRole", "name": "view"},
     "creationTimestamp": "2024-12-01T11:36:00Z"},
    {"name": "dana-cluster-view", "labels": {}, "annotations": {},
     "subjects": [{"kind": "User", "name": "dana"}],
     "roleRef": {"kind": "ClusterRole", "name": "view"},
     "creationTimestamp": "2025-01-12T09:45:00Z"},
    # Resurrectable SA #1 — cluster-admin to an SA whose namespace still
    # exists but whose SA object is gone. `oc create sa pipeline -n ci`
    # reactivates cluster-admin instantly.
    {"name": "ci-pipeline-clusteradmin", "labels": {}, "annotations": {},
     "subjects": [{"kind": "ServiceAccount", "name": "pipeline",
                    "namespace": "ci"}],
     "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
     "creationTimestamp": "2025-02-14T09:30:00Z"},
    # Resurrectable SA #2 — cluster-admin to an SA in a namespace that has
    # ALSO been deleted. `oc new-project legacy-pipelines` followed by
    # `oc create sa runner -n legacy-pipelines` re-opens cluster-admin.
    {"name": "legacy-pipelines-runner-admin", "labels": {}, "annotations": {},
     "subjects": [{"kind": "ServiceAccount", "name": "runner",
                    "namespace": "legacy-pipelines"}],
     "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
     "creationTimestamp": "2024-08-04T14:12:00Z"},
    # Resurrectable SA #3 — `admin` ClusterRole granted via the older User-
    # form principal (system:serviceaccount:<ns>:<sa>). Same lifecycle gap.
    {"name": "tooling-deployer-admin", "labels": {}, "annotations": {},
     "subjects": [{"kind": "User",
                    "name": "system:serviceaccount:tooling:deployer"}],
     "roleRef": {"kind": "ClusterRole", "name": "admin"},
     "creationTimestamp": "2025-01-09T08:15:00Z"},
    # Virtual Group subject — system:authenticated:oauth is synthesized by
    # the OpenShift apiserver; no Group object exists. Surfaces in /subjects
    # with the 'virtual' badge so it's discoverable instead of URL-only.
    {"name": "oauth-users-self-review", "labels": {}, "annotations": {},
     "subjects": [{"kind": "Group", "name": "system:authenticated:oauth"}],
     "roleRef": {"kind": "ClusterRole", "name": "view"},
     "creationTimestamp": "2025-02-01T09:00:00Z"},
]

ROLE_BINDINGS = [
    {"name": "alice-admin", "namespace": "nginx", "labels": {}, "annotations": {},
     "subjects": [{"kind": "User", "name": "alice"}],
     "roleRef": {"kind": "ClusterRole", "name": "admin"},
     "creationTimestamp": "2024-12-01T11:40:00Z"},
    {"name": "admin-rb", "namespace": "mine-platform", "labels": {}, "annotations": {},
     "subjects": [{"kind": "Group", "name": "engineers"}],
     "roleRef": {"kind": "ClusterRole", "name": "admin"},
     "creationTimestamp": "2025-01-12T09:35:00Z"},
    {"name": "admin-rb-copy", "namespace": "mine-platform", "labels": {}, "annotations": {},
     "subjects": [{"kind": "Group", "name": "engineers"}],
     "roleRef": {"kind": "ClusterRole", "name": "admin"},
     "creationTimestamp": "2025-01-12T09:36:00Z"},
    {"name": "secret-readers", "namespace": "payments-prod", "labels": {}, "annotations": {},
     "subjects": [{"kind": "Group", "name": "engineers"}],
     "roleRef": {"kind": "Role", "name": "read-secrets"},
     "creationTimestamp": "2025-03-10T09:10:00Z"},
    {"name": "dana-config-reader", "namespace": "mine-platform", "labels": {}, "annotations": {},
     "subjects": [{"kind": "User", "name": "dana"}],
     "roleRef": {"kind": "Role", "name": "config-reader"},
     "creationTimestamp": "2025-01-12T09:37:00Z"},
    {"name": "manual-approver-restarter", "namespace": "mine-platform", "labels": {}, "annotations": {},
     "subjects": [{"kind": "User", "name": "manual-approver"}],
     "roleRef": {"kind": "Role", "name": "deployment-restarter"},
     "creationTimestamp": "2025-02-01T10:05:00Z"},
    {"name": "mallory-view", "namespace": "mine-platform", "labels": {}, "annotations": {},
     "subjects": [{"kind": "User", "name": "mallory"}],
     "roleRef": {"kind": "ClusterRole", "name": "view"},
     "creationTimestamp": "2025-01-20T10:10:00Z"},
    {"name": "ci-builder-deploy-mine", "namespace": "mine-platform", "labels": {}, "annotations": {},
     "subjects": [{"kind": "ServiceAccount", "name": "builder", "namespace": "ci"}],
     "roleRef": {"kind": "ClusterRole", "name": "edit"},
     "creationTimestamp": "2025-02-14T10:00:00Z"},
    {"name": "mine-builder-use-anyuid", "namespace": "mine-platform", "labels": {}, "annotations": {},
     "subjects": [{"kind": "ServiceAccount", "name": "builder", "namespace": "mine-platform"}],
     "roleRef": {"kind": "ClusterRole", "name": "system:openshift:scc:anyuid"},
     "creationTimestamp": "2025-01-12T09:50:00Z"},
    {"name": "ci-builder-use-anyuid", "namespace": "ci", "labels": {}, "annotations": {},
     "subjects": [{"kind": "ServiceAccount", "name": "builder", "namespace": "ci"}],
     "roleRef": {"kind": "ClusterRole", "name": "system:openshift:scc:anyuid"},
     "creationTimestamp": "2025-02-14T10:05:00Z"},
    {"name": "mine-platform-pulls-shared", "namespace": "shared-images",
     "labels": {}, "annotations": {},
     "subjects": [{"kind": "ServiceAccount", "name": "default", "namespace": "mine-platform"}],
     "roleRef": {"kind": "ClusterRole", "name": "system:image-puller"},
     "creationTimestamp": "2025-01-15T13:10:00Z"},
    {"name": "ci-builder-pushes-shared", "namespace": "shared-images",
     "labels": {}, "annotations": {},
     "subjects": [{"kind": "ServiceAccount", "name": "builder", "namespace": "ci"}],
     "roleRef": {"kind": "ClusterRole", "name": "system:image-builder"},
     "creationTimestamp": "2025-02-14T10:15:00Z"},
    {"name": "default-image-puller", "namespace": "demo", "labels": {}, "annotations": {},
     "subjects": [{"kind": "Group", "name": "system:serviceaccounts:demo"}],
     "roleRef": {"kind": "ClusterRole", "name": "system:image-puller"},
     "creationTimestamp": "2024-12-01T11:55:00Z"},
]

OAUTH_CLUSTER = {
    "name": "cluster",
    "identityProviders": [
        {"name": "dev", "type": "HTPasswd", "mappingMethod": "claim",
         "htpasswd": {"fileData": {"name": "htpasswd-secret"}}},
    ],
}

HTPASSWD_USERS = [
    {"username": "alice", "idp_name": "dev",
     "secret_namespace": "openshift-config", "secret_name": "htpasswd-secret"},
    {"username": "bob", "idp_name": "dev",
     "secret_namespace": "openshift-config", "secret_name": "htpasswd-secret"},
    {"username": "eve", "idp_name": "dev",
     "secret_namespace": "openshift-config", "secret_name": "htpasswd-secret"},
    {"username": "dana", "idp_name": "dev",
     "secret_namespace": "openshift-config", "secret_name": "htpasswd-secret"},
    {"username": "kubeadmin", "idp_name": "dev",
     "secret_namespace": "openshift-config", "secret_name": "htpasswd-secret"},
    # tom is in htpasswd but no User object exists — latent user
    {"username": "tom-future-hire", "idp_name": "dev",
     "secret_namespace": "openshift-config", "secret_name": "htpasswd-secret"},
    # rhea has a User object but no Identity — combined with this htpasswd
    # entry the Subjects table shows 'No ID' + 'htpasswd-backed'.
    {"username": "rhea-rehire", "idp_name": "dev",
     "secret_namespace": "openshift-config", "secret_name": "htpasswd-secret"},
]

PODS = [
    {"name": "web-abc123", "namespace": "nginx",
     "annotations": {"openshift.io/scc": "restricted-v2"},
     "labels": {"app": "web"},
     "ownerReferences": [{"kind": "ReplicaSet", "name": "web-abc"}],
     "spec": {
         "serviceAccountName": "deployer",
         "containers": [
             {"name": "web", "image": "nginx:1.25"},
         ],
     },
     "phase": "Running",
     "containerStatuses": [
         {"name": "web", "image": "docker.io/library/nginx:1.25",
          "imageID": "docker.io/library/nginx@sha256:abc"},
     ],
     "creationTimestamp": "2024-12-01T12:00:00Z"},
    {"name": "app-def456", "namespace": "demo",
     "annotations": {"openshift.io/scc": "restricted-v2"},
     "labels": {"app": "app"},
     "ownerReferences": [],
     "spec": {
         "serviceAccountName": "default",
         "containers": [
             {"name": "app", "image": "registry.access.redhat.com/ubi9/ubi-minimal:latest"},
             {"name": "sidecar", "image": "image-registry.openshift-image-registry.svc:5000/demo/custom:v1"},
         ],
     },
     "phase": "Running",
     "containerStatuses": [
         {"name": "app", "image": "registry.access.redhat.com/ubi9/ubi-minimal:latest",
          "imageID": "registry.access.redhat.com/ubi9/ubi-minimal@sha256:def"},
         {"name": "sidecar", "image": "image-registry.openshift-image-registry.svc:5000/demo/custom:v1",
          "imageID": "image-registry.openshift-image-registry.svc:5000/demo/custom@sha256:ghi"},
     ],
     "creationTimestamp": "2024-12-01T12:05:00Z"},
    {"name": "api-5c77d", "namespace": "mine-platform",
     "annotations": {"openshift.io/scc": "anyuid"},
     "labels": {"app": "api"},
     "ownerReferences": [{"kind": "ReplicaSet", "name": "api-5c77d"}],
     "spec": {
         "serviceAccountName": "builder",
         "containers": [
             {"name": "api", "image": "image-registry.openshift-image-registry.svc:5000/mine-platform/api:latest"},
             {"name": "metrics", "image": "quay.io/prometheus/busybox:latest"},
         ],
     },
     "phase": "Running",
     "containerStatuses": [
         {"name": "api",
          "image": "image-registry.openshift-image-registry.svc:5000/mine-platform/api:latest",
          "imageID": "image-registry.openshift-image-registry.svc:5000/mine-platform/api@sha256:111111"},
         {"name": "metrics", "image": "quay.io/prometheus/busybox:latest",
          "imageID": "quay.io/prometheus/busybox@sha256:222222"},
     ],
     "creationTimestamp": "2025-01-12T10:00:00Z"},
    {"name": "database-maintenance", "namespace": "mine-platform",
     "annotations": {"openshift.io/scc": "anyuid"},
     "labels": {"job-name": "database-maintenance"},
     "ownerReferences": [{"kind": "Job", "name": "database-maintenance"}],
     "spec": {
         "serviceAccountName": "builder",
         "containers": [
             {"name": "maintenance", "image": "registry.redhat.io/ubi9/ubi-minimal:latest"},
         ],
     },
     "phase": "Succeeded",
     "containerStatuses": [
         {"name": "maintenance", "image": "registry.redhat.io/ubi9/ubi-minimal:latest",
          "imageID": "registry.redhat.io/ubi9/ubi-minimal@sha256:333333"},
     ],
     "creationTimestamp": "2025-01-12T10:10:00Z"},
    {"name": "privileged-debug", "namespace": "mine-platform",
     "annotations": {"openshift.io/scc": "privileged"},
     "labels": {"app": "debug"},
     "ownerReferences": [],
     "spec": {
         "serviceAccountName": "builder",
         "containers": [
             {"name": "debug", "image": "registry.redhat.io/rhel8/support-tools:latest"},
         ],
     },
     "phase": "Running",
     "containerStatuses": [
         {"name": "debug", "image": "registry.redhat.io/rhel8/support-tools:latest",
          "imageID": "registry.redhat.io/rhel8/support-tools@sha256:444444"},
     ],
     "creationTimestamp": "2025-01-12T10:20:00Z"},
    {"name": "build-run-1", "namespace": "ci",
     "annotations": {"openshift.io/scc": "anyuid"},
     "labels": {"job-name": "build-run-1"},
     "ownerReferences": [{"kind": "Job", "name": "build-run-1"}],
     "spec": {
         "serviceAccountName": "builder",
         "containers": [
             {"name": "build", "image": "quay.io/buildah/stable:v1.35"},
         ],
     },
     "phase": "Running",
     "containerStatuses": [
         {"name": "build", "image": "quay.io/buildah/stable:v1.35",
          "imageID": "quay.io/buildah/stable@sha256:555555"},
     ],
     "creationTimestamp": "2025-02-14T10:20:00Z"},
    # Baseline
    {"name": "oauth-server-xyz", "namespace": "openshift-authentication",
     "annotations": {"openshift.io/scc": "restricted-v2"},
     "labels": {}, "ownerReferences": [],
     "spec": {"serviceAccountName": "default",
              "containers": [{"name": "oauth", "image": "quay.io/openshift-release-dev/ocp-release@sha256:fake"}]},
     "phase": "Running",
     "containerStatuses": [{"name": "oauth", "image": "quay.io/openshift-release-dev/ocp-release@sha256:fake",
                            "imageID": "quay.io/openshift-release-dev/ocp-release@sha256:fake"}],
     "creationTimestamp": INSTALL_TIME},
    {"name": "drift-pod-1", "namespace": "alice-project",
     "annotations": {}, "labels": {}, "ownerReferences": [],
     "spec": {"containers": [{"name": "web", "image": "docker.io/library/nginx:1.25"}]},
     "phase": "Running",
     "containerStatuses": [{"name": "web", "image": "docker.io/library/nginx:1.25",
                            "imageID": "docker.io/library/nginx@sha256:aaaaaa"}],
     "creationTimestamp": "2026-05-07T00:00:00Z"},
    {"name": "drift-pod-2", "namespace": "alice-project",
     "annotations": {}, "labels": {}, "ownerReferences": [],
     "spec": {"containers": [{"name": "web", "image": "docker.io/library/nginx:1.25"}]},
     "phase": "Running",
     "containerStatuses": [{"name": "web", "image": "docker.io/library/nginx:1.25",
                            "imageID": "docker.io/library/nginx@sha256:bbbbbb"}],
     "creationTimestamp": "2026-05-07T00:00:00Z"},
    # `image-drift-demo` namespace shows the same `:latest` tag pulled
    # at two different digests across two running pods — the canonical
    # mutable-tag drift case.
    {"name": "shipping-api-old", "namespace": "image-drift-demo",
     "annotations": {"openshift.io/scc": "restricted-v2"},
     "labels": {"app": "shipping-api"}, "ownerReferences": [],
     "spec": {"serviceAccountName": "default",
              "containers": [{"name": "api",
                              "image": "quay.io/example/shipping-api:latest"}]},
     "phase": "Running",
     "containerStatuses": [{"name": "api",
                             "image": "quay.io/example/shipping-api:latest",
                             "imageID": "quay.io/example/shipping-api@sha256:cccccc"}],
     "creationTimestamp": "2026-03-10T09:05:00Z"},
    {"name": "shipping-api-new", "namespace": "image-drift-demo",
     "annotations": {"openshift.io/scc": "restricted-v2"},
     "labels": {"app": "shipping-api"}, "ownerReferences": [],
     "spec": {"serviceAccountName": "default",
              "containers": [{"name": "api",
                              "image": "quay.io/example/shipping-api:latest"}]},
     "phase": "Running",
     "containerStatuses": [{"name": "api",
                             "image": "quay.io/example/shipping-api:latest",
                             "imageID": "quay.io/example/shipping-api@sha256:dddddd"}],
     "creationTimestamp": "2026-03-12T11:30:00Z"},
]

IMAGESTREAMS = [
    {"name": "custom", "namespace": "demo", "labels": {}, "annotations": {},
     "creationTimestamp": "2024-12-01T11:55:00Z",
     "spec_tags": [{"name": "v1", "from": "docker.io/library/python:3.11"}],
     "status_tags": ["v1"],
     "dockerImageRepository": "image-registry.openshift-image-registry.svc:5000/demo/custom",
     "publicDockerImageRepository": ""},
    {"name": "api", "namespace": "mine-platform", "labels": {}, "annotations": {},
     "creationTimestamp": "2025-01-12T09:55:00Z",
     "spec_tags": [{"name": "latest", "from": "quay.io/example/api:latest"}],
     "status_tags": ["latest"],
     "dockerImageRepository": "image-registry.openshift-image-registry.svc:5000/mine-platform/api",
     "publicDockerImageRepository": ""},
    {"name": "base", "namespace": "shared-images", "labels": {}, "annotations": {},
     "creationTimestamp": "2025-01-15T13:05:00Z",
     "spec_tags": [{"name": "ubi", "from": "registry.redhat.io/ubi9/ubi-minimal:latest"}],
     "status_tags": ["ubi"],
     "dockerImageRepository": "image-registry.openshift-image-registry.svc:5000/shared-images/base",
     "publicDockerImageRepository": ""},
]

# A trimmed SCC set — enough to demonstrate resurrectable SA grants on
# both a privileged SCC and a benign one. Real OpenShift ships ~8 SCCs;
# Lineage shows whatever the cluster actually returns.
SCCS = [
    {"name": "privileged", "priority": 10,
     "allowPrivilegedContainer": True, "allowHostNetwork": True,
     "allowHostPID": True, "allowHostIPC": True,
     "allowPrivilegeEscalation": True,
     "runAsUser": {"type": "RunAsAny"},
     "creationTimestamp": INSTALL_TIME,
     # `forgotten-batch` namespace was deleted; this SA grant survived.
     # `system:admin` is the legitimate platform user.
     "users": ["system:admin",
                "system:serviceaccount:forgotten-batch:runner"],
     # `system:serviceaccounts:retired-pipeline-ns` is an implicit-group
     # grant: every SA in `retired-pipeline-ns` would get privileged.
     # The namespace is gone. The first `oc new-project
     # retired-pipeline-ns` puts every SA in it (including the
     # auto-created `default`) under this SCC.
     "groups": ["platform-admins",
                "system:serviceaccounts:retired-pipeline-ns"]},
    {"name": "anyuid", "priority": 10,
     "allowPrivilegedContainer": False, "allowHostNetwork": False,
     "allowHostPID": False, "allowHostIPC": False,
     "allowPrivilegeEscalation": True,
     "runAsUser": {"type": "RunAsAny"},
     "creationTimestamp": INSTALL_TIME,
     # `ci/pipeline` SA was deleted but anyuid still admits its name.
     "users": ["system:serviceaccount:ci:pipeline",
                "system:serviceaccount:mine-platform:builder"],
     "groups": ["qa-team", "system:serviceaccounts:mine-platform"]},
    {"name": "restricted-v2", "priority": None,
     "allowPrivilegedContainer": False, "allowHostNetwork": False,
     "allowHostPID": False, "allowHostIPC": False,
     "allowPrivilegeEscalation": False,
     "runAsUser": {"type": "MustRunAsRange"},
     "creationTimestamp": INSTALL_TIME,
     "users": [],
     "groups": ["system:authenticated"]},
]

JOBS = [
    {"name": "database-maintenance", "namespace": "mine-platform",
     "labels": {"app": "api"},
     "ownerReferences": [],
     "creationTimestamp": "2025-01-12T10:09:00Z",
     "spec": {
         "template": {
             "spec": {
                 "serviceAccountName": "builder",
                 "containers": [
                     {"name": "maintenance",
                      "image": "registry.redhat.io/ubi9/ubi-minimal:latest"}
                 ],
             }
         }
     }},
    {"name": "build-run-1", "namespace": "ci",
     "labels": {"app": "pipeline"},
     "ownerReferences": [{"kind": "CronJob", "name": "nightly-build"}],
     "creationTimestamp": "2025-02-14T10:19:00Z",
     "spec": {
         "template": {
             "spec": {
                 "serviceAccountName": "builder",
                 "containers": [
                     {"name": "build", "image": "quay.io/buildah/stable:v1.35"}
                 ],
             }
         }
     }},
]

CRONJOBS = [
    {"name": "nightly-database-check", "namespace": "mine-platform",
     "creationTimestamp": "2025-01-12T10:30:00Z",
     "schedule": "15 2 * * *",
     "spec": {
         "jobTemplate": {
             "spec": {
                 "template": {
                     "spec": {
                         "serviceAccountName": "builder",
                         "containers": [
                             {"name": "check",
                              "image": "registry.redhat.io/ubi9/ubi-minimal:latest"}
                         ],
                     }
                 }
             }
         }
     }},
    {"name": "nightly-build", "namespace": "ci",
     "creationTimestamp": "2025-02-14T10:10:00Z",
     "schedule": "0 1 * * *",
     "spec": {
         "jobTemplate": {
             "spec": {
                 "template": {
                     "spec": {
                         "serviceAccountName": "builder",
                         "containers": [
                             {"name": "build", "image": "quay.io/buildah/stable:v1.35"}
                         ],
                     }
                 }
             }
         }
     }},
]
