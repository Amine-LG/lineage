"""Module-level constants shared across the engine package.

Moved here to keep `__init__.py` focused on assembly and re-exports. No
behavior or values changed.
"""

PRIVILEGED_ROLES = ("cluster-admin", "admin", "system:masters")

# OpenShift auto-creates these ServiceAccount names in every project as
# soon as the project is created. A resurrectable finding naming one of
# these is strictly easier to revive than one naming a custom SA name —
# no `oc create sa` step needed, just `oc new-project <ns>`.
AUTO_CREATED_PROJECT_SAS = ("default", "builder", "deployer")
ROLE_TIERS = {
    "cluster-admin": 5, "system:masters": 5,
    "admin": 4, "edit": 3, "view": 1,
}
COMMON_VERBS = ["get", "list", "watch", "create", "update", "patch",
                "delete", "deletecollection", "*"]
PREFERRED_RESOURCE_API_GROUPS = {
    "pods": {""},
    "secrets": {""},
    "configmaps": {""},
    "services": {""},
    "serviceaccounts": {""},
    "namespaces": {""},
    "nodes": {""},
    "persistentvolumes": {""},
    "persistentvolumeclaims": {""},
    "deployments": {"apps"},
    "replicasets": {"apps"},
    "statefulsets": {"apps"},
    "daemonsets": {"apps"},
    "jobs": {"batch"},
    "cronjobs": {"batch"},
    "roles": {"rbac.authorization.k8s.io"},
    "rolebindings": {"rbac.authorization.k8s.io"},
    "clusterroles": {"rbac.authorization.k8s.io"},
    "clusterrolebindings": {"rbac.authorization.k8s.io"},
    "securitycontextconstraints": {"security.openshift.io"},
    "imagestreams": {"image.openshift.io"},
    "imagestreamtags": {"image.openshift.io"},
    "routes": {"route.openshift.io"},
    "builds": {"build.openshift.io"},
    "buildconfigs": {"build.openshift.io"},
    "deploymentconfigs": {"apps.openshift.io"},
    "users": {"user.openshift.io"},
    "groups": {"user.openshift.io"},
    "identities": {"user.openshift.io"},
    "projects": {"project.openshift.io"},
}
CLUSTER_SCOPED_RBAC_RESOURCES = {
    "apiservices",
    "clusterroles",
    "clusterrolebindings",
    "clusterversions",
    "customresourcedefinitions",
    "groups",
    "identities",
    "namespaces",
    "nodes",
    "oauths",
    "persistentvolumes",
    "projects",
    "storageclasses",
    "users",
    "volumeattachments",
}

# Severity ladder used for resurrectable SA identities. A name-based
# principal (system:serviceaccount:<ns>:<name>) inherits the highest
# privilege level of any grant that still references it.
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SA_PRINCIPAL_PREFIX = "system:serviceaccount:"
SCC_ROLE_PREFIX = "system:openshift:scc:"
