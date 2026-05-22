"""Shared constants for page view models."""

NAMESPACE_CATEGORIES = ("system", "openshift", "project", "unknown")

ACCESS_CATEGORY_LABEL = {
    "local_rbs": "Local RoleBinding",
    "cluster_rbs": "ClusterRoleBinding",
    "cross_ns_sas": "Cross-namespace SA",
    "groups": "Group",
    "unknown_ns_sas": "Unclassified-namespace SA",
    "system_baseline": "System / baseline",
}
