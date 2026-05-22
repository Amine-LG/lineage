"""Compatibility re-exports for page view models."""

from .pages import (
    home_context,
    identity_audit_context,
    subject_detail_context,
    who_can_context,
    aggregated_context,
    scc_detail_context,
    namespaces_context,
    namespace_detail_context,
    cross_namespace_context,
    images_context,
    image_detail_context,
    clusterroles_context,
    clusterrole_detail_context,
    roles_context,
    role_detail_context,
)

__all__ = [
    "home_context",
    "identity_audit_context",
    "subject_detail_context",
    "who_can_context",
    "aggregated_context",
    "scc_detail_context",
    "namespaces_context",
    "namespace_detail_context",
    "cross_namespace_context",
    "images_context",
    "image_detail_context",
    "clusterroles_context",
    "clusterrole_detail_context",
    "roles_context",
    "role_detail_context",
]
