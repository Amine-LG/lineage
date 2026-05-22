"""Page-specific view-model builders."""

from .home import home_context
from .identity import identity_audit_context
from .subjects import subject_detail_context
from .permissions import (
    who_can_context,
    aggregated_context,
    cross_namespace_context,
    clusterroles_context,
    clusterrole_detail_context,
    roles_context,
    role_detail_context,
)
from .scc import scc_detail_context
from .namespaces import namespaces_context, namespace_detail_context
from .images import images_context, image_detail_context

__all__ = [
    "home_context",
    "identity_audit_context",
    "subject_detail_context",
    "who_can_context",
    "aggregated_context",
    "cross_namespace_context",
    "clusterroles_context",
    "clusterrole_detail_context",
    "roles_context",
    "role_detail_context",
    "scc_detail_context",
    "namespaces_context",
    "namespace_detail_context",
    "images_context",
    "image_detail_context",
]
