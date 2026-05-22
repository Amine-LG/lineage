"""Data source facade. Default: live `oc`. Mock: LINEAGE_MOCK=1."""

import os

USE_MOCK = os.environ.get("LINEAGE_MOCK") == "1"


if USE_MOCK:
    from . import mock_data as _m

    def users(): return list(_m.USERS)
    def identities(): return list(_m.IDENTITIES)
    def groups(): return list(_m.GROUPS)
    def namespaces(): return list(_m.NAMESPACES)
    def service_accounts(): return list(_m.SERVICE_ACCOUNTS)
    def cluster_roles(): return list(_m.CLUSTER_ROLES)
    def roles(): return list(_m.ROLES)
    def cluster_role_bindings(): return list(_m.CLUSTER_ROLE_BINDINGS)
    def role_bindings(): return list(_m.ROLE_BINDINGS)
    def oauth_cluster(): return dict(_m.OAUTH_CLUSTER)
    def pods(): return list(_m.PODS)
    def security_context_constraints(): return list(getattr(_m, "SCCS", []))
    def htpasswd_users():
        # Mock can override via HTPASSWD_STATUS (full dict) or HTPASSWD_USERS (list).
        status = getattr(_m, "HTPASSWD_STATUS", None)
        if status is not None:
            return dict(status)
        users = getattr(_m, "HTPASSWD_USERS", [])
        return {"configured": bool(users), "available": True,
                "users": list(users), "reason": None}
    def imagestreams(): return list(getattr(_m, "IMAGESTREAMS", []))
    def jobs(): return list(getattr(_m, "JOBS", []))
    def cronjobs(): return list(getattr(_m, "CRONJOBS", []))
    def live_status():
        # Mock viewer is `alice` so the mock dataset shows the Mine vs
        # Projects distinction clearly: alice-project (requester=alice)
        # lands in Mine; the `demo` namespace (requester=bob) appears
        # under Projects but not Mine.
        return {"ok": True, "server": "(mock)", "user": "alice",
                "version": "mock", "mock": True, "is_admin": True}
    def invalidate_cache(): pass
    def cache_age_seconds(): return 0
    def fetch_errors(): return []
    CACHE_TTL_SECONDS = 300

else:
    from . import cluster as _c

    users = _c.users
    identities = _c.identities
    groups = _c.groups
    namespaces = _c.namespaces
    service_accounts = _c.service_accounts
    cluster_roles = _c.cluster_roles
    roles = _c.roles
    cluster_role_bindings = _c.cluster_role_bindings
    role_bindings = _c.role_bindings
    oauth_cluster = _c.oauth_cluster
    pods = _c.pods
    security_context_constraints = _c.security_context_constraints
    htpasswd_users = _c.htpasswd_users
    imagestreams = _c.imagestreams
    jobs = _c.jobs
    cronjobs = _c.cronjobs
    live_status = _c.live_status
    invalidate_cache = _c.invalidate_cache
    cache_age_seconds = _c.cache_age_seconds
    fetch_errors = _c.fetch_errors
    CACHE_TTL_SECONDS = _c.CACHE_TTL_SECONDS
