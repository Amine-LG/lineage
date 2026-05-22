"""Subject detail view model."""

from ... import engine

def subject_detail_context(kind, name, namespace):
    idx = engine.index()
    paths = engine.effective_permissions(kind, name, namespace, idx)
    reach = engine.namespace_reach_for_subject(kind, name, namespace, idx)
    is_system_group = engine.is_system_virtual_group
    reach_cluster_primary = [r for r in reach.get("cluster_wide", [])
                             if not is_system_group(r.get("via_group"))]
    reach_cluster_system = [r for r in reach.get("cluster_wide", [])
                            if is_system_group(r.get("via_group"))]
    reach_ns_primary = {}
    reach_ns_system = {}
    for ns_name, rows in (reach.get("by_namespace") or {}).items():
        primary = [r for r in rows if not is_system_group(r.get("via_group"))]
        system = [r for r in rows if is_system_group(r.get("via_group"))]
        if primary:
            reach_ns_primary[ns_name] = primary
        if system:
            reach_ns_system[ns_name] = system
    paths_primary = [p for p in paths
                     if not is_system_group(getattr(p, "via_group", None))]
    paths_system = [p for p in paths
                    if is_system_group(getattr(p, "via_group", None))]

    has_any_binding = bool(reach_cluster_primary) or bool(reach_ns_primary)
    is_latent_flag = (kind == "User" and name in engine.latent_usernames(idx))
    is_ghost_flag = (
        engine.is_ghost({"kind": kind, "name": name, "namespace": namespace}, idx)
        and (has_any_binding or not is_latent_flag)
    )

    identities = []
    idps_by_name = {}
    is_stranded_flag = False
    is_phantom_flag = False
    is_htpasswd_backed = False
    if kind == "User":
        identities = idx["identities_by_user"].get(name, [])
        idps_by_name = {idp.get("name"): idp
                        for idp in (idx["oauth_cluster"].get("identityProviders") or [])}
        markers = engine.subject_identity_markers(
            {"kind": "User", "name": name}, idx)
        is_stranded_flag = markers["stranded"]
        is_phantom_flag = markers["phantom"]
        is_htpasswd_backed = markers["htpasswd_backed"]

    groups = engine.groups_for_user(name, idx) if kind == "User" else []
    members = []
    is_virtual_group = False
    virtual_group_note = None
    if kind == "Group":
        group = idx["groups_by_name"].get(name)
        if group:
            members = group.get("users") or []
        elif name.startswith("system:"):
            is_virtual_group = True
            virtual_group_note = engine.describe_virtual_group(name, idx)

    sa_pods = []
    sa_scc_chain = []
    sa_jobs = []
    sa_cronjobs = []
    sa_bindings = None
    sa_images = []
    sa_surviving_grants = None
    if kind == "ServiceAccount" and namespace:
        sa_pods = engine.pods_for_sa(name, namespace, idx)
        sa_scc_chain = engine.scc_chain_for_sa(name, namespace, idx)
        sa_jobs = engine.jobs_for_sa(name, namespace, idx)
        sa_cronjobs = engine.cronjobs_for_sa(name, namespace, idx)
        sa_bindings = engine.bindings_referencing_sa(name, namespace, idx)
        sa_images = engine.images_for_sa(name, namespace, idx)
        if is_ghost_flag:
            sa_surviving_grants = engine.surviving_grants_for_absent_sa(
                name, namespace, idx)

    return {
        "subject": {"kind": kind, "name": name, "namespace": namespace},
        "is_ghost": is_ghost_flag,
        "is_latent": is_latent_flag,
        "is_stranded": is_stranded_flag,
        "is_phantom": is_phantom_flag,
        "is_htpasswd_backed": is_htpasswd_backed,
        "htpasswd_available": idx.get("htpasswd_available", True),
        "htpasswd_configured": idx.get("htpasswd_configured", False),
        "htpasswd_reason": idx.get("htpasswd_reason"),
        "paths": paths,
        "reach": reach,
        "paths_primary": paths_primary,
        "paths_system": paths_system,
        "reach_cluster_primary": reach_cluster_primary,
        "reach_cluster_system": reach_cluster_system,
        "reach_ns_primary": reach_ns_primary,
        "reach_ns_system": reach_ns_system,
        "identities": identities,
        "idps_by_name": idps_by_name,
        "groups": groups,
        "members": members,
        "is_virtual_group": is_virtual_group,
        "virtual_group_note": virtual_group_note,
        "sa_pods": sa_pods,
        "sa_scc_chain": sa_scc_chain,
        "sa_jobs": sa_jobs,
        "sa_cronjobs": sa_cronjobs,
        "sa_bindings": sa_bindings,
        "sa_images": sa_images,
        "sa_surviving_grants": sa_surviving_grants,
        "sccs_by_name": idx["sccs_by_name"],
        "privileged_roles": engine.PRIVILEGED_ROLES,
    }
