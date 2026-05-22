"""Home dashboard view model."""

from ... import engine, data
from ..buckets import (
    bucket_filter,
    review_rows,
    bucket_for_card,
    namespace_category_for_card,
)

def home_context():
    idx = engine.index()
    subjects = engine.all_subjects(idx)
    privileged = engine.privileged_subjects(idx)
    grants = engine.role_grants(idx)
    duplicates = engine.duplicate_bindings(idx)
    audit = engine.identity_audit(idx)
    inventory = engine.image_inventory(idx)
    registries = engine.registry_summary(inventory)
    drift = engine.image_drift(idx)
    streams = engine.imagestream_usage(idx)

    namespaces = engine.all_namespaces(idx)
    user_namespaces = [ns for ns in namespaces
                       if not engine.is_baseline_namespace(ns, idx)]

    user_subjects = review_rows(subjects)
    strict_user_subjects = bucket_filter(subjects, "yours")
    unknown_subjects = bucket_filter(subjects, "unknown")
    real_group_subjects = [
        s for s in subjects
        if s["kind"] == "Group" and not s.get("virtual")
    ]
    user_real_group_subjects = bucket_filter(real_group_subjects, "yours")
    virtual_group_subjects = [
        s for s in subjects
        if s["kind"] == "Group" and s.get("virtual")
    ]
    user_virtual_group_subjects = bucket_filter(virtual_group_subjects, "yours")
    strict_user_priv = bucket_filter(privileged, "yours")
    unknown_priv = bucket_filter(privileged, "unknown")
    user_priv = review_rows(privileged)
    user_images = [i for i in inventory
                   if i.get("user_used") or i.get("unknown_used")]
    user_registries = [r for r in registries
                       if r.get("user_used") or r.get("unknown_used")]
    user_drift = [d for d in drift
                  if d.get("user_used") or d.get("unknown_used")]
    user_streams = [s for s in streams if not s.get("baseline")]
    pods = idx.get("pods") or []
    user_pods = [p for p in pods if not engine.is_baseline_pod(p, idx)]
    namespace_summaries = [engine.namespace_summary(ns, idx)
                           for ns in namespaces]
    project_namespace_count = sum(
        1 for ns in namespace_summaries if ns.get("category") == "project")
    unknown_namespace_count = sum(
        1 for ns in namespace_summaries if ns.get("category") == "unknown")
    project_pod_count = sum(
        1 for p in pods
        if engine.classify_namespace(p.get("namespace"), idx).get("category")
        == "project")
    unknown_pod_count = sum(
        1 for p in pods
        if engine.classify_namespace(p.get("namespace"), idx).get("category")
        == "unknown")
    strict_image_count = sum(1 for i in inventory if i.get("user_used"))
    unknown_image_count = sum(1 for i in inventory if i.get("unknown_used"))
    strict_registry_count = sum(1 for r in registries if r.get("user_used"))
    unknown_registry_count = sum(1 for r in registries if r.get("unknown_used"))
    strict_drift_count = sum(1 for d in drift if d.get("user_used"))
    unknown_drift_count = sum(1 for d in drift if d.get("unknown_used"))
    strict_stream_count = sum(1 for s in streams
                              if not s.get("baseline")
                              and not s.get("unknown"))
    unknown_stream_count = sum(1 for s in streams if s.get("unknown"))
    sccs = list(idx["sccs_by_name"].values())
    user_sccs = [s for s in sccs if not engine.is_baseline_scc(s, idx)]
    aggregated_roles = [
        cr for cr in idx["cluster_roles_by_name"].values()
        if cr.get("aggregationRule")
    ]
    user_aggregated_roles = [
        cr for cr in aggregated_roles
        if not engine.is_baseline_cluster_role(cr, idx)
    ]

    actionable_sas = audit["resurrectable_actionable"]
    actionable_implicit = audit["resurrectable_implicit_actionable"]
    resurrectable_priv = [r for r in actionable_sas
                          if r["severity"] in ("critical", "high")]
    resurrectable_severity_counts = {
        level: sum(1 for r in actionable_sas if r["severity"] == level)
        for level in ("critical", "high", "medium", "low")
    }
    implicit_severity_counts = {
        level: sum(1 for r in actionable_implicit if r["severity"] == level)
        for level in ("critical", "high", "medium", "low")
    }
    combined_critical = (resurrectable_severity_counts["critical"]
                         + implicit_severity_counts["critical"])
    combined_high = (resurrectable_severity_counts["high"]
                     + implicit_severity_counts["high"])
    combined_medium = (resurrectable_severity_counts["medium"]
                       + implicit_severity_counts["medium"])
    combined_low = (resurrectable_severity_counts["low"]
                    + implicit_severity_counts["low"])
    resurrectable_actionable_count = len(actionable_sas)
    resurrectable_implicit_actionable_count = len(actionable_implicit)
    resurrectable_baseline_count = (len(audit["resurrectable_baseline"])
                                    + len(audit["resurrectable_implicit_baseline"]))
    identity_anomaly_count = audit["identity_total"]

    return {
        "anomaly_count": identity_anomaly_count,
        "htpasswd_available": idx.get("htpasswd_available", True),
        "htpasswd_configured": idx.get("htpasswd_configured", False),
        "htpasswd_reason": idx.get("htpasswd_reason"),
        "ghosts_hidden_count": audit["hidden_ghost_count"],
        "resurrectable_count": resurrectable_actionable_count,
        "resurrectable_implicit_count": resurrectable_implicit_actionable_count,
        "resurrectable_baseline_count": resurrectable_baseline_count,
        "resurrectable_critical_count": combined_critical,
        "resurrectable_high_count": combined_high,
        "resurrectable_medium_count": combined_medium,
        "resurrectable_low_count": combined_low,
        "resurrectable_priv": resurrectable_priv,
        "users_yours": sum(1 for s in user_subjects if s["kind"] == "User"),
        "users_total": sum(1 for s in subjects if s["kind"] == "User"),
        "groups_yours": len(user_real_group_subjects),
        "groups_total": len(real_group_subjects),
        "virtual_groups_yours": len(user_virtual_group_subjects),
        "virtual_groups_total": len(virtual_group_subjects),
        "privileged_yours": len(user_priv),
        "privileged_card_bucket": bucket_for_card(len(strict_user_priv),
                                                  len(unknown_priv)),
        "privileged_total": len(privileged),
        "grants_yours_total": len(grants),
        "duplicates_count": len([d for d in duplicates if not d.get("baseline")]),
        "cluster_roles_count": len(idx["cluster_roles_by_name"]),
        "aggregated_count": len(user_aggregated_roles),
        "aggregated_total": len(aggregated_roles),
        "sas_yours": sum(1 for s in user_subjects
                          if s["kind"] == "ServiceAccount"),
        "sas_card_bucket": bucket_for_card(
            sum(1 for s in strict_user_subjects
                if s["kind"] == "ServiceAccount"),
            sum(1 for s in unknown_subjects
                if s["kind"] == "ServiceAccount")),
        "sas_total": sum(1 for s in subjects if s["kind"] == "ServiceAccount"),
        "namespaces_yours": len(user_namespaces),
        "namespaces_card_category": namespace_category_for_card(
            project_namespace_count, unknown_namespace_count),
        "namespaces_total": len(namespaces),
        "pods_count": len(user_pods),
        "pods_card_category": namespace_category_for_card(
            project_pod_count, unknown_pod_count),
        "pods_total": len(pods),
        "scc_count": len(user_sccs),
        "scc_total": len(sccs),
        "images_yours_count": len(user_images),
        "images_total": len(inventory),
        "registries_yours_count": len(user_registries),
        "images_card_bucket": bucket_for_card(strict_image_count,
                                              unknown_image_count),
        "registries_card_bucket": bucket_for_card(strict_registry_count,
                                                  unknown_registry_count),
        "drift_card_bucket": bucket_for_card(strict_drift_count,
                                             unknown_drift_count),
        "imagestreams_card_bucket": bucket_for_card(strict_stream_count,
                                                    unknown_stream_count),
        "registries_total": len(registries),
        "imagestreams_yours_count": len(user_streams),
        "imagestreams_total": len(streams),
        "idps": data.oauth_cluster().get("identityProviders", []),
        "privileged_preview": [p for p in privileged
                                if not p.get("baseline")][:8],
        "privileged_baseline_count": len([p for p in privileged
                                          if p.get("baseline")]),
        "recent_grants": grants[:15],
        "duplicates_preview": [d for d in duplicates
                                if not d.get("baseline")][:5],
        "audit": audit,
        "drift_yours_count": len(user_drift),
    }
