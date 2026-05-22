"""Identity audit view model."""

from ... import engine

def identity_audit_context(args):
    idx = engine.index()
    show_all = args.get("show_all") == "1"
    audit = engine.identity_audit(idx, include_baseline_ghosts=show_all)

    all_res = audit["resurrectable_sas"]
    all_implicit = audit.get("resurrectable_implicit_groups") or []
    actionable_res = [r for r in all_res if not r.get("baseline")]
    actionable_implicit = [r for r in all_implicit if not r.get("baseline")]
    baseline_res = [r for r in all_res if r.get("baseline")]
    baseline_implicit = [r for r in all_implicit if r.get("baseline")]

    def sev_count(level):
        return (sum(1 for r in actionable_res if r["severity"] == level)
                + sum(1 for r in actionable_implicit if r["severity"] == level))

    severity_counts = {
        "all": len(actionable_res) + len(actionable_implicit),
        "critical": sev_count("critical"),
        "high": sev_count("high"),
        "medium": sev_count("medium"),
        "low": sev_count("low"),
    }
    requested_severity = args.get("severity")
    default_severity = "critical"
    severity = (requested_severity or default_severity).strip().lower()
    if severity not in ("all", "critical", "high", "medium", "low"):
        severity = default_severity

    def by_severity(rows):
        if severity == "all":
            return rows
        return [r for r in rows if r["severity"] == severity]

    show_baseline = (severity == "all") or show_all
    baseline_res_visible = by_severity(baseline_res) if show_baseline else []
    baseline_implicit_visible = (by_severity(baseline_implicit)
                                 if show_baseline else [])

    return {
        "audit": audit,
        "show_all": show_all,
        "severity": severity,
        "severity_counts": severity_counts,
        "htpasswd_available": idx.get("htpasswd_available", True),
        "htpasswd_configured": idx.get("htpasswd_configured", False),
        "htpasswd_reason": idx.get("htpasswd_reason"),
        "resurrectable_filtered": by_severity(actionable_res),
        "resurrectable_implicit_filtered": by_severity(actionable_implicit),
        "resurrectable_baseline": baseline_res_visible,
        "resurrectable_implicit_baseline": baseline_implicit_visible,
        "resurrectable_baseline_total": len(baseline_res),
        "resurrectable_implicit_baseline_total": len(baseline_implicit),
        "show_baseline": show_baseline,
        "self_provisioner": engine.self_provisioner_posture(idx),
    }
