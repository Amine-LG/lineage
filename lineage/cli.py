"""
Lineage CLI: machine-readable + human-readable audit report.

Usage:
  python -m lineage audit                # text report, exit 1 if real anomalies
  python -m lineage audit --json         # JSON for jq / CI
  python -m lineage audit --fail-on=any  # exit 1 on ANY finding
  python -m lineage audit --fail-on=none # never exit non-zero (info-only)
"""

import argparse
import json
import sys

from . import engine, data


def collect_findings(idx=None):
    if idx is None:
        idx = engine.index()
    audit = engine.identity_audit(idx, include_baseline_ghosts=False)
    privileged = engine.privileged_subjects(idx)
    duplicates = engine.duplicate_bindings(idx)

    user_priv = [p for p in privileged if not p.get("baseline")]
    user_dups = [d for d in duplicates if not d.get("baseline")]
    actionable_sas = audit["resurrectable_actionable"]
    actionable_implicit = audit["resurrectable_implicit_actionable"]
    real_anomalies = (
        bool(audit["latent_users"])
        or bool(audit["phantom_users"])
        or any(not g.get("routine") for g in audit["bound_ghosts"])
        or bool(audit["stranded_users"])
        or bool(audit["orphan_identities"])
        or bool(actionable_sas)
        or bool(actionable_implicit)
    )

    # Degraded-state flags surface in JSON so CI / jq pipelines can branch
    # on whether the htpasswd-source checks actually ran.
    htpasswd_configured = bool(idx.get("htpasswd_configured", False))
    htpasswd_available = bool(idx.get("htpasswd_available", True))
    htpasswd_degraded = htpasswd_configured and not htpasswd_available
    is_admin = bool(idx.get("is_admin", True))

    return {
        "cluster": data.live_status(),
        "htpasswd": {
            "configured": htpasswd_configured,
            "available": htpasswd_available,
            "degraded": htpasswd_degraded,
            "reason": idx.get("htpasswd_reason"),
        },
        "limited_view": not is_admin,
        "anomalies": {
            "latent_users": audit["latent_users"],
            "phantom_users": audit["phantom_users"],
            "bound_ghosts": [
                {"kind": g["subject"]["kind"],
                 "name": g["subject"]["name"],
                 "namespace": g["subject"].get("namespace"),
                 "grant_count": g.get("grant_count", 1),
                 "grants": [
                     {"kind": gr.get("kind"),
                      "name": gr.get("name"),
                      "namespace": gr.get("namespace"),
                      "role": gr.get("role"),
                      "role_kind": gr.get("role_kind"),
                      "scc_use": gr.get("scc_use", False)}
                     for gr in g.get("grants", [])
                 ],
                 "scc_use_any": bool(g.get("scc_use_grants")),
                 "routine": g.get("routine", False)}
                for g in audit["bound_ghosts"]
            ],
            "stranded_users": audit["stranded_users"],
            "orphan_identities": audit["orphan_identities"],
            "resurrectable_sas": [
                {"principal": r["principal"],
                 "namespace": r["namespace"],
                 "name": r["name"],
                 "namespace_present": r["namespace_present"],
                 "severity": r["severity"],
                 "grant_count": r["grant_count"],
                 "baseline": bool(r.get("baseline")),
                 "baseline_reason": r.get("baseline_reason")}
                for r in audit["resurrectable_sas"]
            ],
            "resurrectable_implicit_groups": [
                {"kind": r.get("kind"),
                 "group": r.get("group"),
                 "namespace": r.get("namespace"),
                 "namespace_present": r.get("namespace_present"),
                 "scc": r.get("scc"),
                 "scc_present": r.get("scc_present"),
                 "severity": r.get("severity"),
                 "source": r.get("source"),
                 "source_kind": r.get("source_kind"),
                 "subject_kind": r.get("subject_kind"),
                 "subject_name": r.get("subject_name"),
                 "subject_namespace": r.get("subject_namespace"),
                 "baseline": bool(r.get("baseline")),
                 "baseline_reason": r.get("baseline_reason")}
                for r in audit.get("resurrectable_implicit_groups", [])
            ],
        },
        "summary": {
            "privileged_user_subjects": len(user_priv),
            "privileged_baseline_subjects": len(privileged) - len(user_priv),
            "duplicate_user_bindings": len(user_dups),
            "resurrectable_sas_actionable": len(actionable_sas),
            "resurrectable_sas_baseline": len(audit["resurrectable_sas"]) - len(actionable_sas),
            "resurrectable_implicit_actionable": len(actionable_implicit),
            "resurrectable_implicit_baseline": (len(audit.get("resurrectable_implicit_groups") or []) - len(actionable_implicit)),
            "anomalies_total": audit["total"],
            "real_anomalies_present": real_anomalies,
        },
    }


def render_text(findings):
    lines = []
    cluster = findings["cluster"]
    if cluster.get("ok"):
        admin_tag = "" if cluster.get("is_admin") else " (limited view — non-admin)"
        lines.append(f"Lineage audit · {cluster.get('user', '?')} @ {cluster.get('server', '?')}{admin_tag}")
    else:
        lines.append(f"Lineage audit · NOT CONNECTED ({cluster.get('error')})")
        return "\n".join(lines)
    lines.append("")

    # Degraded-state warnings — print BEFORE the counts so a reader doesn't
    # interpret a zero count as a clean cluster when the check was skipped.
    htp = findings.get("htpasswd") or {}
    htp_degraded = bool(htp.get("degraded"))
    if findings.get("limited_view"):
        lines.append("[WARN]  Limited view (non-admin) — bound ghost, stranded, "
                     "phantom, and orphan-identity detection are disabled. "
                     "Counts below may be 0 because the check could not run, "
                     "not because the cluster is clean.")
    if htp_degraded:
        reason = htp.get("reason") or "Secret unreadable"
        lines.append(f"[WARN]  HTPasswd checks degraded — the openshift-config "
                     f"htpasswd Secret is unreadable ({reason}). Latent "
                     f"(htpasswd-source), removed-from-htpasswd phantom, and "
                     f"htpasswd-backed markers are unavailable; "
                     f"counts that look like 0 here may simply reflect the "
                     f"missing read.")
    if findings.get("limited_view") or htp_degraded:
        lines.append("")

    s = findings["summary"]
    a = findings["anomalies"]

    def status(label, count, fail_when_nonzero=True, skipped=False):
        if skipped:
            tag = "[SKIP]"
        else:
            tag = "[FAIL]" if (fail_when_nonzero and count > 0) else "[OK]"
        suffix = " (check unavailable)" if skipped else ""
        lines.append(f"{tag:7s} {count} {label}{suffix}")

    # Latent / phantom from htpasswd source need htpasswd readable.
    # Group-listed latent users are still computable; we don't have a
    # source-split here, so flag the line as SKIP only when htpasswd is the
    # sole IdP backing and the check is degraded.
    status("latent users (in IdP, no User object)", len(a["latent_users"]),
           skipped=htp_degraded)
    for u in a["latent_users"]:
        lines.append(f"  - {u['username']}  ({u.get('source', 'unknown')}: {u.get('detail', 'no detail')})")

    status("phantom users (User+Identity, missing IdP backing)",
           len(a["phantom_users"]),
           skipped=htp_degraded or findings.get("limited_view"))
    for u in a["phantom_users"]:
        reasons = "; ".join(u.get("reasons") or [])
        lines.append(f"  - {u['name']}  ({reasons or 'stale identity backing'})")

    # Split actionable vs baseline — baseline rows are platform noise
    # (openshift-*/kube-* namespaces) and cannot be exploited via
    # `oc new-project`. Show counts separately so CI gates don't trip
    # on platform residue.
    res_actionable = [r for r in a["resurrectable_sas"] if not r.get("baseline")]
    res_baseline = [r for r in a["resurrectable_sas"] if r.get("baseline")]
    status("resurrectable ServiceAccounts (actionable)", len(res_actionable))
    for r in res_actionable:
        ns_state = "namespace present" if r["namespace_present"] else "namespace deleted"
        lines.append(f"  - {r['principal']}  ({r['severity']}, {ns_state}, {r['grant_count']} grant(s))")
    if res_baseline:
        lines.append(f"[INFO]  {len(res_baseline)} baseline platform ServiceAccount(s) (openshift-*/kube-*) — not developer-actionable")

    implicit_groups = a.get("resurrectable_implicit_groups", [])
    impl_actionable = [r for r in implicit_groups if not r.get("baseline")]
    impl_baseline = [r for r in implicit_groups if r.get("baseline")]
    status("SCC resurrectable/future grants (actionable)", len(impl_actionable))
    for r in impl_actionable:
        kind = r.get("kind")
        if kind == "ghost-scc-target":
            subject = _format_scc_subject_ref(r)
            lines.append(
                f"  - future SCC/{r.get('scc')} for {subject} "
                f"({r.get('severity')}, SCC absent) via {r.get('source')}"
            )
        elif kind == "ghost-scc-subject":
            subject = _format_scc_subject_ref(r)
            lines.append(
                f"  - missing {subject} can use SCC/{r.get('scc')} "
                f"({r.get('severity')}) via {r.get('source')}"
            )
        else:
            ns_state = ("namespace present" if r.get("namespace_present")
                        else "namespace deleted")
            lines.append(
                f"  - {r.get('group')} via SCC/{r.get('scc')} "
                f"({r.get('severity')}, {ns_state}) from {r.get('source')}"
            )
    if impl_baseline:
        lines.append(f"[INFO]  {len(impl_baseline)} baseline platform SCC grant finding(s) — not developer-actionable")

    real_ghosts = [g for g in a["bound_ghosts"] if not g["routine"]]
    status("bound ghosts (real anomalies, distinct principals)",
           len(real_ghosts),
           skipped=findings.get("limited_view"))
    for g in real_ghosts:
        ns = f" in {g['namespace']}" if g.get("namespace") else ""
        nbind = g.get("grant_count", 1)
        scc_tag = " [SCC use]" if g.get("scc_use_any") else ""
        lines.append(f"  - {g['kind']}/{g['name']}{ns}  ({nbind} binding(s){scc_tag})")
        for gr in g.get("grants", []):
            in_ns = f" in {gr['namespace']}" if gr.get("namespace") else ""
            lines.append(f"     · {gr['kind']}/{gr['name']}{in_ns} → {gr.get('role_kind') or '?'}/{gr.get('role') or '?'}")

    routine = [g for g in a["bound_ghosts"] if g["routine"]]
    if routine:
        lines.append(f"[INFO]  {len(routine)} baseline ghosts hidden by default")

    status("stranded users (User object, no Identity)",
           len(a["stranded_users"]),
           skipped=findings.get("limited_view"))
    for u in a["stranded_users"]:
        lines.append(f"  - {u['name']}")

    status("orphan identities (Identity, no User)", len(a["orphan_identities"]),
           skipped=findings.get("limited_view"))
    for o in a["orphan_identities"]:
        lines.append(f"  - {o['identity']}  →  missing user {o['missing_user']}")

    lines.append("")
    lines.append(f"[INFO]  {s['privileged_user_subjects']} user-managed privileged bindings"
                 f"  ({s['privileged_baseline_subjects']} baseline)")
    if s["duplicate_user_bindings"]:
        lines.append(f"[INFO]  {s['duplicate_user_bindings']} duplicate user-managed bindings")

    lines.append("")
    if s["real_anomalies_present"]:
        lines.append("RESULT: real anomalies found.")
    else:
        lines.append("RESULT: no real anomalies.")
    return "\n".join(lines)


def _format_scc_subject_ref(row):
    kind = row.get("subject_kind") or "Subject"
    name = row.get("subject_name") or row.get("group") or "?"
    namespace = row.get("subject_namespace")
    if namespace:
        return f"{kind}/{namespace}/{name}"
    return f"{kind}/{name}"


def cmd_audit(args):
    findings = collect_findings()
    if args.json:
        print(json.dumps(findings, indent=2, default=str))
    else:
        print(render_text(findings))

    if args.fail_on == "none":
        return 0
    if args.fail_on == "any":
        return 1 if findings["summary"]["anomalies_total"] > 0 else 0
    return 1 if findings["summary"]["real_anomalies_present"] else 0


def main():
    parser = argparse.ArgumentParser(prog="lineage")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_audit = sub.add_parser("audit", help="Identity & permission audit report")
    p_audit.add_argument("--json", action="store_true", help="output JSON for CI / jq")
    p_audit.add_argument("--fail-on", choices=["any", "real", "none"], default="real",
                         help="exit-code behavior (default: real)")
    args = parser.parse_args()
    if args.cmd == "audit":
        sys.exit(cmd_audit(args))


if __name__ == "__main__":
    main()
