"""Permission and RBAC page view models."""

from urllib.parse import urlencode

from ... import engine
from ..buckets import bucket_filter, bucket_counts

def who_can_context(args):
    verb = (args.get("verb") or "").strip()
    resource = (args.get("resource") or "").strip()
    name = (args.get("name") or "").strip() or None
    namespace = (args.get("namespace") or "").strip() or None
    bucket = args.get("bucket") or "yours"
    kind_filter = args.get("kind") or "all"
    path_filter = args.get("path") or "all"
    idx = engine.index()
    matches = []
    if verb and resource:
        matches = engine.who_can(verb, resource, namespace, idx, name=name)

    if bucket not in ("yours", "unknown", "baseline", "all"):
        bucket = "yours"
    if kind_filter not in ("all", "User", "Group", "ServiceAccount"):
        kind_filter = "all"
    if path_filter not in ("all", "direct", "expanded", "ghost"):
        path_filter = "all"

    bucket_count = bucket_counts(matches)
    bucket_rows = bucket_filter(matches, bucket)
    kind_counts = {"all": len(bucket_rows), "User": 0, "Group": 0,
                   "ServiceAccount": 0}
    for row in bucket_rows:
        kind = (row.get("subject") or {}).get("kind")
        if kind in kind_counts:
            kind_counts[kind] += 1
    kind_rows = [m for m in bucket_rows
                 if kind_filter == "all"
                 or (m.get("subject") or {}).get("kind") == kind_filter]
    path_counts = {
        "all": len(kind_rows),
        "direct": sum(1 for m in kind_rows if not m.get("via_group")),
        "expanded": sum(1 for m in kind_rows if m.get("via_group")),
        "ghost": sum(1 for m in kind_rows if m.get("ghost")),
    }
    if path_filter == "direct":
        visible_matches = [m for m in kind_rows if not m.get("via_group")]
    elif path_filter == "expanded":
        visible_matches = [m for m in kind_rows if m.get("via_group")]
    elif path_filter == "ghost":
        visible_matches = [m for m in kind_rows if m.get("ghost")]
    else:
        visible_matches = kind_rows

    def who_can_url(next_bucket=None, next_kind=None, next_path=None):
        params = {}
        if verb:
            params["verb"] = verb
        if resource:
            params["resource"] = resource
        if name:
            params["name"] = name
        if namespace:
            params["namespace"] = namespace
        params["bucket"] = next_bucket or bucket
        params["kind"] = next_kind or kind_filter
        params["path"] = next_path or path_filter
        return f"/who-can?{urlencode(params)}#who-can-results"

    return {
        "verb": verb,
        "resource": resource,
        "name": name or "",
        "namespace": namespace or "",
        "matches": matches,
        "visible_matches": visible_matches,
        "bucket": bucket,
        "kind_filter": kind_filter,
        "path_filter": path_filter,
        "bucket_counts": bucket_count,
        "kind_counts": kind_counts,
        "path_counts": path_counts,
        "who_can_url": who_can_url,
        "queried": bool(verb and resource),
        "verbs": engine.COMMON_VERBS,
        "resources": engine.all_resources_seen(idx),
        "namespaces": engine.all_namespaces(idx),
    }

def aggregated_context():
    idx = engine.index()
    rows = []

    def selector_parts(selectors):
        out = []
        for sel in selectors:
            labels = (sel or {}).get("matchLabels", {}) or {}
            exprs = (sel or {}).get("matchExpressions", []) or []
            parts = [f"{k}={v}" for k, v in sorted(labels.items())]
            for expr in exprs:
                key = expr.get("key") or "?"
                op = expr.get("operator") or "?"
                vals = expr.get("values") or []
                if op == "In":
                    parts.append(f"{key} in ({', '.join(vals)})")
                elif op == "NotIn":
                    parts.append(f"{key} not in ({', '.join(vals)})")
                elif op == "Exists":
                    parts.append(f"{key} exists")
                elif op == "DoesNotExist":
                    parts.append(f"{key} does not exist")
                else:
                    parts.append(f"{key} {op}")
            if parts:
                out.append(", ".join(parts))
        return out

    def selector_text(selectors):
        parts = selector_parts(selectors)
        return " · ".join(parts) if parts else "none"

    def component_rows(components, selectors):
        selector_keys = {
            k
            for sel in selectors
            for k in ((sel or {}).get("matchLabels", {}) or {})
        }
        selector_keys.update(
            expr.get("key")
            for sel in selectors
            for expr in ((sel or {}).get("matchExpressions", []) or [])
            if expr.get("key")
        )
        rows = []
        for component in components:
            labels = component.get("labels") or {}
            matched = [
                f"{k}={labels[k]}" if k in labels else f"{k}=<absent>"
                for k in sorted(selector_keys)
            ]
            rows.append({
                "name": component["name"],
                "creation_ts": component.get("creationTimestamp") or "",
                "rule_count": len(component.get("rules") or []),
                "matched_labels": ", ".join(matched) if matched else "—",
            })
        rows.sort(key=lambda r: r["name"])
        rows.sort(key=lambda r: r["creation_ts"], reverse=True)
        return rows

    for cr in idx["cluster_roles_by_name"].values():
        if not cr.get("aggregationRule"):
            continue
        rules, components = engine.expand_aggregated_role(cr, idx)
        selectors = cr["aggregationRule"].get("clusterRoleSelectors") or []
        rows.append({"name": cr["name"],
                     "creation_ts": cr.get("creationTimestamp") or "",
                     "selectors": selectors,
                     "selector_text": selector_text(selectors),
                     "selector_parts": selector_parts(selectors),
                     "rules": rules,
                     "components": component_rows(components, selectors),
                     "summary": engine.summarize_rules(rules)})
    rows.sort(key=lambda r: r["name"])
    rows.sort(key=lambda r: r["creation_ts"], reverse=True)
    return {"rows": rows}

def cross_namespace_context(args):
    idx = engine.index()
    bindings = engine.cross_namespace_bindings(idx)
    pullers = engine.image_puller_grants(idx)
    bind_counts = bucket_counts(bindings)
    pull_counts = bucket_counts(pullers)
    bucket = args.get("bucket", "yours")
    return {
        "bindings": bucket_filter(bindings, bucket),
        "pullers": bucket_filter(pullers, bucket),
        "bucket": bucket,
        "bind_counts": bind_counts,
        "pull_counts": pull_counts,
        "limited": not idx.get("is_admin", True),
    }

def clusterroles_context(args):
    idx = engine.index()
    rows = []
    for cr in idx["cluster_roles_by_name"].values():
        rules, components = engine.expand_aggregated_role(cr, idx)
        bound = engine.bindings_for_role("ClusterRole", cr["name"], None, idx)
        bound_by = [{"kind": b["kind"], "name": b["name"],
                     "namespace": b.get("namespace"),
                     "subject_count": len(b.get("subjects") or [])}
                    for b in bound]
        rows.append({
            "name": cr["name"],
            "aggregated": bool(cr.get("aggregationRule")),
            "component_count": len(components),
            "rule_count": len(rules),
            "summary": engine.summarize_rules(rules),
            "bound_by": bound_by,
            "binding_count": len(bound_by),
            "is_privileged": cr["name"] in engine.PRIVILEGED_ROLES,
            "creation_ts": cr.get("creationTimestamp"),
        })
    q = (args.get("q") or "").strip().lower()
    if q:
        rows = [r for r in rows if q in r["name"].lower()]
    only_bound = args.get("bound") == "1"
    if only_bound:
        rows = [r for r in rows if r["binding_count"] > 0]
    rows.sort(key=lambda r: (not r["is_privileged"], -r["binding_count"],
                              r["name"]))
    rows.sort(key=lambda r: r.get("creation_ts") or "", reverse=True)
    error_kinds = idx.get("fetch_error_kinds") or set()
    crs_visible = (len(rows) > 0) or "clusterroles" not in error_kinds
    has_crb = any(b.get("kind") == "ClusterRoleBinding"
                  for b in idx.get("all_bindings") or [])
    crbs_visible = has_crb or "crb" not in error_kinds
    return {"rows": rows, "q": q, "only_bound": only_bound,
            "crs_visible": crs_visible, "crbs_visible": crbs_visible}

def clusterrole_detail_context(name):
    idx = engine.index()
    role = idx["cluster_roles_by_name"].get(name)
    if role is None:
        return None
    rules, components = engine.expand_aggregated_role(role, idx)
    bound_by = engine.bindings_for_role("ClusterRole", name, None, idx)
    ns_counts = {}
    cluster_wide_count = 0
    for binding in bound_by:
        if binding.get("kind") == "ClusterRoleBinding":
            cluster_wide_count += 1
        else:
            ns = binding.get("namespace") or ""
            ns_counts[ns] = ns_counts.get(ns, 0) + 1
    namespaces_reached = sorted(
        [{"namespace": ns, "binding_count": count}
         for ns, count in ns_counts.items()],
        key=lambda x: (-x["binding_count"], x["namespace"]))
    return {
        "role": role,
        "rules": rules,
        "components": components,
        "bound_by": bound_by,
        "summary": engine.summarize_rules(rules),
        "namespaces_reached": namespaces_reached,
        "cluster_wide_count": cluster_wide_count,
        "aggregation_parents": engine.aggregation_parents_for_role(role, idx),
        "scc_use": engine.scc_use_interpretation(rules, idx),
        "privileged_roles": engine.PRIVILEGED_ROLES,
    }

def roles_context(args):
    idx = engine.index()
    rows = []
    for (ns, name), role in idx["roles_by_key"].items():
        bound = engine.bindings_for_role("Role", name, ns, idx)
        baseline_ns = engine.is_baseline_namespace(ns, idx)
        unknown_ns = (not baseline_ns) and engine.is_unknown_namespace(ns, idx)
        rows.append({
            "name": name,
            "namespace": ns,
            "rule_count": len(role.get("rules") or []),
            "summary": engine.summarize_rules(role.get("rules") or []),
            "binding_count": len(bound),
            "baseline_ns": baseline_ns,
            "unknown_ns": unknown_ns,
            "baseline": baseline_ns,
            "unknown": unknown_ns,
            "creation_ts": role.get("creationTimestamp"),
        })
    default_bucket = "yours" if idx.get("is_admin", True) else "all"
    bucket = args.get("bucket", default_bucket)
    total = len(rows)
    counts = bucket_counts(rows)
    rows = bucket_filter(rows, bucket)
    q = (args.get("q") or "").strip().lower()
    if q:
        rows = [r for r in rows
                if q in r["name"].lower() or q in r["namespace"].lower()]
    rows.sort(key=lambda r: (r["baseline_ns"], r["unknown_ns"],
                              -r["binding_count"], r["namespace"], r["name"]))
    rows.sort(key=lambda r: r.get("creation_ts") or "", reverse=True)
    error_kinds = idx.get("fetch_error_kinds") or set()
    has_rb = any(b.get("kind") == "RoleBinding"
                 for b in idx.get("all_bindings") or [])
    return {"rows": rows, "q": q, "bucket": bucket,
            "total": total, "counts": counts,
            "rbs_visible": has_rb or "rb" not in error_kinds,
            "is_admin": idx.get("is_admin", True)}

def role_detail_context(namespace, name):
    idx = engine.index()
    role = idx["roles_by_key"].get((namespace, name))
    if role is None:
        return None
    return {
        "role": role,
        "namespace": namespace,
        "name": name,
        "rules": role.get("rules") or [],
        "summary": engine.summarize_rules(role.get("rules") or []),
        "bound_by": engine.bindings_for_role("Role", name, namespace, idx),
    }
