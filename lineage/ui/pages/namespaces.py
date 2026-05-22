"""Namespace page view models."""

from ... import engine
from .common import NAMESPACE_CATEGORIES, ACCESS_CATEGORY_LABEL

def namespaces_context(args):
    idx = engine.index()
    current_user = idx.get("current_user")
    rows = [engine.namespace_summary(ns, idx) for ns in engine.all_namespaces(idx)]
    deleted_namespaces = engine.deleted_namespaces_with_grants(idx)
    total = len(rows)
    counts = {c: sum(1 for r in rows if r.get("category") == c)
              for c in NAMESPACE_CATEGORIES}
    counts["all"] = total
    counts["mine"] = sum(1 for r in rows
                         if engine.is_mine_namespace(r, current_user))
    counts["baseline"] = sum(1 for r in rows if r.get("baseline"))
    category = (args.get("category") or "").strip()
    bucket = (args.get("bucket") or "").strip()
    if not category and bucket:
        category = {"yours": "mine", "baseline": "baseline",
                    "all": "all"}.get(bucket, bucket)
    if not category:
        category = "project"

    if category == "all":
        filtered = rows
    elif category == "mine":
        filtered = [r for r in rows
                    if engine.is_mine_namespace(r, current_user)]
    elif category == "baseline":
        filtered = [r for r in rows if r.get("baseline")]
    else:
        filtered = [r for r in rows if r.get("category") == category]

    q = (args.get("q") or "").strip().lower()
    if q:
        filtered = [r for r in filtered if q in r["namespace"].lower()]
    filtered.sort(key=lambda r: (-r["highest_tier"], r["namespace"]))
    filtered.sort(key=lambda r: r.get("creation_ts") or "", reverse=True)
    return {"rows": filtered, "q": q, "category": category,
            "counts": counts, "current_user": current_user,
            "deleted_namespaces": deleted_namespaces}

def namespace_detail_context(ns, args):
    idx = engine.index()
    summary = engine.namespace_summary(ns, idx)
    access_cats = engine.subjects_with_access_in_categorized(ns, idx)
    access_rows_all = []
    for cat_key, rows in access_cats.items():
        for row in rows:
            row = dict(row)
            row["category_label"] = ACCESS_CATEGORY_LABEL.get(cat_key, cat_key)
            access_rows_all.append(row)
    access_rows_all.sort(key=lambda r: (-r.get("score", 0),
                                          r["subject"].get("kind") or "",
                                          r["subject"].get("namespace") or "",
                                          r["subject"].get("name") or ""))
    access_counts = {
        "yours": sum(1 for r in access_rows_all
                       if not r.get("baseline") and not r.get("unknown")),
        "unknown": sum(1 for r in access_rows_all if r.get("unknown")),
        "baseline": sum(1 for r in access_rows_all if r.get("baseline")),
        "all": len(access_rows_all),
    }
    access_kind_counts = {
        "all": len(access_rows_all),
        "User": sum(1 for r in access_rows_all
                       if r["subject"].get("kind") == "User"),
        "Group": sum(1 for r in access_rows_all
                       if r["subject"].get("kind") == "Group"),
        "ServiceAccount": sum(1 for r in access_rows_all
                               if r["subject"].get("kind") == "ServiceAccount"),
    }
    access_bucket = (args.get("access_bucket") or "all").lower()
    if access_bucket not in ("yours", "unknown", "baseline", "all"):
        access_bucket = "all"
    access_kind = args.get("access_kind") or "User"
    if access_kind not in ("all", "User", "Group", "ServiceAccount"):
        access_kind = "User"
    access_rows = access_rows_all
    if access_bucket == "yours":
        access_rows = [r for r in access_rows
                       if not r.get("baseline") and not r.get("unknown")]
    elif access_bucket == "unknown":
        access_rows = [r for r in access_rows if r.get("unknown")]
    elif access_bucket == "baseline":
        access_rows = [r for r in access_rows if r.get("baseline")]
    if access_kind != "all":
        access_rows = [r for r in access_rows
                       if r["subject"].get("kind") == access_kind]

    bucket = args.get("bucket", "yours")
    sas = sorted(
        [sa for sa in idx["sas_by_key"].values() if sa["namespace"] == ns],
        key=lambda x: (x.get("creationTimestamp") or "", x.get("name") or ""),
        reverse=True,
    )
    pods_in = sorted(
        [p for p in (idx.get("pods") or []) if p.get("namespace") == ns],
        key=lambda p: (p.get("creationTimestamp") or "", p.get("name") or ""),
        reverse=True,
    )
    rbs = sorted(
        [b for b in idx["all_bindings"]
         if b["kind"] == "RoleBinding" and b.get("namespace") == ns],
        key=lambda b: (b.get("creationTimestamp") or "", b.get("name") or ""),
        reverse=True,
    )
    scc_counts = {}
    for pod in pods_in:
        scc = (pod.get("annotations") or {}).get("openshift.io/scc")
        if scc:
            scc_counts[scc] = scc_counts.get(scc, 0) + 1
    scc_summary = sorted(
        [{"name": name, "pod_count": count,
          "privileged": bool((idx["sccs_by_name"].get(name) or {})
                              .get("allowPrivilegedContainer"))}
         for name, count in scc_counts.items()],
        key=lambda x: (-x["pod_count"], x["name"]))
    streams_here = sorted(
        [s for s in (idx.get("imagestreams") or [])
         if s.get("namespace") == ns],
        key=lambda s: (s.get("creationTimestamp") or "", s.get("name") or ""),
        reverse=True,
    )
    return {
        "ns": ns,
        "summary": summary,
        "access_rows": access_rows,
        "access_total": len(access_rows_all),
        "access_counts": access_counts,
        "access_kind_counts": access_kind_counts,
        "access_bucket": access_bucket,
        "access_kind": access_kind,
        "sas": sas,
        "pods": pods_in,
        "rbs": rbs,
        "scc_counts": scc_counts,
        "scc_summary": scc_summary,
        "bucket": bucket,
        "resurrectable": [r for r in engine.resurrectable_sa_identities(idx)
                          if r["namespace"] == ns],
        "namespace_present": ns in idx["namespaces_by_name"],
        "cross_ns": engine.cross_ns_bindings_for_namespace(ns, idx),
        "images_here": engine.images_running_in_namespace(ns, idx),
        "streams_here": streams_here,
    }
