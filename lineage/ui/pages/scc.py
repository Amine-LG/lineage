"""SCC page view models."""

from ... import engine
from ... import classifier as cf
from ..buckets import bucket_filter, bucket_counts

def scc_detail_context(name, args):
    idx = engine.index()
    scc = idx["sccs_by_name"].get(name)
    if scc is None:
        return None
    admitted = engine.pods_admitted_by_scc(name, idx)
    admitted.sort(key=lambda p: (p.get("namespace", ""), p.get("name", "")))
    admitted.sort(key=lambda p: p.get("creationTimestamp") or "", reverse=True)
    absent_sa_grants = engine.absent_sa_grants_for_scc(name, idx)
    potential_subjects_all = engine.scc_potential_subjects(name, idx)
    potential_counts = bucket_counts(potential_subjects_all)
    potential_kind_counts = {
        "all": len(potential_subjects_all),
        "User": sum(1 for r in potential_subjects_all if r.get("kind") == "User"),
        "Group": sum(1 for r in potential_subjects_all if r.get("kind") == "Group"),
        "ServiceAccount": sum(1 for r in potential_subjects_all
                               if r.get("kind") == "ServiceAccount"),
    }
    potential_bucket = (args.get("subject_bucket") or "all").lower()
    if potential_bucket not in ("yours", "unknown", "baseline", "all"):
        potential_bucket = "all"
    potential_kind = args.get("subject_kind") or "User"
    if potential_kind not in ("all", "User", "Group", "ServiceAccount"):
        potential_kind = "User"
    potential_subjects = bucket_filter(potential_subjects_all, potential_bucket)
    if potential_kind != "all":
        potential_subjects = [r for r in potential_subjects
                              if r.get("kind") == potential_kind]

    ns_counts = {}
    for pod in admitted:
        ns = pod.get("namespace") or ""
        ns_counts[ns] = ns_counts.get(ns, 0) + 1
    admitted_ns_summary = [{"namespace": ns, "pod_count": count}
                            for ns, count in ns_counts.items()]
    admitted_ns_summary.sort(key=lambda x: (-x["pod_count"], x["namespace"]))

    img_counts = {}
    for pod in admitted:
        seen = set()
        for container in ((pod.get("spec") or {}).get("containers") or []):
            ref = container.get("image") or ""
            if not ref or ref in seen:
                continue
            seen.add(ref)
            img_counts[ref] = img_counts.get(ref, 0) + 1
    admitted_images = [{"image": ref,
                        "registry": cf.registry_for(ref),
                        "pod_count": count}
                        for ref, count in img_counts.items()]
    admitted_images.sort(key=lambda x: (-x["pod_count"], x["image"]))

    sa_prefix = "system:serviceaccount:"
    user_links = []
    for user in (scc.get("users") or []):
        if user.startswith(sa_prefix):
            rest = user[len(sa_prefix):]
            if ":" in rest:
                ns, sname = rest.split(":", 1)
                user_links.append({"raw": user, "kind": "ServiceAccount",
                                   "name": sname, "namespace": ns,
                                   "linkable": True})
                continue
        if user.startswith("system:"):
            user_links.append({"raw": user, "kind": "system",
                               "name": user, "namespace": None,
                               "linkable": False})
        else:
            user_links.append({"raw": user, "kind": "User",
                               "name": user, "namespace": None,
                               "linkable": True})
    group_links = [{"raw": group, "kind": "Group", "name": group,
                    "linkable": not group.startswith("system:")}
                   for group in (scc.get("groups") or [])]

    return {
        "scc": scc,
        "admitted": admitted,
        "absent_sa_grants": absent_sa_grants,
        "potential_subjects": potential_subjects,
        "potential_subjects_total": len(potential_subjects_all),
        "potential_counts": potential_counts,
        "potential_kind_counts": potential_kind_counts,
        "potential_bucket": potential_bucket,
        "potential_kind": potential_kind,
        "admitted_ns_summary": admitted_ns_summary,
        "admitted_images": admitted_images,
        "user_links": user_links,
        "group_links": group_links,
    }
