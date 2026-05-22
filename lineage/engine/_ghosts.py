"""Bound-ghost detection: bindings whose subject does not exist.

Ghost detection is an admin-only signal. Non-admin sessions get an
incomplete subject inventory and would produce false positives, so
both helpers short-circuit when `idx['is_admin']` is False.
"""

from .. import classifier as cf
from ._classify import is_baseline_subject, is_baseline_binding


def is_ghost(s, idx):
    """Bound but no backing object. system: prefixes are virtual, not ghosts.

    For non-admins the subject index is incomplete (alice can't list users
    cluster-wide), so 'missing from index' doesn't mean 'ghost'. Returns
    False in that case to avoid false positives.
    """
    if not idx.get("is_admin", True):
        return False
    kind = s.get("kind")
    name = s.get("name") or ""
    if name.startswith("system:"):
        return False
    if kind == "User":
        return name not in idx["users_by_name"]
    if kind == "Group":
        return name not in idx["groups_by_name"]
    if kind == "ServiceAccount":
        return (s.get("namespace"), name) not in idx["sas_by_key"]
    return False


def find_ghost_subjects(idx, include_baseline=False):
    """
    Ghost detection requires complete subject visibility — skipped for non-admins.

    Tags each ghost with one of:
      - "scc"     : bound only by an SCC binding (admission, not RBAC)
      - "routine" : subject or binding looks operator-managed
      - "real"    : actual anomaly worth surfacing
    """
    if not idx.get("is_admin", True):
        return []
    out = []
    for b in idx["all_bindings"]:
        for s in (b.get("subjects") or []):
            if not is_ghost(s, idx):
                continue
            sub_baseline = is_baseline_subject(s, idx)
            bind_baseline = is_baseline_binding(b, idx)
            scc = cf.is_scc_binding(b)
            if scc:
                category = "scc"
            elif sub_baseline or bind_baseline:
                category = "routine"
            else:
                category = "real"
            if not include_baseline and category != "real":
                continue
            out.append({
                "subject": s, "binding": b,
                "subject_baseline": sub_baseline,
                "binding_baseline": bind_baseline,
                "category": category,
                "routine": category != "real",
                "creation_ts": b.get("creationTimestamp"),
            })
    out.sort(key=lambda g: (g.get("creation_ts") or "",
                            g["subject"].get("kind") or "",
                            g["subject"].get("namespace") or "",
                            g["subject"].get("name") or ""),
             reverse=True)
    return out
