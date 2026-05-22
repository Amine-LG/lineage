"""
Lineage engine. Pure functions over `lineage.data`.

- Namespace classification is layered: each namespace gets a category
  (system / openshift / project / unknown) plus
  the list of signals that produced that category. The boolean
  is_baseline_namespace is a thin reduction kept for backward-compat. See
  classifier.classify_namespace_obj for the rule set and rationale.
- role_grants(): every binding to a non-baseline subject, with creation_ts,
  sorted newest first. The 'who got what role when' audit.
- Ghost suppression: ghosts where subject lives in baseline ns OR binding is
  baseline are hidden by default.
- Effective-permission paths come with a verb/resource summary so they're
  skimmable; the full rule list expands on click.
"""

from collections import defaultdict

from .. import data
from ._constants import (
    PRIVILEGED_ROLES,
    AUTO_CREATED_PROJECT_SAS,
    ROLE_TIERS,
    COMMON_VERBS,
    PREFERRED_RESOURCE_API_GROUPS,
    CLUSTER_SCOPED_RBAC_RESOURCES,
    SEVERITY_ORDER,
    SA_PRINCIPAL_PREFIX,
    SCC_ROLE_PREFIX,
)


# ============================================================ #
# Indices                                                      #
# ============================================================ #

def index():
    status = data.live_status()
    identities = data.identities()
    nsbn = {n["name"]: n for n in data.namespaces()}
    htp = data.htpasswd_users()
    # Backward-compat: if a data source still returns a plain list, treat it
    # as readable and configured iff non-empty (legacy mocks / fixtures).
    if isinstance(htp, list):
        htp = {"configured": bool(htp), "available": True,
               "users": list(htp), "reason": None}
    idx = {
        "is_admin": status.get("is_admin", True),
        "current_user": status.get("user"),
        "users_by_name": {u["name"]: u for u in data.users()},
        "groups_by_name": {g["name"]: g for g in data.groups()},
        "namespaces_by_name": nsbn,
        "sas_by_key": {(sa["namespace"], sa["name"]): sa for sa in data.service_accounts()},
        "identities": identities,
        "identities_by_user": _identities_by_user(identities),
        "cluster_roles_by_name": {cr["name"]: cr for cr in data.cluster_roles()},
        "roles_by_key": {(r["namespace"], r["name"]): r for r in data.roles()},
        "all_bindings": _all_bindings(data.cluster_role_bindings(), data.role_bindings()),
        "pods": data.pods(),
        "sccs_by_name": {s["name"]: s for s in data.security_context_constraints()},
        "htpasswd_users": htp.get("users") or [],
        "htpasswd_available": bool(htp.get("available", True)),
        "htpasswd_configured": bool(htp.get("configured", False)),
        "htpasswd_reason": htp.get("reason"),
        "oauth_cluster": data.oauth_cluster(),
        "imagestreams": data.imagestreams(),
        "jobs": data.jobs(),
        "cronjobs": data.cronjobs(),
    }
    # Per-resource visibility — derived from cache state AFTER every
    # fetch above has had a chance to populate `_error`. Computing this
    # before the fetches would miss any kind that errors out (since
    # `_oc_json` is what writes the `_error` field into the cache).
    # Routes use this set to surface "X not visible" notes without
    # hiding visible primary objects.
    idx["fetch_error_kinds"] = {
        e["kind"] for e in (data.fetch_errors() or [])
    }
    return idx


def _identities_by_user(idents):
    out = {}
    for i in idents:
        u = (i.get("user") or {}).get("name", "")
        if u:
            out.setdefault(u, []).append(i)
    return out


def _rolebinding_with_subject_defaults(binding):
    rb = {**binding, "kind": "RoleBinding"}
    binding_ns = rb.get("namespace")
    if not binding_ns:
        return rb
    subjects = []
    changed = False
    for subject in (rb.get("subjects") or []):
        if (subject.get("kind") == "ServiceAccount"
                and not subject.get("namespace")):
            subjects.append({**subject, "namespace": binding_ns})
            changed = True
        else:
            subjects.append(subject)
    if changed:
        rb["subjects"] = subjects
    return rb


def _all_bindings(crbs, rbs):
    return ([{**b, "kind": "ClusterRoleBinding", "namespace": None} for b in crbs]
            + [_rolebinding_with_subject_defaults(b) for b in rbs])


# ============================================================ #
# Classification — see _classify.py                            #
# ============================================================ #
from ._classify import (
    _cluster_install_ts,
    classify_namespace,
    is_baseline_namespace,
    is_unknown_namespace,
    is_mine_namespace,
    is_baseline_subject,
    is_baseline_binding,
    is_baseline_user,
    CRC_DEFAULT_HTPASSWD_USERS,
    _is_crc_default_htpasswd_user,
    is_baseline_sa,
    is_unknown_sa,
    is_unknown_subject,
    is_unknown_binding,
    is_baseline_absent_sa,
    is_unknown_absent_sa,
)


# ============================================================ #
# Group membership + virtual groups + aggregation              #
# See _rbac.py                                                 #
# ============================================================ #
from ._rbac import (
    groups_for_user,
    rbac_groups_for_user,
    groups_for_serviceaccount,
    SYSTEM_AUTO_MEMBERSHIP_GROUPS,
    is_system_virtual_group,
    expand_aggregated_role,
    _labels_match_any,
    _labels_match_selector,
    _expand_group_subject,
    _resolve_role,
    summarize_rules,
)


# ============================================================ #
# Ghost subjects — see _ghosts.py                              #
# ============================================================ #
from ._ghosts import is_ghost, find_ghost_subjects


# ============================================================ #
# Resurrectable identities — see _resurrectable.py             #
# ============================================================ #
from ._resurrectable import (
    _parse_sa_principal,
    _scc_name_from_role,
    _scc_for_role_name,
    _role_severity,
    _role_tier,
    _is_privileged_role_name,
    _is_privileged_scc_role,
    _subject_binding_is_baseline,
    _subject_binding_is_unknown,
    _is_bound_stranded_user,
    _latest_timestamp,
    _scc_severity,
    _max_severity,
    resurrectable_sa_identities,
    deleted_namespaces_with_grants,
    _sccs_granted_by_rule,
    resurrectable_implicit_scc_groups,
)


# ============================================================ #
# SCC subject / use analysis — see _scc.py                     #
# ============================================================ #
from ._scc import (
    self_provisioner_posture,
    absent_sa_grants_for_scc,
    _rule_grants_scc_use,
    _normalize_scc_subject,
    _scc_group_scope,
    _scc_subject_row,
    scc_potential_subjects,
)


# ============================================================ #
# Effective permissions + who-can — see _who_can.py            #
# ============================================================ #
from ._who_can import (
    PathStep,
    EffectivePath,
    effective_permissions,
    _subject_matches,
    who_can,
    _resource_key,
    _preferred_api_groups_for_resource,
    _role_bindings_can_grant_resource,
    _api_groups_for_resource,
    _rule_allows,
    all_resources_seen,
)


# ============================================================ #
# Subjects inventory                                           #
# ============================================================ #

from ._rbac import describe_virtual_group, virtual_groups_referenced  # noqa: E402


def latent_usernames(idx):
    """All usernames that look pre-provisioned but have no User object.
    Includes: htpasswd-listed, Group-listed."""
    out = set()
    for h in (idx.get("htpasswd_users") or []):
        if h["username"] not in idx["users_by_name"]:
            out.add(h["username"])
    for g in idx["groups_by_name"].values():
        for member in (g.get("users") or []):
            if member and member not in idx["users_by_name"]:
                out.add(member)
    return out


def all_subjects(idx=None):
    if idx is None:
        idx = index()
    out = []
    latent = latent_usernames(idx)

    htpasswd_set_for_users = (
        {h["username"] for h in (idx.get("htpasswd_users") or [])}
        if idx.get("htpasswd_available", True) else set()
    )
    for u in idx["users_by_name"].values():
        idents = idx["identities_by_user"].get(u["name"], [])
        baseline = is_baseline_user(u, idx)
        stranded = bool(idx.get("is_admin", True) and not baseline and not idents)
        phantom = _is_phantom_user(u["name"], idx)
        htpasswd_backed = u["name"] in htpasswd_set_for_users
        out.append({"kind": "User", "name": u["name"], "namespace": None,
                    "ghost": False, "latent": False,
                    "stranded": stranded,
                    "phantom": phantom,
                    "htpasswd_backed": htpasswd_backed,
                    "baseline": baseline,
                    "unknown": False,  # Users classify as yours/baseline only.
                    "origin": _origin_for_user(idents),
                    "identities": idents,
                    "creationTimestamp": u.get("creationTimestamp")})

    for g in idx["groups_by_name"].values():
        baseline = (g["name"] or "").startswith("system:")
        out.append({"kind": "Group", "name": g["name"], "namespace": None,
                    "ghost": False, "latent": False, "baseline": baseline,
                    "unknown": False,  # Groups classify as yours/baseline only.
                    "origin": "manual",
                    "members": g.get("users") or [],
                    "creationTimestamp": g.get("creationTimestamp")})

    # Virtual / system groups referenced by RBAC or SCCs but having no Group
    # object. These are synthesized by the apiserver per-request; we surface
    # them so reviewers can discover them in /subjects instead of guessing a
    # URL like /subject/Group/system:authenticated:oauth.
    seen_group_names = {g["name"] for g in idx["groups_by_name"].values()}
    for vg in virtual_groups_referenced(idx):
        if vg in seen_group_names:
            continue
        subject = {"kind": "Group", "name": vg}
        baseline = is_baseline_subject(subject, idx)
        unknown = (not baseline) and is_unknown_subject(subject, idx)
        out.append({"kind": "Group", "name": vg, "namespace": None,
                    "ghost": False, "latent": False,
                    "baseline": baseline,
                    "unknown": unknown,
                    "virtual": True,
                    "origin": "virtual/system group",
                    "members": [],
                    "creationTimestamp": None})

    for sa in idx["sas_by_key"].values():
        baseline = is_baseline_sa(sa, idx)
        unknown = is_unknown_sa(sa, idx)
        out.append({"kind": "ServiceAccount", "name": sa["name"],
                    "namespace": sa["namespace"],
                    "ghost": False, "latent": False, "baseline": baseline,
                    "unknown": unknown,
                    "origin": "baseline" if baseline
                              else ("unknown" if unknown else "user"),
                    "creationTimestamp": sa.get("creationTimestamp")})

    row_by_key = {}
    seen = set()
    for ghost in find_ghost_subjects(idx, include_baseline=True):
        s = ghost["subject"]
        key = (s.get("kind"), s.get("name"), s.get("namespace"))
        if key in seen:
            continue
        seen.add(key)
        # Ghost SAs in an unknown namespace are unknown, not baseline.
        gunknown = (s.get("kind") == "ServiceAccount"
                    and not ghost["routine"]
                    and s.get("namespace")
                    and is_unknown_namespace(s.get("namespace"), idx))
        row = {"kind": s.get("kind"), "name": s.get("name"),
               "namespace": s.get("namespace"),
               "ghost": True, "latent": False,
               "baseline": ghost["routine"] and not gunknown,
               "unknown": bool(gunknown),
               "routine": ghost["routine"],
               "origin": "ghost",
               "bound_by": ghost["binding"]["name"],
               "creationTimestamp": ghost.get("creation_ts")}
        out.append(row)
        row_by_key[key] = row

    for r in resurrectable_sa_identities(idx):
        key = ("ServiceAccount", r["name"], r["namespace"])
        grant_names = ", ".join(
            f"{g['kind']}/{g['name']}" for g in r.get("grants", [])
        )
        row = row_by_key.get(key)
        if row is None:
            row = {"kind": "ServiceAccount", "name": r["name"],
                   "namespace": r["namespace"],
                   "ghost": True, "latent": False}
            out.append(row)
            row_by_key[key] = row
        baseline = is_baseline_absent_sa(r["namespace"], idx)
        unknown = (not baseline) and is_unknown_absent_sa(r["namespace"], idx)
        row.update({
            "baseline": baseline,
            "unknown": unknown,
            "routine": baseline,
            "origin": "resurrectable",
            "bound_by": grant_names,
            "resurrectable": True,
            "severity": r["severity"],
            "grant_count": r["grant_count"],
            "namespace_present": r["namespace_present"],
            "creationTimestamp": r.get("creation_ts") or row.get("creationTimestamp"),
        })

    # Latent: in IdP backing store / Group, no User object yet.
    # A username can be latent AND a ghost at the same time — e.g. alice is
    # in the htpasswd Secret (no User) but is also referenced by a binding,
    # which makes her appear as a ghost. The earlier behavior dropped the
    # latent fact in that case; we now mutate the existing User row instead
    # so multiple identity markers can coexist.
    htpasswd_set = {h["username"] for h in (idx.get("htpasswd_users") or [])}
    existing_user_rows = {o["name"]: o for o in out if o.get("kind") == "User"}
    for username in sorted(latent):
        sources = []
        if username in htpasswd_set:
            sources.append("htpasswd")
        for g in idx["groups_by_name"].values():
            if username in (g.get("users") or []):
                sources.append(f"Group/{g['name']}")
        origin_suffix = ", ".join(sources) if sources else ""
        existing = existing_user_rows.get(username)
        if existing is not None:
            existing["latent"] = True
            # Preserve any pre-existing origin (e.g. "ghost") but make the
            # latent source explicit so the page explains *why*.
            base_origin = existing.get("origin") or ""
            existing["origin"] = (f"{base_origin}, latent ({origin_suffix})"
                                  if origin_suffix
                                  else (f"{base_origin}, latent"
                                        if base_origin else "latent"))
            continue
        origin = (f"latent ({origin_suffix})" if origin_suffix else "latent")
        out.append({"kind": "User", "name": username, "namespace": None,
                    "ghost": False, "latent": True, "baseline": False,
                    "unknown": False, "origin": origin})
    out.sort(key=lambda s: (s.get("kind") or "",
                            s.get("namespace") or "",
                            s.get("name") or ""))
    out.sort(key=lambda s: s.get("creationTimestamp") or "", reverse=True)
    return out

def _origin_for_user(idents):
    if not idents:
        return "no-identity"
    return ", ".join(sorted({(i.get("providerName") or "?") for i in idents}))


# ============================================================ #
# Pods, SCCs, Tokens                                           #
# ============================================================ #

OPENSHIFT_BASELINE_SCC_NAMES = frozenset({
    "anyuid",
    "hostaccess",
    "hostmount-anyuid",
    "hostmount-anyuid-v2",
    "hostnetwork",
    "hostnetwork-v2",
    "hostpath-provisioner",
    "machine-api-termination-handler",
    "nested-container",
    "nonroot",
    "nonroot-v2",
    "privileged",
    "restricted",
    "restricted-v2",
    "restricted-v3",
})


def is_baseline_pod(pod, idx):
    """A pod is platform baseline when it runs in a baseline namespace.

    Do not use quiet/managed-looking pod metadata here: user workloads can
    legitimately be operator-managed inside user projects. Namespace
    classification is the strong signal for the dashboard headline.
    """
    return is_baseline_namespace(pod.get("namespace"), idx)


def is_baseline_scc(scc, idx=None):
    """Known OpenShift/CRC built-in SCCs.

    SCCs are cluster-scoped, so namespace signals are unavailable. Keep this
    exact-name based: a custom SCC with benign-looking fields must still count
    as reviewer-owned/non-baseline on the home dashboard.
    """
    return (scc.get("name") or "") in OPENSHIFT_BASELINE_SCC_NAMES


def is_baseline_cluster_role(role, idx=None):
    """ClusterRole baseline classifier for home/dashboard summarization.

    Uses platform-managed metadata, not "quiet" behavior. In particular, an
    aggregated ClusterRole without Kubernetes/OpenShift/OLM release metadata
    remains non-baseline even if it currently selects zero components.
    """
    labels = role.get("labels") or {}
    annotations = role.get("annotations") or {}

    if labels.get("kubernetes.io/bootstrapping") == "rbac-defaults":
        return True
    if annotations.get("rbac.authorization.kubernetes.io/autoupdate") == "true":
        return True
    if any(k.startswith("include.release.openshift.io/") for k in annotations):
        return True
    if "capability.openshift.io/name" in annotations:
        return True

    owner_ns = labels.get("olm.owner.namespace") or labels.get("olm.operatornamespace")
    if labels.get("olm.managed") == "true" and owner_ns and idx is not None:
        return is_baseline_namespace(owner_ns, idx)

    return False


def pods_for_sa(sa_name, sa_namespace, idx):
    out = []
    for p in (idx.get("pods") or []):
        if p.get("namespace") != sa_namespace:
            continue
        spec = p.get("spec") or {}
        sa = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
        if sa == sa_name:
            out.append(p)
    return out


def scc_chain_for_sa(sa_name, sa_namespace, idx):
    sa_user = f"system:serviceaccount:{sa_namespace}:{sa_name}"
    sa_group_specific = f"system:serviceaccounts:{sa_namespace}"
    out = []
    for scc in idx["sccs_by_name"].values():
        users_l = scc.get("users") or []
        groups_l = scc.get("groups") or []
        via = None
        if sa_user in users_l:
            via = f"user {sa_user}"
        else:
            for g in ("system:authenticated", "system:serviceaccounts", sa_group_specific):
                if g in groups_l:
                    via = f"group {g}"
                    break
        if via:
            out.append({"scc": scc, "via": via})
    out.sort(key=lambda x: (-(x["scc"].get("priority") or 0), x["scc"]["name"]))
    return out


def jobs_for_sa(sa_name, sa_namespace, idx):
    """Jobs in this namespace whose pod template runs as the given SA.
    Newest first; rows without a creationTimestamp sort last."""
    out = []
    for j in (idx.get("jobs") or []):
        if j.get("namespace") != sa_namespace:
            continue
        spec = ((j.get("spec") or {}).get("template") or {}).get("spec") or {}
        sa = spec.get("serviceAccountName") or spec.get("serviceAccount") or "default"
        if sa == sa_name:
            owners = j.get("ownerReferences") or []
            owner = owners[0] if owners else None
            out.append({
                "name": j.get("name"),
                "creation_ts": j.get("creationTimestamp"),
                "owner_kind": owner.get("kind") if owner else None,
                "owner_name": owner.get("name") if owner else None,
            })
    out.sort(key=lambda r: (r.get("creation_ts") or "", r.get("name") or ""),
             reverse=True)
    return out


def cronjobs_for_sa(sa_name, sa_namespace, idx):
    """CronJobs in this namespace whose job template runs as the given SA.
    Newest first; rows without a creationTimestamp sort last."""
    out = []
    for c in (idx.get("cronjobs") or []):
        if c.get("namespace") != sa_namespace:
            continue
        job_template = (c.get("spec") or {}).get("jobTemplate") or {}
        pod_spec = ((job_template.get("spec") or {}).get("template") or {}).get("spec") or {}
        sa = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount") or "default"
        if sa == sa_name:
            out.append({
                "name": c.get("name"),
                "schedule": c.get("schedule"),
                "creation_ts": c.get("creationTimestamp"),
            })
    out.sort(key=lambda r: (r.get("creation_ts") or "", r.get("name") or ""),
             reverse=True)
    return out

def pods_admitted_by_scc(scc_name, idx):
    return [p for p in (idx.get("pods") or [])
            if (p.get("annotations") or {}).get("openshift.io/scc") == scc_name]


def sccs_with_admission_counts(idx):
    counts = {}
    for p in (idx.get("pods") or []):
        ann = (p.get("annotations") or {}).get("openshift.io/scc")
        if ann:
            counts[ann] = counts.get(ann, 0) + 1
    out = [{"scc": s, "admission_count": counts.get(s["name"], 0),
            "is_privileged": bool(s.get("allowPrivilegedContainer"))}
           for s in idx["sccs_by_name"].values()]
    out.sort(key=lambda x: (-x["admission_count"], x["scc"]["name"]))
    return out


def _is_phantom_user(name, idx):
    """User+Identity exist but the IdP backing entry is gone.

    When the HTPasswd Secret is unreadable (htpasswd_available is False),
    we cannot tell if the user is still in the backing store, so we do NOT
    flag HTPasswd-backed identities as phantom. Identities pointing to a
    provider that no longer exists in OAuth/cluster are still phantom —
    that check doesn't depend on Secret readability."""
    if not idx.get("is_admin", True):
        return False
    if is_baseline_user({"name": name}, idx):
        return False
    user = idx["users_by_name"].get(name)
    if not user:
        return False
    idents = idx["identities_by_user"].get(name) or []
    if not idents:
        return False
    idps = (idx.get("oauth_cluster") or {}).get("identityProviders") or []
    idp_type_by_name = {idp.get("name"): idp.get("type") for idp in idps}
    htpasswd_idp_names = {n for n, t in idp_type_by_name.items() if t == "HTPasswd"}
    htpasswd_set = {h["username"] for h in (idx.get("htpasswd_users") or [])}
    htpasswd_available = idx.get("htpasswd_available", True)

    for i in idents:
        pname = i.get("providerName")
        if (pname in htpasswd_idp_names and htpasswd_available
                and name not in htpasswd_set):
            return True
        if pname and pname not in idp_type_by_name:
            return True
    return False


def _is_stranded_user(name, idx):
    """User object exists, but no Identity points at it."""
    if not idx.get("is_admin", True):
        return False
    if not name or is_baseline_user({"name": name}, idx):
        return False
    return name in idx["users_by_name"] and not idx["identities_by_user"].get(name)


def subject_identity_markers(subject, idx, latent=None):
    """Public helper returning the per-subject identity markers that the UI
    surfaces as badges: phantom, stranded ('No ID'), latent, htpasswd_backed.

    Non-User subjects get all-False markers. The htpasswd_backed flag is only
    True when the HTPasswd Secret was actually readable AND a real User
    object exists for this name — otherwise `latent` already captures the
    "in htpasswd, no User" case and adding htpasswd-backed is redundant
    (and contradicts /subjects, which gates the flag on User existence).
    """
    if subject.get("kind") != "User":
        return {"phantom": False, "stranded": False, "latent": False,
                "htpasswd_backed": False}
    name = subject.get("name") or ""
    latent_names = latent if latent is not None else latent_usernames(idx)
    htpasswd_set = {h["username"] for h in (idx.get("htpasswd_users") or [])}
    user_exists = name in (idx.get("users_by_name") or {})
    return {
        "phantom": _is_phantom_user(name, idx),
        "stranded": _is_stranded_user(name, idx),
        "latent": name in latent_names,
        "htpasswd_backed": (idx.get("htpasswd_available", True)
                            and user_exists
                            and name in htpasswd_set),
    }


# Backward-compat alias — old private name. Prefer subject_identity_markers.
_subject_identity_markers = subject_identity_markers


def privileged_subjects(idx):
    out = []
    latent = latent_usernames(idx)
    for b in idx["all_bindings"]:
        ref = b.get("roleRef") or {}
        if ref.get("kind") != "ClusterRole":
            continue
        role_name = ref.get("name") or ""
        if not _is_privileged_role_name(role_name, idx):
            continue
        for s in (b.get("subjects") or []):
            baseline = _subject_binding_is_baseline(s, b, idx)
            unknown = (not baseline) and _subject_binding_is_unknown(s, b, idx)
            markers = subject_identity_markers(s, idx, latent)
            out.append({
                "subject": s, "binding": b,
                "role": role_name,
                "scope": "cluster" if b["kind"] == "ClusterRoleBinding" else b.get("namespace"),
                "ghost": is_ghost(s, idx),
                **markers,
                "baseline": baseline,
                "unknown": unknown,
                "creation_ts": b.get("creationTimestamp"),
                "tier": _role_tier(role_name, idx),
                "is_privileged_scc": _is_privileged_scc_role(role_name, idx),
            })
    out.sort(key=lambda x: (not x["ghost"], not x["phantom"],
                            -(x.get("tier") or 0),
                            x["role"], x["subject"].get("name") or ""))
    out.sort(key=lambda x: x.get("creation_ts") or "", reverse=True)
    out.sort(key=lambda x: x["baseline"])
    return out


def role_grants(idx):
    """Every binding to a non-baseline subject, sorted newest first.
    Each row carries an `unknown` flag so callers can filter."""
    out = []
    latent = latent_usernames(idx)
    for b in idx["all_bindings"]:
        ref = b.get("roleRef") or {}
        rname = ref.get("name") or ""
        rkind = ref.get("kind") or ""
        role_present = _resolve_role(ref, b.get("namespace"), idx) is not None
        for s in (b.get("subjects") or []):
            baseline = _subject_binding_is_baseline(s, b, idx)
            if baseline:
                continue
            unknown = _subject_binding_is_unknown(s, b, idx)
            markers = subject_identity_markers(s, idx, latent)
            out.append({
                "subject": s,
                "binding": {"kind": b["kind"], "name": b["name"],
                            "namespace": b.get("namespace")},
                "role": rname, "role_kind": rkind,
                "role_present": role_present,
                "baseline": False, "unknown": unknown,
                "tier": _role_tier(rname, idx),
                "is_privileged": _is_privileged_role_name(rname, idx),
                "scope": "cluster" if b["kind"] == "ClusterRoleBinding" else b.get("namespace"),
                "ghost": is_ghost(s, idx),
                **markers,
                "creation_ts": b.get("creationTimestamp"),
            })
    out.sort(key=lambda x: x["tier"], reverse=True)
    out.sort(key=lambda x: x.get("creation_ts") or "", reverse=True)
    return out

def duplicate_bindings(idx):
    groups = defaultdict(list)
    latent = latent_usernames(idx)

    def subject_row(kind, namespace, name):
        subject = {"kind": kind, "namespace": namespace or None, "name": name}
        return {
            **subject,
            "ghost": is_ghost(subject, idx),
            **subject_identity_markers(subject, idx, latent),
        }

    for b in idx["all_bindings"]:
        ref = b.get("roleRef") or {}
        if not ref.get("kind") or not ref.get("name"):
            continue
        subj_key = tuple(sorted(
            (s.get("kind", ""), s.get("namespace") or "", s.get("name", ""))
            for s in (b.get("subjects") or [])
        ))
        if not subj_key:
            continue
        key = (b["kind"], b.get("namespace") or "",
               ref.get("kind"), ref.get("name"), subj_key)
        groups[key].append(b)
    dups = []
    for key, bs in groups.items():
        if len(bs) > 1:
            all_baseline = all(
                all(_subject_binding_is_baseline(s, b, idx)
                    for s in (b.get("subjects") or []))
                for b in bs)
            all_unknown = (not all_baseline) and all(
                all(_subject_binding_is_unknown(s, b, idx)
                    or _subject_binding_is_baseline(s, b, idx)
                    for s in (b.get("subjects") or []))
                for b in bs) and any(
                any(_subject_binding_is_unknown(s, b, idx)
                    for s in (b.get("subjects") or []))
                for b in bs)
            dups.append({
                "binding_kind": key[0],
                "binding_namespace": key[1] or None,
                "role_kind": key[2], "role": key[3],
                "is_privileged": _is_privileged_role_name(key[3], idx),
                "baseline": all_baseline,
                "unknown": all_unknown,
                "subjects": [subject_row(k, ns, n) for k, ns, n in key[4]],
                "bindings": [{"kind": b["kind"], "name": b["name"],
                              "namespace": b.get("namespace")} for b in bs],
                "count": len(bs),
                "creation_ts": _latest_timestamp(
                    b.get("creationTimestamp") for b in bs),
            })
    dups.sort(key=lambda d: (not d["is_privileged"], -d["count"], d["role"]))
    dups.sort(key=lambda d: d.get("creation_ts") or "", reverse=True)
    dups.sort(key=lambda d: d["baseline"])
    return dups


# ============================================================ #
# Namespaces                                                   #
# ============================================================ #

def all_namespaces(idx):
    namespaces = set(idx["namespaces_by_name"].keys())
    for sa in idx["sas_by_key"].values():
        if sa.get("namespace"):
            namespaces.add(sa["namespace"])
    for r in idx["roles_by_key"].values():
        if r.get("namespace"):
            namespaces.add(r["namespace"])
    for b in idx["all_bindings"]:
        if b["kind"] == "RoleBinding" and b.get("namespace"):
            namespaces.add(b["namespace"])
    for p in (idx.get("pods") or []):
        if p.get("namespace"):
            namespaces.add(p["namespace"])
    return sorted(namespaces)


def namespace_summary(ns, idx):
    sas = [sa for sa in idx["sas_by_key"].values() if sa["namespace"] == ns]
    pods_in = [p for p in (idx.get("pods") or []) if p.get("namespace") == ns]
    rbs = [b for b in idx["all_bindings"]
           if b["kind"] == "RoleBinding" and b.get("namespace") == ns]
    highest_tier = 0
    highest_role = None
    for b in rbs:
        rname = (b.get("roleRef") or {}).get("name") or ""
        tier = _role_tier(rname, idx)
        if tier > highest_tier:
            highest_tier = tier
            highest_role = rname
    has_priv_pods = any(
        (p.get("annotations") or {}).get("openshift.io/scc") == "privileged"
        for p in pods_in
    )
    ns_obj = idx["namespaces_by_name"].get(ns) or {}
    requester = (ns_obj.get("annotations") or {}).get("openshift.io/requester")
    cls = classify_namespace(ns, idx)
    return {"namespace": ns,
            "baseline": cls["is_baseline"],
            "category": cls["category"],
            "signals": cls["signals"],
            "user_owned": cls["is_user_owned"],
            "owner": cls.get("owner") or requester,
            "requester": requester,
            "creation_ts": ns_obj.get("creationTimestamp"),
            "sas_count": len(sas), "pods_count": len(pods_in),
            "rolebindings_count": len(rbs), "highest_role_in_ns": highest_role,
            "highest_tier": highest_tier, "has_privileged_pods": has_priv_pods}


def _power_score(role_name, scope, n_rules):
    tier = _role_tier(role_name)
    scope_bonus = 50 if scope == "cluster" else 0
    return tier * 100 + scope_bonus + min(n_rules, 50)


def _resource_name(resource):
    return (resource or "").split("/", 1)[0]


def _rule_resource_pairs(rule):
    for api_group in (rule.get("apiGroups") or [""]):
        for resource in (rule.get("resources") or []):
            yield (api_group or "", _resource_name(resource))


def _is_scc_resource_pair(api_group, resource):
    return ((api_group or "") == "security.openshift.io"
            and _resource_name(resource) == "securitycontextconstraints")


_CLUSTER_LEVEL_RESOURCE_PAIRS = frozenset({
    ("", "namespaces"),
    ("", "nodes"),
    ("", "persistentvolumes"),
    ("", "componentstatuses"),
    ("apiextensions.k8s.io", "customresourcedefinitions"),
    ("apiregistration.k8s.io", "apiservices"),
    ("authentication.k8s.io", "selfsubjectreviews"),
    ("authentication.k8s.io", "tokenreviews"),
    ("authorization.k8s.io", "selfsubjectaccessreviews"),
    ("authorization.k8s.io", "selfsubjectrulesreviews"),
    ("authorization.k8s.io", "subjectaccessreviews"),
    ("authorization.openshift.io", "selfsubjectrulesreviews"),
    ("authorization.openshift.io", "subjectaccessreviews"),
    ("oauth.openshift.io", "oauthaccesstokens"),
    ("oauth.openshift.io", "oauthauthorizetokens"),
    ("oauth.openshift.io", "oauthclientauthorizations"),
    ("oauth.openshift.io", "oauthclients"),
    ("oauth.openshift.io", "tokenreviews"),
    ("oauth.openshift.io", "useroauthaccesstokens"),
    ("project.openshift.io", "projectrequests"),
    ("project.openshift.io", "projects"),
    ("rbac.authorization.k8s.io", "clusterrolebindings"),
    ("rbac.authorization.k8s.io", "clusterroles"),
    ("security.openshift.io", "securitycontextconstraints"),
    ("storage.k8s.io", "storageclasses"),
    ("storage.k8s.io", "volumeattachments"),
    ("user.openshift.io", "groups"),
    ("user.openshift.io", "identities"),
    ("user.openshift.io", "useridentitymappings"),
    ("user.openshift.io", "users"),
})

_CLUSTER_LEVEL_API_GROUPS = frozenset({
    "config.openshift.io",
    "operator.openshift.io",
})


def _can_learn_namespace_resource(api_group, resource):
    api_group = api_group or ""
    resource = _resource_name(resource)
    if resource == "*":
        return False
    if api_group in _CLUSTER_LEVEL_API_GROUPS:
        return False
    if (api_group, resource) in _CLUSTER_LEVEL_RESOURCE_PAIRS:
        return False
    return not _is_scc_resource_pair(api_group, resource)


def _namespace_resource_evidence(idx):
    """Resource pairs Lineage can justify as namespace-scoped.

    The seed set comes from namespace-scoped inventories Lineage already
    collects; extra pairs are learned from actual namespaced Roles and
    RoleBindings in the index after filtering out resources Lineage already
    models as cluster-level APIs.
    """
    evidence = {
        ("", "pods"),
        ("", "serviceaccounts"),
        ("batch", "cronjobs"),
        ("batch", "jobs"),
        ("image.openshift.io", "imagestreams"),
        ("rbac.authorization.k8s.io", "rolebindings"),
        ("rbac.authorization.k8s.io", "roles"),
    }
    for role in (idx.get("roles_by_key") or {}).values():
        for rule in role.get("rules") or []:
            for api_group, resource in _rule_resource_pairs(rule):
                if not _can_learn_namespace_resource(api_group, resource):
                    continue
                evidence.add((api_group, resource))
    for binding in idx.get("all_bindings") or []:
        if binding.get("kind") != "RoleBinding":
            continue
        role = _resolve_role(binding.get("roleRef") or {},
                             binding.get("namespace"), idx)
        if role is None:
            continue
        rules, _ = expand_aggregated_role(role, idx)
        for rule in rules:
            for api_group, resource in _rule_resource_pairs(rule):
                if not _can_learn_namespace_resource(api_group, resource):
                    continue
                evidence.add((api_group, resource))
    return evidence


def _evidence_matches(api_group, resource, evidence):
    api_group = api_group or ""
    resource = _resource_name(resource)
    if api_group == "*" and resource == "*":
        return True
    if resource == "*":
        return any(group == api_group for group, _ in evidence)
    if api_group == "*":
        return any(name == resource for _, name in evidence)
    return (api_group, resource) in evidence


def _rule_has_namespace_effect(rule, idx, evidence=None):
    """Whether a rule can grant access inside a namespace.

    ClusterRoleBindings are cluster-wide, but many default OpenShift grants
    point at non-resource URLs or cluster-scoped APIs. Those relationships
    are real, but they do not automatically mean the subject can touch
    namespace objects. Keep the namespace detail page focused on resource
    pairs that are known from Lineage's namespace inventories or from
    namespace-scoped RBAC already present in the index.
    """
    if not (rule.get("resources") or []):
        return False
    if evidence is None:
        evidence = _namespace_resource_evidence(idx)
    for api_group, resource in _rule_resource_pairs(rule):
        if _evidence_matches(api_group, resource, evidence):
            return True
    return False


def subjects_with_access_in_categorized(ns, idx):
    """Split subjects-with-access into mutually exclusive categories so
    nothing is silently hidden by a single 'yours'-style filter.

    Category order (first match wins per row):
      system_baseline : subject is system:* / baseline-classified,
                        or the binding itself is baseline-named
      unknown_ns_sas  : SA subject in an unknown namespace (review-worthy)
      groups          : Group subject
      cross_ns_sas    : SA subject in a different (known/yours) namespace,
                        bound by a local RoleBinding (a foreign SA gaining
                        access here)
      cluster_rbs     : non-system non-Group subject via ClusterRoleBinding
      local_rbs       : non-system non-Group subject via local RoleBinding
    """
    cats = {"local_rbs": [], "cluster_rbs": [], "cross_ns_sas": [],
            "groups": [], "unknown_ns_sas": [], "system_baseline": []}
    latent = latent_usernames(idx)
    namespace_evidence = _namespace_resource_evidence(idx)

    def _classify(subject, binding):
        name = subject.get("name") or ""
        kind = subject.get("kind")
        if kind == "User" and is_baseline_subject(subject, idx):
            return "system_baseline"
        if kind == "Group" and name.startswith("system:"):
            return "system_baseline"
        if is_baseline_subject(subject, idx) or is_baseline_binding(binding, idx):
            return "system_baseline"
        if kind == "ServiceAccount" and is_unknown_subject(subject, idx):
            return "unknown_ns_sas"
        if kind == "Group":
            return "groups"
        if (binding.get("kind") == "RoleBinding"
                and kind == "ServiceAccount"
                and subject.get("namespace")
                and subject.get("namespace") != ns):
            return "cross_ns_sas"
        if binding.get("kind") == "ClusterRoleBinding":
            return "cluster_rbs"
        return "local_rbs"

    def _emit(subject, binding, scope, ref, n_rules, via_group=None):
        """Append one row, classifying by subject + binding context."""
        cat = _classify(subject, binding)
        markers = subject_identity_markers(subject, idx, latent)
        cats[cat].append({
            "subject": subject,
            "role": ref.get("name"),
            "role_kind": ref.get("kind"),
            "scope": scope,
            "binding": {"kind": binding["kind"], "name": binding["name"],
                         "namespace": binding.get("namespace")},
            "ghost": is_ghost(subject, idx),
            **markers,
            "baseline": cat == "system_baseline",
            "unknown": cat == "unknown_ns_sas",
            "category": cat,
            "n_rules": n_rules,
            "via_group": via_group,
            "derived": via_group is not None,
            "score": _power_score(ref.get("name") or "", scope, n_rules),
        })

    seen_derived = set()  # (kind, ns, name, role, scope, source_binding)

    for b in idx.get("all_bindings") or []:
        if b.get("kind") == "ClusterRoleBinding":
            scope = "cluster"
        elif b.get("kind") == "RoleBinding" and b.get("namespace") == ns:
            scope = f"namespace:{ns}"
        else:
            continue
        ref = b.get("roleRef") or {}
        role = _resolve_role(ref, b.get("namespace"), idx)
        if role is None:
            continue
        rules, _ = expand_aggregated_role(role, idx)
        namespace_rules = [r for r in rules
                           if _rule_has_namespace_effect(
                               r, idx, namespace_evidence)]
        if not namespace_rules:
            continue
        for s in (b.get("subjects") or []):
            # Always emit the direct row so the binding shape is visible
            _emit(s, b, scope, ref, len(namespace_rules))
            # If this subject is an enumerable Group, also emit derived
            # rows for each principal that gains access via membership.
            # Reviewers asking "who has access?" need the actual users,
            # not just the group name.
            if s.get("kind") == "Group":
                for member in _expand_group_subject(s.get("name") or "", idx):
                    key = (member.get("kind"), member.get("namespace") or "",
                            member.get("name") or "", ref.get("name") or "",
                            scope, b.get("name") or "")
                    if key in seen_derived:
                        continue
                    seen_derived.add(key)
                    _emit(member, b, scope, ref, len(namespace_rules),
                          via_group=s.get("name"))
    for cat in cats.values():
        cat.sort(key=lambda r: (-r["score"],
                                 r["subject"].get("kind") or "",
                                 r["subject"].get("namespace") or "",
                                 r["subject"].get("name") or ""))
    return cats


def namespace_reach_for_subject(subject_kind, subject_name, subject_namespace, idx):
    cluster_paths = []
    ns_paths = defaultdict(list)
    seen_groups = set()

    def add_path(b, via_group=None):
        ref = b.get("roleRef") or {}
        rname = ref.get("name") or ""
        rkind = ref.get("kind") or ""
        entry = {"role": rname, "role_kind": rkind,
                 "binding_name": b["name"],
                 "binding_kind": b["kind"],
                 "via_group": via_group,
                 "tier": _role_tier(rname, idx)}
        if b["kind"] == "ClusterRoleBinding":
            cluster_paths.append(entry)
        else:
            ns_paths[b.get("namespace")].append(entry)

    for b in idx["all_bindings"]:
        for s in (b.get("subjects") or []):
            if _subject_matches(s, subject_kind, subject_name, subject_namespace):
                add_path(b, None)

    if subject_kind == "User":
        for gname in rbac_groups_for_user(subject_name, idx):
            seen_groups.add(gname)
            for b in idx["all_bindings"]:
                for s in (b.get("subjects") or []):
                    if s.get("kind") == "Group" and s.get("name") == gname:
                        add_path(b, gname)

    if subject_kind == "ServiceAccount":
        for gname in groups_for_serviceaccount(
                subject_name, subject_namespace, idx):
            seen_groups.add(gname)
            for b in idx["all_bindings"]:
                for s in (b.get("subjects") or []):
                    if s.get("kind") == "Group" and s.get("name") == gname:
                        add_path(b, gname)

    return {
        "cluster_wide": cluster_paths,
        "by_namespace": dict(ns_paths),
        "via_groups": sorted(seen_groups),
    }


# ============================================================ #
# Identity audit — see _identity_audit.py                      #
# ============================================================ #
from ._identity_audit import _aggregate_bound_ghosts, identity_audit


# ============================================================ #
# Images, ImageStreams, cross-namespace image grants — see _images.py
# ============================================================ #
from ._images import (
    _pod_images,
    image_inventory,
    registry_summary,
    _digest_of,
    _spec_image_key,
    image_drift,
    imagestream_usage,
    cross_namespace_bindings,
    bindings_for_role,
    image_puller_grants,
    cross_ns_bindings_for_namespace,
    images_running_in_namespace,
    bindings_referencing_sa,
    images_for_sa,
    surviving_grants_for_absent_sa,
    aggregation_parents_for_role,
    scc_use_interpretation,
    _normalize_image_repo,
    imagestream_for_image,
    digest_siblings_for_image,
    image_pods_by_namespace,
)


# Public engine surface plus grandfathered compatibility exports.
#
# The engine used to be a single module. After the package split, callers still
# import `lineage.engine` and access helpers as `engine.<name>`. Keeping this
# list explicit documents that surface and tells pyflakes/ruff these imports
# are intentional re-exports, not unused imports.
__all__ = [
    # Index assembly
    "index",

    # Classification
    "classify_namespace",
    "is_baseline_namespace",
    "is_unknown_namespace",
    "is_mine_namespace",
    "is_baseline_subject",
    "is_baseline_binding",
    "is_baseline_user",
    "is_baseline_sa",
    "is_unknown_sa",
    "is_unknown_subject",
    "is_unknown_binding",
    "is_baseline_absent_sa",
    "is_unknown_absent_sa",
    "is_baseline_pod",
    "is_baseline_scc",
    "is_baseline_cluster_role",

    # Subjects and identity
    "latent_usernames",
    "all_subjects",
    "subject_identity_markers",
    "is_ghost",
    "find_ghost_subjects",
    "identity_audit",
    "privileged_subjects",
    "role_grants",
    "duplicate_bindings",
    "describe_virtual_group",
    "virtual_groups_referenced",

    # RBAC and permissions
    "groups_for_user",
    "rbac_groups_for_user",
    "groups_for_serviceaccount",
    "is_system_virtual_group",
    "expand_aggregated_role",
    "summarize_rules",
    "PathStep",
    "EffectivePath",
    "effective_permissions",
    "who_can",
    "all_resources_seen",
    "all_namespaces",
    "namespace_summary",
    "subjects_with_access_in_categorized",
    "namespace_reach_for_subject",

    # Workloads and SCCs
    "pods_for_sa",
    "scc_chain_for_sa",
    "jobs_for_sa",
    "cronjobs_for_sa",
    "pods_admitted_by_scc",
    "sccs_with_admission_counts",
    "self_provisioner_posture",
    "absent_sa_grants_for_scc",
    "scc_potential_subjects",
    "resurrectable_sa_identities",
    "deleted_namespaces_with_grants",
    "resurrectable_implicit_scc_groups",

    # Images and ImageStreams
    "image_inventory",
    "registry_summary",
    "image_drift",
    "imagestream_usage",
    "cross_namespace_bindings",
    "bindings_for_role",
    "image_puller_grants",
    "cross_ns_bindings_for_namespace",
    "images_running_in_namespace",
    "bindings_referencing_sa",
    "images_for_sa",
    "surviving_grants_for_absent_sa",
    "aggregation_parents_for_role",
    "scc_use_interpretation",
    "imagestream_for_image",
    "digest_siblings_for_image",
    "image_pods_by_namespace",

    # Constants used by UI routes and templates
    "PRIVILEGED_ROLES",
    "COMMON_VERBS",
    "OPENSHIFT_BASELINE_SCC_NAMES",

    # Grandfathered compatibility helpers. These remain importable as
    # engine.<name>, but new code should prefer the public helpers above.
    "AUTO_CREATED_PROJECT_SAS",
    "ROLE_TIERS",
    "PREFERRED_RESOURCE_API_GROUPS",
    "CLUSTER_SCOPED_RBAC_RESOURCES",
    "SEVERITY_ORDER",
    "SA_PRINCIPAL_PREFIX",
    "SCC_ROLE_PREFIX",
    "CRC_DEFAULT_HTPASSWD_USERS",
    "SYSTEM_AUTO_MEMBERSHIP_GROUPS",
    "_identities_by_user",
    "_rolebinding_with_subject_defaults",
    "_all_bindings",
    "_cluster_install_ts",
    "_is_crc_default_htpasswd_user",
    "_labels_match_any",
    "_labels_match_selector",
    "_expand_group_subject",
    "_resolve_role",
    "_parse_sa_principal",
    "_scc_name_from_role",
    "_scc_for_role_name",
    "_role_severity",
    "_role_tier",
    "_is_privileged_role_name",
    "_is_privileged_scc_role",
    "_subject_binding_is_baseline",
    "_subject_binding_is_unknown",
    "_is_bound_stranded_user",
    "_latest_timestamp",
    "_scc_severity",
    "_max_severity",
    "_sccs_granted_by_rule",
    "_rule_grants_scc_use",
    "_normalize_scc_subject",
    "_scc_group_scope",
    "_scc_subject_row",
    "_subject_matches",
    "_resource_key",
    "_preferred_api_groups_for_resource",
    "_role_bindings_can_grant_resource",
    "_api_groups_for_resource",
    "_rule_allows",
    "_aggregate_bound_ghosts",
    "_pod_images",
    "_digest_of",
    "_spec_image_key",
    "_normalize_image_repo",
    "_origin_for_user",
    "_is_phantom_user",
    "_is_stranded_user",
    "_subject_identity_markers",
    "_power_score",
    "_resource_name",
    "_rule_resource_pairs",
    "_is_scc_resource_pair",
    "_can_learn_namespace_resource",
    "_namespace_resource_evidence",
    "_evidence_matches",
    "_rule_has_namespace_effect",
]
