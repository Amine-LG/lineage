"""SecurityContextConstraint subject and use-grant analysis.

`scc_potential_subjects` is the workhorse — every row on `/scc/<name>`
goes through `_scc_subject_row`, which folds direct SCC.users/groups,
RBAC `use` grants, and group-derived members into one classified list.
"""

from ._constants import SA_PRINCIPAL_PREFIX
from ._classify import (
    is_baseline_subject,
    is_unknown_subject,
    is_baseline_namespace,
    is_unknown_namespace,
)
from ._rbac import (
    _resolve_role,
    expand_aggregated_role,
    _expand_group_subject,
)
from ._ghosts import is_ghost
from ._resurrectable import (
    _parse_sa_principal,
    _scc_severity,
    _subject_binding_is_baseline,
    _subject_binding_is_unknown,
)


def self_provisioner_posture(idx):
    """Detect whether project self-provisioning appears enabled, using
    only the already-collected RBAC index — no new oc reads.

    The default OpenShift install binds the `self-provisioner`
    ClusterRole to the virtual Group `system:authenticated:oauth` (and
    sometimes `system:authenticated`). That binding is the one that
    lets any logged-in user run `oc new-project <name>`, which is the
    trigger for every namespace-reuse / resurrectable-implicit-group
    finding in Lineage.

    Returns a dict with:
      state    : "enabled" | "disabled" | "unknown"
      binding  : str | None  — name of the CRB making it enabled
      subject  : str | None  — the group string the CRB names
      reason   : str         — short, reviewer-facing
    """
    error_kinds = idx.get("fetch_error_kinds") or set()
    # If we couldn't list CRBs, we can't claim either way.
    if "crb" in error_kinds:
        return {
            "state": "unknown",
            "binding": None,
            "subject": None,
            "reason": ("ClusterRoleBindings are not readable in this "
                       "session, so Lineage cannot determine whether "
                       "self-provisioner is bound. Treat namespace-reuse "
                       "findings as potentially triggerable."),
        }
    candidates = ("system:authenticated:oauth", "system:authenticated")
    for b in (idx.get("all_bindings") or []):
        if b.get("kind") != "ClusterRoleBinding":
            continue
        ref = b.get("roleRef") or {}
        if ref.get("name") != "self-provisioner":
            continue
        for s in (b.get("subjects") or []):
            if s.get("kind") != "Group":
                continue
            name = s.get("name") or ""
            if name in candidates:
                return {
                    "state": "enabled",
                    "binding": b.get("name"),
                    "subject": name,
                    "reason": (
                        "Project self-provisioning appears enabled — "
                        f"ClusterRoleBinding/{b.get('name')} binds the "
                        f"`self-provisioner` ClusterRole to "
                        f"`{name}`. Any authenticated user can run "
                        "`oc new-project <name>`, so namespace-reuse "
                        "findings (resurrectable implicit-SA groups, "
                        "SA principals in deleted namespaces) may be "
                        "triggerable by non-admin users."
                    ),
                }
    # No binding found and CRB visibility is fine → disabled.
    return {
        "state": "disabled",
        "binding": None,
        "subject": None,
        "reason": ("No ClusterRoleBinding to `self-provisioner` for "
                   "`system:authenticated[:oauth]` is visible. "
                   "Non-admin users cannot self-provision projects, "
                   "so namespace-reuse findings need administrator "
                   "action to trigger."),
    }


def absent_sa_grants_for_scc(scc_name, idx):
    """For the SCC detail page: which entries in this SCC's users list
    point at SAs that don't exist."""
    scc = (idx.get("sccs_by_name") or {}).get(scc_name)
    if not scc:
        return []
    sas = idx.get("sas_by_key") or {}
    namespaces = idx.get("namespaces_by_name") or {}
    out = []
    for u in (scc.get("users") or []):
        parsed = _parse_sa_principal(u or "")
        if not parsed:
            continue
        ns, name = parsed
        if (ns, name) in sas:
            continue
        out.append({
            "principal": u, "namespace": ns, "name": name,
            "namespace_present": ns in namespaces,
            "creation_ts": scc.get("creationTimestamp"),
        })
    out.sort(key=lambda r: (r["namespace_present"], r["namespace"], r["name"]))
    out.sort(key=lambda r: r.get("creation_ts") or "", reverse=True)
    return out


def _rule_grants_scc_use(rule, scc_name):
    verbs = rule.get("verbs") or []
    if "*" not in verbs and "use" not in verbs:
        return False
    resources = rule.get("resources") or []
    if ("*" not in resources
            and "securitycontextconstraints" not in resources
            and "securitycontextconstraints.security.openshift.io" not in resources):
        return False
    names = rule.get("resourceNames") or []
    if names and "*" not in names and scc_name not in names:
        return False
    return True


def _normalize_scc_subject(subject):
    """SCC/RBAC subjects sometimes name SAs as User principals."""
    if (subject.get("kind") == "User"
            and (subject.get("name") or "").startswith(SA_PRINCIPAL_PREFIX)):
        parsed = _parse_sa_principal(subject.get("name"))
        if parsed:
            ns, name = parsed
            return {"kind": "ServiceAccount", "name": name, "namespace": ns}
    return dict(subject)


def _scc_group_scope(group_name, idx):
    if group_name == "system:authenticated":
        return {
            "broad": True,
            "state": "virtual group",
            "note": "all authenticated users and ServiceAccounts",
            "current_count": None,
        }
    if group_name == "system:serviceaccounts":
        return {
            "broad": True,
            "state": "virtual group",
            "note": "all ServiceAccounts in all namespaces, including future SAs",
            "current_count": len(idx.get("sas_by_key") or {}),
        }
    prefix = "system:serviceaccounts:"
    if group_name.startswith(prefix):
        ns = group_name[len(prefix):]
        ns_present = ns in (idx.get("namespaces_by_name") or {})
        current = sum(1 for sa_ns, _ in (idx.get("sas_by_key") or {}) if sa_ns == ns)
        if ns_present:
            note = f"all current and future ServiceAccounts in namespace {ns}"
            state = "namespace present"
        else:
            note = f"all ServiceAccounts if namespace {ns} is recreated"
            state = "namespace deleted"
        return {
            "broad": True,
            "state": state,
            "note": note,
            "current_count": current,
            "namespace_present": ns_present,
            "namespace": ns,
        }
    if group_name.startswith("system:"):
        return {
            "broad": False,
            "state": "virtual/system group",
            "note": "platform virtual group",
            "current_count": None,
        }
    group = (idx.get("groups_by_name") or {}).get(group_name)
    if group:
        members = group.get("users") or []
        return {
            "broad": False,
            "state": "group present",
            "note": f"{len(members)} member(s)",
            "current_count": len(members),
        }
    return {
        "broad": False,
        "state": "group missing",
        "note": "binding names a Group object that is not present",
        "current_count": None,
    }


def _scc_subject_row(subject, via, source, scc_name, idx, role_name=None,
                     creation_ts=None, binding=None):
    subject = _normalize_scc_subject(subject)
    kind = subject.get("kind")
    name = subject.get("name") or ""
    namespace = subject.get("namespace")
    state = "present"
    note = ""
    broad = False
    current_count = None
    namespace_present = None

    if kind == "ServiceAccount":
        grant_label = "RBAC access" if source == "RBAC use grant" else "the SCC grant"
        namespace_present = namespace in (idx.get("namespaces_by_name") or {})
        exists = (namespace, name) in (idx.get("sas_by_key") or {})
        if exists:
            state = "SA present"
            note = "can use this SCC now if selected by admission"
        elif namespace_present:
            state = "SA missing"
            note = f"recreating this ServiceAccount reactivates {grant_label}"
        else:
            state = "namespace deleted"
            note = f"recreating the namespace and ServiceAccount reactivates {grant_label}"
    elif kind == "User":
        if name.startswith("system:"):
            state = "virtual/system user"
            note = "platform identity"
        elif name in (idx.get("users_by_name") or {}):
            state = "user present"
            note = "can use this SCC now if authenticated"
        else:
            state = "user missing"
            note = "future user with this name would inherit access that can use this SCC"
    elif kind == "Group":
        scope = _scc_group_scope(name, idx)
        broad = scope["broad"]
        state = scope["state"]
        note = scope["note"]
        current_count = scope.get("current_count")
        namespace_present = scope.get("namespace_present")

    ghost = is_ghost(subject, idx)
    resurrectable = kind == "ServiceAccount" and ghost
    baseline = is_baseline_subject(subject, idx)
    unknown = (not baseline) and is_unknown_subject(subject, idx)
    group_ns_prefix = "system:serviceaccounts:"
    if kind == "Group" and name.startswith(group_ns_prefix):
        group_ns = name[len(group_ns_prefix):]
        baseline = is_baseline_namespace(group_ns, idx)
        unknown = (not baseline) and is_unknown_namespace(group_ns, idx)
    if binding is not None:
        baseline = _subject_binding_is_baseline(subject, binding, idx)
        unknown = (not baseline) and _subject_binding_is_unknown(
            subject, binding, idx)
    return {
        "subject": subject,
        "kind": kind,
        "name": name,
        "namespace": namespace,
        "via": via,
        "source": source,
        "role": role_name,
        "state": state,
        "note": note,
        "current_count": current_count,
        "namespace_present": namespace_present,
        "ghost": ghost,
        "resurrectable": resurrectable,
        "broad": broad,
        "baseline": baseline,
        "unknown": unknown,
        "severity": _scc_severity((idx.get("sccs_by_name") or {}).get(scc_name) or {}),
        "creation_ts": creation_ts,
    }


def scc_potential_subjects(scc_name, idx):
    """Subjects that can currently use, or could later reactivate, an SCC.

    Includes direct SCC.users, SCC.groups, and RBAC bindings whose resolved
    role grants `use` on this securitycontextconstraint.
    """
    scc = (idx.get("sccs_by_name") or {}).get(scc_name)
    if not scc:
        return []

    rows = []
    for user in (scc.get("users") or []):
        parsed = _parse_sa_principal(user)
        if parsed:
            ns, name = parsed
            subject = {"kind": "ServiceAccount", "name": name, "namespace": ns}
        else:
            subject = {"kind": "User", "name": user}
        rows.append(_scc_subject_row(subject, "scc.users", "SCC user list",
                                     scc_name, idx,
                                     creation_ts=scc.get("creationTimestamp")))

    def _add_row(subject, via, source, *, role_name=None,
                  creation_ts=None, binding=None, via_group=None):
        row = _scc_subject_row(subject, via, source, scc_name, idx,
                                role_name=role_name,
                                creation_ts=creation_ts, binding=binding)
        row["via_group"] = via_group
        row["derived"] = via_group is not None
        rows.append(row)

    seen_derived = set()  # (kind, ns, name, source-binding-name)

    for group in (scc.get("groups") or []):
        subject = {"kind": "Group", "name": group}
        _add_row(subject, "scc.groups", "SCC group list",
                  creation_ts=scc.get("creationTimestamp"))
        for member in _expand_group_subject(group, idx):
            key = (member.get("kind"), member.get("namespace") or "",
                    member.get("name") or "", f"scc.groups/{group}")
            if key in seen_derived:
                continue
            seen_derived.add(key)
            _add_row(member, f"scc.groups/{group}", "SCC group list",
                      creation_ts=scc.get("creationTimestamp"),
                      via_group=group)

    for binding in idx.get("all_bindings") or []:
        ref = binding.get("roleRef") or {}
        role_name = ref.get("name") or ""
        role = _resolve_role(ref, binding.get("namespace"), idx)
        grants_use = False
        if role is not None:
            rules, _ = expand_aggregated_role(role, idx)
            grants_use = any(
                _rule_grants_scc_use(rule, scc_name) for rule in rules
            )
        if not grants_use:
            continue
        via = f"{binding['kind']}/{binding['name']}"
        for subject in binding.get("subjects") or []:
            _add_row(subject, via, "RBAC use grant",
                      role_name=role_name,
                      creation_ts=binding.get("creationTimestamp"),
                      binding=binding)
            if subject.get("kind") == "Group":
                for member in _expand_group_subject(
                        subject.get("name") or "", idx):
                    key = (member.get("kind"),
                            member.get("namespace") or "",
                            member.get("name") or "",
                            f"{via}|{subject.get('name')}")
                    if key in seen_derived:
                        continue
                    seen_derived.add(key)
                    _add_row(member, f"{via} (via {subject.get('name')})",
                              "RBAC use grant",
                              role_name=role_name,
                              creation_ts=binding.get("creationTimestamp"),
                              binding=binding,
                              via_group=subject.get("name"))

    rows.sort(key=lambda r: (
        not r["resurrectable"], not r["ghost"], not r["broad"],
        r["baseline"], r["kind"] or "", r["namespace"] or "", r["name"] or "",
        r["via"] or "",
    ))
    rows.sort(key=lambda r: r.get("creation_ts") or "", reverse=True)
    return rows
