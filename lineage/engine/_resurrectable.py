"""Resurrectable SA identities and implicit-SCC-group grants.

Recreating an OpenShift project (or a ServiceAccount, or an SCC) is a
cheap operation, but RBAC and SCC admission authenticate principals by
reusable name string. So a deleted SA / namespace / SCC can leave
surviving grants behind that come back to life the moment its name is
recreated. The helpers below surface those latent grants alongside the
severity and posture of the underlying role / SCC.

Also exposes small RBAC severity / role-tier helpers used by other
engine modules (e.g. identity audit, who-can scoring).
"""

from collections import defaultdict

from .. import classifier as cf
from ._constants import (
    SA_PRINCIPAL_PREFIX,
    SCC_ROLE_PREFIX,
    ROLE_TIERS,
    PRIVILEGED_ROLES,
    SEVERITY_ORDER,
    AUTO_CREATED_PROJECT_SAS,
)
from ._classify import (
    is_baseline_subject,
    is_baseline_binding,
    is_baseline_user,
    is_baseline_namespace,
    is_unknown_subject,
)
from ._rbac import _resolve_role, expand_aggregated_role


def _parse_sa_principal(s):
    """'system:serviceaccount:<ns>:<name>' → (ns, name) or None.

    Kubernetes RBAC and OpenShift SCCs both authenticate ServiceAccounts by
    this name string. The string is reusable: deleting the SA (or even the
    namespace) does not remove bindings or SCC grants that reference it,
    and recreating either restores the privilege.
    """
    if not s or not s.startswith(SA_PRINCIPAL_PREFIX):
        return None
    rest = s[len(SA_PRINCIPAL_PREFIX):]
    if ":" not in rest:
        return None
    ns, name = rest.split(":", 1)
    if not ns or not name:
        return None
    return (ns, name)


def _scc_name_from_role(role_name):
    role_name = role_name or ""
    if role_name.startswith(SCC_ROLE_PREFIX):
        return role_name[len(SCC_ROLE_PREFIX):] or None
    return None


def _scc_for_role_name(role_name, idx):
    scc_name = _scc_name_from_role(role_name)
    if not scc_name or not idx:
        return None
    return (idx.get("sccs_by_name") or {}).get(scc_name)


def _role_severity(role_name, idx=None):
    scc = _scc_for_role_name(role_name, idx)
    if scc:
        return _scc_severity(scc)
    scc_name = _scc_name_from_role(role_name)
    if scc_name == "privileged":
        return "critical"
    if scc_name in {"anyuid", "hostaccess", "hostmount-anyuid", "hostnetwork"}:
        return "high"
    if role_name in ("cluster-admin", "system:masters"):
        return "critical"
    if role_name == "admin":
        return "high"
    if role_name == "edit":
        return "medium"
    return "low"


def _role_tier(role_name, idx=None):
    if role_name in ROLE_TIERS:
        return ROLE_TIERS[role_name]
    if _scc_name_from_role(role_name):
        return {"critical": 5, "high": 4, "medium": 3, "low": 1}.get(
            _role_severity(role_name, idx), 0)
    return 0


def _is_privileged_role_name(role_name, idx=None):
    if role_name in PRIVILEGED_ROLES:
        return True
    return (_scc_name_from_role(role_name) is not None
            and _role_severity(role_name, idx) in ("critical", "high"))


def _is_privileged_scc_role(role_name, idx):
    scc = _scc_for_role_name(role_name, idx)
    if scc:
        return bool(scc.get("allowPrivilegedContainer"))
    return _scc_name_from_role(role_name) == "privileged"


def _subject_binding_is_baseline(subject, binding, idx):
    """Subject-level baseline for binding rows.

    Some OpenShift SCC grants live in system-named ClusterRoleBindings
    (`system:openshift:scc:<name>`). The binding object is platform-named,
    but a project-owned subject added to it is still user-relevant and must
    remain visible in Yours/recent views.
    """
    if _is_bound_stranded_user(subject, binding, idx):
        return False
    if is_baseline_subject(subject, idx):
        return True
    role_name = ((binding.get("roleRef") or {}).get("name") or "")
    if _scc_name_from_role(role_name):
        return False
    return is_baseline_binding(binding, idx)


def _subject_binding_is_unknown(subject, binding, idx):
    """Companion of _subject_binding_is_baseline. The row's unknown
    classification is driven by the SUBJECT, never by the binding's
    namespace alone — a human User with normal identity provenance must
    NOT become Unclassified just because the RoleBinding referencing
    them sits in an unclassified namespace. The binding's namespace is
    visible to the reviewer in the binding column; classification of
    the subject row should reflect the subject.
    """
    if _subject_binding_is_baseline(subject, binding, idx):
        return False
    return is_unknown_subject(subject, idx)


def _is_bound_stranded_user(subject, binding, idx):
    if subject.get("kind") != "User":
        return False
    name = subject.get("name") or ""
    if is_baseline_user({"name": name}, idx):
        return False
    if name not in (idx.get("users_by_name") or {}):
        return False
    if (idx.get("identities_by_user") or {}).get(name):
        return False
    if cf.is_baseline_binding(binding):
        return False
    if (binding.get("kind") == "RoleBinding" and binding.get("namespace")
            and is_baseline_namespace(binding.get("namespace"), idx)):
        return False
    return True


def _latest_timestamp(values):
    return max((v for v in values if v), default=None)


def _scc_severity(scc):
    """Map an SCC's posture to the same severity ladder used elsewhere.
    Driven by SCC fields (not by name) so vendor-renamed SCCs still rank
    correctly."""
    if scc.get("allowPrivilegedContainer"):
        return "critical"
    if (scc.get("allowHostNetwork") or scc.get("allowHostPID")
            or scc.get("allowHostIPC")):
        return "high"
    if (scc.get("runAsUser") or {}).get("type") == "RunAsAny":
        return "high"
    if scc.get("allowPrivilegeEscalation"):
        return "medium"
    return "low"


def _max_severity(*levels):
    return max(levels, key=lambda x: SEVERITY_ORDER.get(x, 0))


def resurrectable_sa_identities(idx):
    """ServiceAccount principals (system:serviceaccount:<ns>:<name>) that
    are still referenced by an authorization grant — RBAC binding or SCC
    user list — but whose underlying ServiceAccount object is absent.

    Recreating the SA (and the namespace, if also gone) immediately
    reactivates whatever role or SCC the grant points to. This is not a
    bug in Kubernetes/OpenShift; it is a consequence of RBAC and SCC
    admission authenticating SAs by reusable name string rather than by
    object lifecycle. Lineage surfaces the relationship so the operator
    can prune the surviving grant or accept the residue knowingly.

    Aggregates by principal — one entry per absent SA, listing every grant
    that still references it. Severity is the highest role/SCC privilege
    seen, bumped one tier when the namespace itself is also gone because
    a future namespace recreation could make the surviving grants usable again.
    """
    if not idx.get("is_admin", True):
        return []

    grants = defaultdict(list)
    namespaces = idx.get("namespaces_by_name") or {}
    sas = idx.get("sas_by_key") or {}

    def _add(ns, name, grant):
        grants[(ns, name)].append(grant)

    # 1. RBAC bindings whose subject kind=ServiceAccount has no backing SA.
    for b in idx["all_bindings"]:
        for s in (b.get("subjects") or []):
            if s.get("kind") != "ServiceAccount":
                continue
            ns, name = s.get("namespace"), s.get("name")
            if not ns or not name or (ns, name) in sas:
                continue
            ref = b.get("roleRef") or {}
            rname = ref.get("name") or ""
            is_scc_role = _scc_name_from_role(rname) is not None
            _add(ns, name, {
                "kind": b["kind"], "name": b["name"],
                "namespace": b.get("namespace"),
                "role": rname, "role_kind": ref.get("kind"),
                "via": "RBAC SCC use grant" if is_scc_role else "RBAC",
                "is_privileged_role": _is_privileged_role_name(rname, idx),
                "is_privileged_scc": _is_privileged_scc_role(rname, idx),
                "severity": _role_severity(rname, idx),
                "creation_ts": b.get("creationTimestamp"),
            })

    # 2. RBAC bindings whose subject kind=User uses the SA principal form.
    #    Older OpenShift tooling sometimes adds SAs as User subjects with
    #    name='system:serviceaccount:<ns>:<sa>' — the same lifecycle gap
    #    applies.
    for b in idx["all_bindings"]:
        for s in (b.get("subjects") or []):
            if s.get("kind") != "User":
                continue
            parsed = _parse_sa_principal(s.get("name") or "")
            if not parsed:
                continue
            ns, name = parsed
            if (ns, name) in sas:
                continue
            ref = b.get("roleRef") or {}
            rname = ref.get("name") or ""
            is_scc_role = _scc_name_from_role(rname) is not None
            _add(ns, name, {
                "kind": b["kind"], "name": b["name"],
                "namespace": b.get("namespace"),
                "role": rname, "role_kind": ref.get("kind"),
                "via": ("RBAC SCC use grant (User-form principal)"
                        if is_scc_role else "RBAC (User-form principal)"),
                "is_privileged_role": _is_privileged_role_name(rname, idx),
                "is_privileged_scc": _is_privileged_scc_role(rname, idx),
                "severity": _role_severity(rname, idx),
                "creation_ts": b.get("creationTimestamp"),
            })

    # 3. SCC.users entries pointing at a missing SA. SCC admission is
    #    independent of RBAC and uses the same name string.
    for scc in (idx.get("sccs_by_name") or {}).values():
        for u in (scc.get("users") or []):
            parsed = _parse_sa_principal(u or "")
            if not parsed:
                continue
            ns, name = parsed
            if (ns, name) in sas:
                continue
            _add(ns, name, {
                "kind": "SCC", "name": scc.get("name", ""),
                "namespace": None,
                "role": scc.get("name", ""), "role_kind": "SCC",
                "via": "SCC user list",
                "is_privileged_role": False,
                "is_privileged_scc": bool(scc.get("allowPrivilegedContainer")),
                "severity": _scc_severity(scc),
                "creation_ts": scc.get("creationTimestamp"),
            })

    out = []
    for (ns, name), items in grants.items():
        ns_present = ns in namespaces
        sev = "low"
        for it in items:
            sev = _max_severity(sev, it["severity"])
        # Namespace-also-missing escalates: a future `oc new-project <ns>`
        # plus a `oc create sa <name>` reactivates everything in this list
        # in a single shell session.
        if not ns_present and sev != "critical":
            sev = _max_severity(sev, "high")
        items.sort(key=lambda g: (g["kind"], g["name"]))
        items.sort(key=lambda g: SEVERITY_ORDER.get(g["severity"], 0),
                   reverse=True)
        items.sort(key=lambda g: g.get("creation_ts") or "", reverse=True)
        rbac_times = [g.get("creation_ts") for g in items
                      if g.get("creation_ts") and g.get("kind") != "SCC"]
        grant_times = rbac_times or [g.get("creation_ts") for g in items
                                     if g.get("creation_ts")]
        # Baseline classification: a "resurrectable" finding in a
        # platform-protected namespace (openshift-*, kube-*, default,
        # ...) is NOT actionable by a normal developer — project-request
        # admission blocks `oc new-project openshift-foo`. Keep the row
        # so admin still sees stale references, but mark it baseline so
        # it stops driving the home dashboard's "looks risky" counters.
        baseline = cf.name_is_baseline(ns)
        baseline_reason = (
            "platform-protected namespace (openshift-*/kube-*/baseline)"
            if baseline else None
        )
        out.append({
            "namespace": ns,
            "name": name,
            "principal": f"{SA_PRINCIPAL_PREFIX}{ns}:{name}",
            "namespace_present": ns_present,
            "grants": items,
            "grant_count": len(items),
            "severity": sev,
            "creation_ts": _latest_timestamp(grant_times),
            "has_cluster_admin": any(g.get("role") == "cluster-admin"
                                      for g in items),
            "has_privileged_scc": any(g.get("is_privileged_scc")
                                       for g in items),
            "has_scc_grant": any(g["via"] == "SCC user list" for g in items),
            # G2 context: auto-created OpenShift project SAs reappear the
            # moment `oc new-project` is run, with no `oc create sa` step.
            # Not a severity bump (severity already reflects role/SCC + ns
            # absence) — just an explicit reviewer signal.
            "auto_created_sa": name in AUTO_CREATED_PROJECT_SAS,
            "baseline": baseline,
            "baseline_reason": baseline_reason,
        })
    out.sort(key=lambda x: (x["namespace"], x["name"]))
    out.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 0),
                            x["has_cluster_admin"],
                            x["has_privileged_scc"]),
             reverse=True)
    out.sort(key=lambda x: x.get("creation_ts") or "", reverse=True)
    return out


def deleted_namespaces_with_grants(idx):
    """Namespaces no longer present as Namespace objects but still
    referenced by surviving grants via SA principals. A future
    `oc new-project <ns>` would re-open the door."""
    by_ns = defaultdict(list)
    for entry in resurrectable_sa_identities(idx):
        if not entry["namespace_present"]:
            by_ns[entry["namespace"]].append(entry)
    out = []
    for ns, principals in sorted(by_ns.items()):
        sev = "low"
        for p in principals:
            sev = _max_severity(sev, p["severity"])
        out.append({
            "namespace": ns,
            "principals": principals,
            "principal_count": len(principals),
            "max_severity": sev,
            "creation_ts": _latest_timestamp(p.get("creation_ts") for p in principals),
        })
    out.sort(key=lambda x: x["namespace"])
    out.sort(key=lambda x: SEVERITY_ORDER.get(x["max_severity"], 0),
             reverse=True)
    out.sort(key=lambda x: x.get("creation_ts") or "", reverse=True)
    return out


def _sccs_granted_by_rule(rule, all_scc_names):
    """Return the SCC names a single role rule grants `use` on.

    Empty/missing `resourceNames` (or "*") means the rule grants every
    SCC — that mirrors Kubernetes RBAC's "no resourceNames filter" semantics.
    """
    verbs = rule.get("verbs") or []
    if "*" not in verbs and "use" not in verbs:
        return ()
    resources = rule.get("resources") or []
    if ("*" not in resources
            and "securitycontextconstraints" not in resources
            and "securitycontextconstraints.security.openshift.io" not in resources):
        return ()
    names = rule.get("resourceNames") or []
    if not names or "*" in names:
        return tuple(all_scc_names)
    return tuple(n for n in names if n in all_scc_names)


def resurrectable_implicit_scc_groups(idx):
    """SCC access that becomes live when a `system:serviceaccounts:<ns>`
    target namespace is recreated. Two independent shapes:

    1. **Direct SCC field** — an SCC's `.groups` list contains
       `system:serviceaccounts:<missing-ns>`.
    2. **RBAC `use` grant** — a (Cluster)RoleBinding's subject is
       `Group/system:serviceaccounts:<missing-ns>` and the bound role
       grants `use` on `securitycontextconstraints` (the shape produced
       by `oc adm policy add-scc-to-group`, which writes RBAC, not the
       SCC field).

    The OpenShift apiserver synthesizes `system:serviceaccounts:<ns>`
    from the SAs currently living in `<ns>`. So either shape sits
    dormant while the namespace is absent — until any user who can
    self-provision a project of that name recreates the namespace.
    OpenShift then auto-creates `default`, `builder`, and `deployer`
    ServiceAccounts in the new namespace, **and every one of them
    instantly satisfies the group entry**. No SA-name guessing required.
    """
    if not idx.get("is_admin", True):
        return []
    namespaces = idx.get("namespaces_by_name") or {}
    sccs = idx.get("sccs_by_name") or {}
    prefix = "system:serviceaccounts:"
    out = []
    seen = set()  # (scc, ns, via_key) for dedup

    def _missing_ns_from_group(name):
        """Return ns if `name` is `system:serviceaccounts:<ns>` AND the
        namespace is missing. Returns None otherwise (including for
        `system:authenticated`, `system:serviceaccounts` bare, etc.).
        Strict prefix match so raw system groups can't be misclassified.

        Baseline-named namespaces (openshift-*/kube-*/default/…) are
        still returned — they get `baseline=True` downstream so they
        stay visible but don't drive home-card actionable counters."""
        if not name or not name.startswith(prefix):
            return None
        ns = name[len(prefix):]
        if not ns or ns in namespaces:
            return None
        return ns

    def _baseline_for_ns(ns):
        if cf.name_is_baseline(ns):
            return True, "platform-protected namespace (openshift-*/kube-*/baseline)"
        return False, None

    # ---- Path A: direct SCC.groups entries -------------------------------
    for scc in sccs.values():
        scc_name = scc.get("name", "")
        for g in (scc.get("groups") or []):
            ns = _missing_ns_from_group(g)
            if ns is None:
                continue
            key = (scc_name, ns, "direct")
            if key in seen:
                continue
            seen.add(key)
            baseline, baseline_reason = _baseline_for_ns(ns)
            out.append({
                "kind": "implicit-sa-group",
                "group": g,
                "namespace": ns,
                "namespace_present": False,
                "scc": scc_name,
                "is_privileged_scc": bool(scc.get("allowPrivilegedContainer")),
                "severity": _scc_severity(scc),
                "via": "SCC group list",
                "source": f"SCC/{scc_name}",
                "source_kind": "scc.groups",
                "role": None,
                "binding_kind": None,
                "binding_name": None,
                "binding_namespace": None,
                "explanation": (
                    "Recreating this project auto-creates the "
                    "default, builder, and deployer ServiceAccounts. "
                    "Every one of them instantly satisfies the SCC's "
                    "implicit-SA group entry — no old SA name needs to "
                    "match. Any pod in the recreated project becomes "
                    "eligible for the SCC."
                ),
                "auto_created_sa": True,
                "creation_ts": scc.get("creationTimestamp"),
                "baseline": baseline,
                "baseline_reason": baseline_reason,
            })

    # ---- Path B: RBAC bindings granting SCC use to a missing-ns group ---
    all_scc_names = list(sccs.keys())
    for binding in idx.get("all_bindings") or []:
        # Short-circuit: only bindings whose any subject is a missing-ns
        # serviceaccounts group are interesting.
        candidate_groups = []
        for s in (binding.get("subjects") or []):
            if s.get("kind") != "Group":
                continue
            ns = _missing_ns_from_group(s.get("name") or "")
            if ns is None:
                continue
            candidate_groups.append((ns, s))
        if not candidate_groups:
            continue

        ref = binding.get("roleRef") or {}
        role_name = ref.get("name") or ""

        # Which SCCs does this binding's role grant `use` on?
        scc_names_granted = set()
        scc_from_role_name = _scc_name_from_role(role_name)
        if scc_from_role_name and scc_from_role_name in sccs:
            scc_names_granted.add(scc_from_role_name)
        role = _resolve_role(ref, binding.get("namespace"), idx)
        if role is not None:
            rules, _ = expand_aggregated_role(role, idx)
            for rule in rules:
                scc_names_granted.update(_sccs_granted_by_rule(rule, all_scc_names))
        if not scc_names_granted:
            continue

        b_kind = binding.get("kind", "")
        b_name = binding.get("name", "")
        b_ns = binding.get("namespace")
        if b_kind == "RoleBinding" and b_ns:
            source = f"{b_kind}/{b_ns}/{b_name}"
        else:
            source = f"{b_kind}/{b_name}"
        via = f"RBAC use grant via {b_kind}/{b_name}"

        for scc_name in scc_names_granted:
            scc = sccs.get(scc_name) or {}
            severity = _scc_severity(scc)
            for ns, subject in candidate_groups:
                key = (scc_name, ns, source)
                if key in seen:
                    continue
                seen.add(key)
                baseline, baseline_reason = _baseline_for_ns(ns)
                out.append({
                    "kind": "implicit-sa-group",
                    "group": subject.get("name"),
                    "namespace": ns,
                    "namespace_present": False,
                    "scc": scc_name,
                    "is_privileged_scc": bool(scc.get("allowPrivilegedContainer")),
                    "severity": severity,
                    "via": via,
                    "source": source,
                    "source_kind": "rbac.use",
                    "role": role_name,
                    "binding_kind": b_kind,
                    "binding_name": b_name,
                    "binding_namespace": b_ns,
                    "explanation": (
                        f"RBAC grants use of SCC/{scc_name} to "
                        f"Group/{subject.get('name')}; recreating that "
                        "namespace auto-creates default/builder/deployer "
                        "SAs that instantly satisfy the group, making "
                        "the SCC grant live."
                    ),
                    "auto_created_sa": True,
                    "creation_ts": binding.get("creationTimestamp"),
                    "baseline": baseline,
                    "baseline_reason": baseline_reason,
                })

    # ---- Path C: RBAC bindings granting SCC use to a missing User or
    # named-Group subject. Shape produced by:
    #   oc adm policy add-scc-to-group  anyuid crazy-anyuid-group   # ghost Group
    #   oc adm policy add-scc-to-user   anyuid crazy-anyuid-user    # ghost User
    # The subject doesn't currently exist on the cluster, but if anyone
    # later creates a User/Group with that exact name (or an OAuth claim
    # maps to it), they instantly inherit SCC use.
    users = idx.get("users_by_name") or {}
    groups = idx.get("groups_by_name") or {}
    sas = idx.get("sas_by_key") or {}
    for binding in idx.get("all_bindings") or []:
        ref = binding.get("roleRef") or {}
        role_name = ref.get("name") or ""
        scc_names_granted = set()
        scc_from_role_name = _scc_name_from_role(role_name)
        if scc_from_role_name and scc_from_role_name in sccs:
            scc_names_granted.add(scc_from_role_name)
        role = _resolve_role(ref, binding.get("namespace"), idx)
        if role is not None:
            rules, _ = expand_aggregated_role(role, idx)
            for rule in rules:
                scc_names_granted.update(_sccs_granted_by_rule(rule, all_scc_names))
        if not scc_names_granted:
            continue
        # Bindings to system: groups never produce a ghost finding here —
        # Path B handles namespace-scoped SA groups; everything else
        # (`system:authenticated`, `system:cluster-admins`, …) is either
        # a virtual group or a stable platform group, not a ghost.
        ghost_user_or_group_subjects = []
        for s in (binding.get("subjects") or []):
            kind = s.get("kind")
            name = s.get("name") or ""
            if not name or name.startswith("system:"):
                continue
            if kind == "User" and name not in users:
                ghost_user_or_group_subjects.append(s)
            elif kind == "Group" and name not in groups:
                ghost_user_or_group_subjects.append(s)
        if not ghost_user_or_group_subjects:
            continue

        b_kind = binding.get("kind", "")
        b_name = binding.get("name", "")
        b_ns = binding.get("namespace")
        if b_kind == "RoleBinding" and b_ns:
            source = f"{b_kind}/{b_ns}/{b_name}"
        else:
            source = f"{b_kind}/{b_name}"
        via = f"RBAC use grant via {b_kind}/{b_name}"

        for scc_name in scc_names_granted:
            scc = sccs.get(scc_name) or {}
            severity = _scc_severity(scc)
            for subject in ghost_user_or_group_subjects:
                sub_kind = subject.get("kind")
                sub_name = subject.get("name")
                key = (scc_name, f"{sub_kind}:{sub_name}", source)
                if key in seen:
                    continue
                seen.add(key)
                out.append({
                    "kind": "ghost-scc-subject",
                    "subject_kind": sub_kind,
                    "subject_name": sub_name,
                    "group": sub_name if sub_kind == "Group" else None,
                    "namespace": None,
                    "namespace_present": None,
                    "scc": scc_name,
                    "is_privileged_scc": bool(scc.get("allowPrivilegedContainer")),
                    "severity": severity,
                    "via": via,
                    "source": source,
                    "source_kind": "rbac.use.ghost-subject",
                    "role": role_name,
                    "binding_kind": b_kind,
                    "binding_name": b_name,
                    "binding_namespace": b_ns,
                    "explanation": (
                        f"RBAC grants use of SCC/{scc_name} to "
                        f"{sub_kind}/{sub_name}, but no {sub_kind} with that "
                        "name exists today. Creating the "
                        f"{sub_kind} (or mapping any OAuth identity to it) "
                        "makes the SCC grant instantly live for that principal."
                    ),
                    "auto_created_sa": False,
                    "creation_ts": binding.get("creationTimestamp"),
                    "baseline": False,
                    "baseline_reason": None,
                })

    # ---- Path D: RBAC bindings granting use on an SCC that DOESN'T
    # exist on the cluster. Shape produced by:
    #   oc adm policy add-scc-to-user  non-existing-scc  some-user
    #   oc adm policy add-scc-to-group NO-SCC-GROUP      some-group
    # OpenShift creates the `system:openshift:scc:<missing>` ClusterRole
    # and binding even though the SCC doesn't exist. The grant is
    # dormant — until an admin creates an SCC with that exact name, at
    # which point every bound subject instantly receives use of it.
    # Severity stays **low** while the target SCC is absent (we can't
    # know its future posture). When the SCC is created, the binding
    # is re-evaluated through Path A/B/C with the actual posture.
    for binding in idx.get("all_bindings") or []:
        ref = binding.get("roleRef") or {}
        role_name = ref.get("name") or ""

        missing_scc_names = set()
        # Any resolved rule with verb=use on SCC referencing a missing name.
        # Do not infer from the role name alone: a RoleBinding can point at a
        # missing roleRef, or a custom ClusterRole can reuse the
        # system:openshift:scc:* prefix without granting SCC use.
        role = _resolve_role(ref, binding.get("namespace"), idx)
        if role is not None:
            rules, _ = expand_aggregated_role(role, idx)
            for rule in rules:
                verbs = rule.get("verbs") or []
                if "*" not in verbs and "use" not in verbs:
                    continue
                resources = rule.get("resources") or []
                if ("*" not in resources
                        and "securitycontextconstraints" not in resources
                        and "securitycontextconstraints.security.openshift.io" not in resources):
                    continue
                for nm in (rule.get("resourceNames") or []):
                    if not nm or nm == "*":
                        continue
                    if nm not in sccs:
                        missing_scc_names.add(nm)
        if not missing_scc_names:
            continue

        b_kind = binding.get("kind", "")
        b_name = binding.get("name", "")
        b_ns = binding.get("namespace")
        if b_kind == "RoleBinding" and b_ns:
            source = f"{b_kind}/{b_ns}/{b_name}"
        else:
            source = f"{b_kind}/{b_name}"
        via = f"RBAC use grant via {b_kind}/{b_name}"

        for missing_scc in missing_scc_names:
            for subject in (binding.get("subjects") or []):
                sub_kind = subject.get("kind")
                sub_name = subject.get("name") or ""
                sub_ns = subject.get("namespace")
                missing_sa_group_ns = None

                # Is the subject itself present?
                sub_present = True
                if sub_kind == "User":
                    sub_present = sub_name in users or sub_name.startswith("system:")
                elif sub_kind == "Group":
                    missing_sa_group_ns = _missing_ns_from_group(sub_name)
                    if missing_sa_group_ns is not None:
                        sub_present = False
                    elif sub_name.startswith("system:"):
                        sub_present = True
                    else:
                        sub_present = sub_name in groups
                elif sub_kind == "ServiceAccount":
                    sub_present = (sub_ns, sub_name) in sas

                key = (missing_scc, sub_kind, sub_name, sub_ns or "", source)
                if key in seen:
                    continue
                seen.add(key)

                explanation = (
                    f"RBAC grants use of SCC/{missing_scc}, but no SCC "
                    f"with that name exists today. Creating an SCC named "
                    f"`{missing_scc}` reactivates this grant instantly for "
                    f"every bound subject."
                )
                if not sub_present:
                    if missing_sa_group_ns:
                        explanation += (
                            f" Note: the bound serviceaccounts group points "
                            f"at missing namespace `{missing_sa_group_ns}` — "
                            "both the SCC and that namespace must come into "
                            "existence before the grant has members."
                        )
                    else:
                        explanation += (
                            f" Note: the bound {sub_kind}/{sub_name} "
                            "does not currently exist either — both the SCC "
                            "and the subject must come into existence "
                            "before the grant takes effect."
                        )

                # Baseline classification: we cannot use binding-name
                # heuristics here because `oc adm policy add-scc-to-*`
                # writes its CRBs under the same `system:openshift:scc:*`
                # convention regardless of who issued the command. The
                # honest signal is subject provenance — if every subject
                # is itself a platform identity (system:* group,
                # baseline SA, bootstrap user), the dormant grant is
                # operator plumbing; otherwise it's a user-created
                # binding worth surfacing as actionable.
                subj_list = binding.get("subjects") or []
                all_subjects_baseline = bool(subj_list) and all(
                    is_baseline_subject(s, idx) for s in subj_list
                )
                if all_subjects_baseline:
                    baseline = True
                    baseline_reason = (
                        "binding's subjects are all platform identities "
                        "— dormant operator plumbing, not a developer-"
                        "exploitable path"
                    )
                else:
                    baseline = False
                    baseline_reason = None

                out.append({
                    "kind": "ghost-scc-target",
                    "scc": missing_scc,
                    "scc_present": False,
                    "subject_kind": sub_kind,
                    "subject_name": sub_name,
                    "subject_namespace": sub_ns,
                    "subject_present": sub_present,
                    "namespace": None,
                    "namespace_present": None,
                    "group": sub_name if sub_kind == "Group" else None,
                    "is_privileged_scc": False,
                    # Low until the SCC is created: we cannot compute
                    # _scc_severity on something that doesn't exist.
                    # When the SCC is created its posture decides
                    # severity via Path A/B/C, escalating automatically.
                    "severity": "low",
                    "via": via,
                    "source": source,
                    "source_kind": "rbac.use.ghost-scc",
                    "role": role_name,
                    "binding_kind": b_kind,
                    "binding_name": b_name,
                    "binding_namespace": b_ns,
                    "explanation": explanation,
                    "auto_created_sa": False,
                    "creation_ts": binding.get("creationTimestamp"),
                    "baseline": baseline,
                    "baseline_reason": baseline_reason,
                })

    out.sort(key=lambda r: (r["scc"], r.get("namespace") or "",
                             r.get("subject_name") or "",
                             r.get("source") or ""))
    out.sort(key=lambda r: SEVERITY_ORDER.get(r["severity"], 0),
             reverse=True)
    return out
