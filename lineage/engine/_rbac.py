"""Group membership, virtual groups, aggregated ClusterRole expansion,
and rule summarization. Pure data-shape helpers — no cluster I/O."""

from markupsafe import escape


def groups_for_user(username, idx):
    return [g["name"] for g in idx["groups_by_name"].values()
            if username in (g.get("users") or [])]


def rbac_groups_for_user(username, idx):
    """Groups a User belongs to, INCLUDING the virtual groups the apiserver
    assigns at authentication time.

    Virtual groups (`system:authenticated`, `system:authenticated:oauth`)
    are auto-assigned only to principals that successfully authenticate.
    A ghost User (name not in `users_by_name`) has no token, never
    authenticates, and therefore inherits no virtual groups.
    """
    if not username:
        return []
    groups = list(groups_for_user(username, idx))
    user_exists = (idx is not None
                   and username in (idx.get("users_by_name") or {}))
    if user_exists:
        for virtual in ("system:authenticated", "system:authenticated:oauth"):
            if virtual not in groups:
                groups.append(virtual)
    return groups


def groups_for_serviceaccount(name, namespace, idx=None):
    """RBAC groups Kubernetes/OpenShift assign to a ServiceAccount.

    These are not Group objects and will not appear in `oc get groups`, but
    RBAC bindings to them authorize matching ServiceAccounts at request time.

    A ghost SA (not in `sas_by_key`) cannot authenticate and therefore
    inherits no virtual groups — same logic as `rbac_groups_for_user`.
    """
    if not name or not namespace:
        return []
    if idx is not None and (namespace, name) not in (idx.get("sas_by_key") or {}):
        return []
    return [
        "system:authenticated",
        "system:serviceaccounts",
        f"system:serviceaccounts:{namespace}",
    ]


# Auto-membership virtual groups: the apiserver assigns these implicitly to
# every matching principal. Bindings to them grant the named role to a very
# broad audience (every authenticated user, every ServiceAccount, etc.), so
# they tend to dominate a subject's path list. The subject-detail page
# folds reach/paths via these groups into a collapsible section so the
# subject-specific bindings stay readable. `system:masters`, `system:nodes`,
# and `system:bootstrappers` are intentionally NOT included — those require
# explicit client-cert or token authentication and are not auto-membership.
SYSTEM_AUTO_MEMBERSHIP_GROUPS = frozenset({
    "system:authenticated",
    "system:unauthenticated",
    "system:authenticated:oauth",
    "system:serviceaccounts",
})


def is_system_virtual_group(name):
    """True iff `name` is a virtual group the apiserver auto-assigns.

    Used to split subject-detail tables into "primary" (direct + real-group)
    and "via system virtual group" (collapsible) sections.
    """
    if not name:
        return False
    if name in SYSTEM_AUTO_MEMBERSHIP_GROUPS:
        return True
    return name.startswith("system:serviceaccounts:")


# ============================================================ #
# Aggregated ClusterRole expansion                             #
# ============================================================ #

def expand_aggregated_role(role, idx):
    if not role.get("aggregationRule"):
        return list(role.get("rules") or []), []
    selectors = (role["aggregationRule"] or {}).get("clusterRoleSelectors", []) or []
    components = []
    rules = []
    for cr in idx["cluster_roles_by_name"].values():
        if cr["name"] == role["name"]:
            continue
        if _labels_match_any(cr.get("labels") or {}, selectors):
            components.append(cr)
            for r in (cr.get("rules") or []):
                rules.append({**r, "_from": cr["name"]})
    return rules, components


def _labels_match_any(labels, selectors):
    for sel in selectors:
        if _labels_match_selector(labels, sel or {}):
            return True
    return False


def _labels_match_selector(labels, selector):
    ml = selector.get("matchLabels", {}) or {}
    exprs = selector.get("matchExpressions", []) or []
    if not ml and not exprs:
        return True
    if any(labels.get(k) != v for k, v in ml.items()):
        return False
    for expr in exprs:
        key = expr.get("key")
        op = expr.get("operator")
        vals = expr.get("values") or []
        present = key in labels
        value = labels.get(key)
        if op == "In":
            if not present or value not in vals:
                return False
        elif op == "NotIn":
            if present and value in vals:
                return False
        elif op == "Exists":
            if not present:
                return False
        elif op == "DoesNotExist":
            if present:
                return False
        else:
            return False
    return True


def _expand_group_subject(group_name, idx):
    """Enumerate the principals a Group subject grants access TO.

    Returns a list of subject dicts (each shaped like a regular RBAC
    subject) that gain access by virtue of group membership:

    - Named Group with `.users` set → one User entry per member
    - `system:serviceaccounts:<ns>` → one ServiceAccount entry per SA in
      that namespace (bounded by what the index sees)
    - `system:authenticated` / `system:authenticated:oauth` → NOT
      enumerated (cardinality = every user on the cluster, which would
      explode the namespace access table; the Group row itself is shown
      with a "broad" note instead)
    - `system:masters`, `system:nodes`, `system:cluster-admins`,
      `system:serviceaccounts` (bare) → NOT enumerated (virtual /
      structural groups with no enumerable per-cluster membership)

    Each returned dict carries a `_derived_from` slot so callers can
    render the source group on derived rows.
    """
    if not group_name:
        return []
    sa_prefix = "system:serviceaccounts:"
    if group_name.startswith(sa_prefix):
        scope_ns = group_name[len(sa_prefix):]
        if not scope_ns:
            return []
        # Enumerate SAs that actually exist in that namespace
        out = []
        for sa_ns, sa_name in (idx.get("sas_by_key") or {}):
            if sa_ns != scope_ns:
                continue
            out.append({"kind": "ServiceAccount", "name": sa_name,
                         "namespace": sa_ns,
                         "_derived_from": group_name})
        return out
    if group_name in ("system:authenticated", "system:authenticated:oauth",
                       "system:serviceaccounts", "system:masters",
                       "system:nodes", "system:cluster-admins"):
        return []
    # Named (real) Group — enumerate its `.users` field
    group = (idx.get("groups_by_name") or {}).get(group_name)
    if not group:
        return []
    out = []
    for member in (group.get("users") or []):
        if not member:
            continue
        out.append({"kind": "User", "name": member,
                     "_derived_from": group_name})
    return out


def _resolve_role(role_ref, binding_namespace, idx):
    kind = role_ref.get("kind")
    name = role_ref.get("name")
    if kind == "ClusterRole":
        return idx["cluster_roles_by_name"].get(name)
    if kind == "Role":
        return idx["roles_by_key"].get((binding_namespace, name))
    return None


def summarize_rules(rules):
    """Compress rules into a skimmable summary."""
    api_groups = set()
    resources = set()
    verbs = set()
    nonres = set()
    for r in rules:
        for g in (r.get("apiGroups") or [""]):
            api_groups.add(g if g else "core")
        for res in (r.get("resources") or []):
            if res:
                resources.add(res)
        for v in (r.get("verbs") or []):
            verbs.add(v)
        for u in (r.get("nonResourceURLs") or []):
            nonres.add(u)
    return {
        "api_groups": sorted(api_groups),
        "resources": sorted(resources),
        "verbs": sorted(verbs),
        "nonresource_urls": sorted(nonres),
        "total_rules": len(rules),
        "wildcard": "*" in verbs,
    }


# ============================================================ #
# Virtual / system Group description                           #
# ============================================================ #

def describe_virtual_group(name, idx=None):
    """Describe a virtual / system Group purely from cluster state.

    No per-name dictionary. The function recognizes one well-known
    *structural* convention — `system:serviceaccounts[:<ns>]` — because
    the apiserver computes membership for that name from observable
    index state (the namespaces and ServiceAccounts that already exist).
    Every other `system:*` name gets the same generic note describing
    the mechanism, since the authoritative answer to "what does this
    name grant?" is the list of bindings rendered elsewhere on the page.
    """
    if not name or not name.startswith("system:"):
        return None
    generic = (
        "Synthesized by the apiserver — no <code>Group</code> object exists; "
        "membership is computed per-request from the authenticated identity. "
        "The bindings below are the authoritative description of what this "
        "name currently grants."
    )
    idx = idx or {}
    prefix = "system:serviceaccounts:"
    if name.startswith(prefix):
        ns = name[len(prefix):] or ""
        if not ns:
            return generic
        ns_html = escape(ns)
        ns_present = ns in (idx.get("namespaces_by_name") or {})
        sa_count = sum(1 for sa_ns, _ in (idx.get("sas_by_key") or {})
                       if sa_ns == ns)
        presence = ("namespace present" if ns_present
                    else "namespace not visible — would activate if recreated")
        count = (f"; {sa_count} ServiceAccount"
                 f"{'s' if sa_count != 1 else ''} currently in "
                 f"<code>{ns_html}</code>") if sa_count else ""
        return (f"{generic} By the <code>system:serviceaccounts:&lt;ns&gt;</code>"
                f" convention this name resolves to every ServiceAccount in "
                f"<code>{ns_html}</code> ({presence}{count}).")
    if name == "system:serviceaccounts":
        total = len(idx.get("sas_by_key") or {})
        return (f"{generic} By the <code>system:serviceaccounts</code> "
                f"convention this name resolves to every ServiceAccount in "
                f"every namespace ({total} currently visible).")
    return generic


def virtual_groups_referenced(idx):
    """Sorted list of virtual/system Group names that any RBAC binding or
    SCC.groups list references but for which no Group object exists.

    Kubernetes (and OpenShift) synthesize these groups for authenticated
    requests; they will never appear in `oc get groups`. Surfacing them in
    the Subjects inventory makes them discoverable instead of relying on a
    URL-guess like /subject/Group/system:authenticated:oauth.
    """
    real = set((idx.get("groups_by_name") or {}).keys())
    out = set()
    for b in (idx.get("all_bindings") or []):
        for s in (b.get("subjects") or []):
            if s.get("kind") != "Group":
                continue
            name = s.get("name") or ""
            if name.startswith("system:") and name not in real:
                out.add(name)
    for scc in (idx.get("sccs_by_name") or {}).values():
        for name in (scc.get("groups") or []):
            if name and name.startswith("system:") and name not in real:
                out.add(name)
    return sorted(out)
