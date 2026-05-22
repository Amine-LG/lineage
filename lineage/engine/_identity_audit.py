"""Identity audit — combines ghost subjects, resurrectable findings,
HTPasswd / IdP state, and User/Identity provenance into one rollup
consumed by the home dashboard, /identity-audit page, and CLI."""

from ._classify import is_baseline_user
from ._ghosts import find_ghost_subjects
from ._resurrectable import (
    _scc_name_from_role,
    _latest_timestamp,
    resurrectable_sa_identities,
    deleted_namespaces_with_grants,
    resurrectable_implicit_scc_groups,
)


def _aggregate_bound_ghosts(rows):
    """Collapse per-binding ghost rows to per-missing-principal rows.

    Two RoleBindings naming the same nonexistent User `editor` should
    appear as ONE bound-ghost finding with `grants=[…2 bindings…]`,
    not as two separate ghost users.

    Each output row carries:
      - subject (kind, name, namespace)
      - grants: [{kind, name, namespace, role, role_kind, scc_use,
                  baseline, creation_ts}] — sorted newest-first
      - grant_count
      - subject_baseline (carried from input — same across rows for a
        given subject)
      - binding_baseline: True iff EVERY grant is baseline
      - category: 'real' if any grant is real, else worst of the rest
      - routine: True iff category != 'real'
      - scc_use_grants: subset of `grants` whose roleRef grants SCC use
      - creation_ts: newest binding timestamp
    """
    by_subject = {}
    order = []
    for r in rows:
        s = r["subject"]
        key = (s.get("kind"), s.get("namespace"), s.get("name"))
        if key not in by_subject:
            order.append(key)
            by_subject[key] = {
                "subject": {"kind": s.get("kind"),
                             "name": s.get("name"),
                             "namespace": s.get("namespace")},
                "subject_baseline": r["subject_baseline"],
                "binding_baseline_all": True,
                "category": None,
                "grants": [],
            }
        agg = by_subject[key]
        b = r["binding"]
        ref = b.get("roleRef") or {}
        role_name = ref.get("name") or ""
        agg["grants"].append({
            "kind": b.get("kind"),
            "name": b.get("name"),
            "namespace": b.get("namespace"),
            "role": role_name,
            "role_kind": ref.get("kind"),
            "scc_use": _scc_name_from_role(role_name) is not None,
            "baseline": r["binding_baseline"],
            "category": r["category"],
            "creation_ts": r.get("creation_ts"),
        })
        if not r["binding_baseline"]:
            agg["binding_baseline_all"] = False

    # Category priority: any 'real' wins; else any 'scc'; else 'routine'.
    priority = {"real": 3, "scc": 2, "routine": 1}
    out = []
    for key in order:
        agg = by_subject[key]
        cat = "routine"
        for g in agg["grants"]:
            if priority.get(g["category"], 0) > priority.get(cat, 0):
                cat = g["category"]
        agg["category"] = cat
        agg["routine"] = cat != "real"
        agg["binding_baseline"] = agg.pop("binding_baseline_all")
        agg["grant_count"] = len(agg["grants"])
        agg["scc_use_grants"] = [g for g in agg["grants"] if g["scc_use"]]
        agg["grants"].sort(
            key=lambda g: (g.get("creation_ts") or "",
                            g.get("namespace") or "",
                            g.get("name") or ""),
            reverse=True)
        agg["creation_ts"] = _latest_timestamp(
            g.get("creation_ts") for g in agg["grants"])
        out.append(agg)

    out.sort(key=lambda a: (a["subject"].get("kind") or "",
                             a["subject"].get("namespace") or "",
                             a["subject"].get("name") or ""))
    out.sort(key=lambda a: a.get("creation_ts") or "", reverse=True)
    return out


def identity_audit(idx, include_baseline_ghosts=False):
    # Resurrectable SA identities are shown in their own section. Exclude
    # those same SA subjects from generic bound ghosts so the dashboard and
    # identity-audit page do not double count the same lifecycle finding.
    resurrectable = resurrectable_sa_identities(idx)
    resurrectable_keys = {(r["namespace"], r["name"]) for r in resurrectable}

    def is_resurrectable_sa_ghost(ghost):
        subject = ghost.get("subject") or {}
        return (subject.get("kind") == "ServiceAccount"
                and (subject.get("namespace"), subject.get("name")) in resurrectable_keys)

    bound_ghost_rows = [
        g for g in find_ghost_subjects(idx, include_baseline=include_baseline_ghosts)
        if not is_resurrectable_sa_ghost(g)
    ]
    all_ghost_rows = [
        g for g in find_ghost_subjects(idx, include_baseline=True)
        if not is_resurrectable_sa_ghost(g)
    ]
    # Aggregate per missing principal — N bindings to the same ghost
    # User/Group/SA produces ONE bound_ghosts entry with grants=[…].
    # The home review tile and the identity-audit table both reflect
    # "distinct missing principals", not "binding row count".
    bound_ghosts = _aggregate_bound_ghosts(bound_ghost_rows)
    all_ghosts = _aggregate_bound_ghosts(all_ghost_rows)
    hidden_ghost_count = len(all_ghosts) - len(bound_ghosts)

    htpasswd_by_user = {h["username"]: h for h in (idx.get("htpasswd_users") or [])}
    user_names = set(idx["users_by_name"].keys())

    # Map IdP name → type from OAuth/cluster. Used to know which providers
    # are HTPasswd-backed regardless of how the user named them.
    idps = (idx.get("oauth_cluster") or {}).get("identityProviders") or []
    idp_type_by_name = {idp.get("name"): idp.get("type") for idp in idps}
    htpasswd_idp_names = {name for name, typ in idp_type_by_name.items()
                          if typ == "HTPasswd"}

    # 1. Latent users — in IdP backing store / Group, no User object yet.
    latent_users = []
    seen_latent = set()

    for username, info in htpasswd_by_user.items():
        if username in user_names or username in seen_latent:
            continue
        latent_users.append({
            "username": username,
            "source": "htpasswd",
            "detail": f"in Secret {info['secret_namespace']}/{info['secret_name']} (idp={info['idp_name']})",
        })
        seen_latent.add(username)

    for g in idx["groups_by_name"].values():
        for member in (g.get("users") or []):
            if not member or member in user_names or member in seen_latent:
                continue
            latent_users.append({
                "username": member,
                "source": "group",
                "detail": f"listed in Group/{g['name']}",
            })
            seen_latent.add(member)

    latent_users.sort(key=lambda x: (x["source"], x["username"]))

    # 2. Phantom users — User+Identity exist, but the HTPasswd backing entry
    #    is gone (or the entire HTPasswd IdP is gone from OAuth/cluster).
    #    Detection works by matching Identity.providerName against IdP names
    #    of type=HTPasswd in OAuth/cluster — the authoritative source. The
    #    "removed from htpasswd" reason is only emitted when the HTPasswd
    #    Secret was actually readable; otherwise we can't tell.
    htpasswd_available = idx.get("htpasswd_available", True)
    phantom_users = []
    for u in idx["users_by_name"].values():
        name = u["name"]
        if is_baseline_user(u, idx):
            continue
        idents = idx["identities_by_user"].get(name) or []
        if not idents:
            continue
        # Find this user's Identities that point to a current HTPasswd IdP
        htpasswd_provider_names = {
            i.get("providerName") for i in idents
            if i.get("providerName") in htpasswd_idp_names
        }
        # Find Identities pointing to providers that NO LONGER exist in OAuth
        orphaned_provider_names = {
            i.get("providerName") for i in idents
            if i.get("providerName") and i.get("providerName") not in idp_type_by_name
        }
        reasons = []
        if (htpasswd_available and htpasswd_provider_names
                and name not in htpasswd_by_user):
            reasons.append(f"removed from htpasswd ({', '.join(sorted(htpasswd_provider_names))})")
        if orphaned_provider_names:
            reasons.append(f"IdP no longer configured ({', '.join(sorted(orphaned_provider_names))})")
        if reasons:
            phantom_users.append({
                "name": name,
                "providers": sorted(htpasswd_provider_names | orphaned_provider_names),
                "reasons": reasons,
            })
    phantom_users.sort(key=lambda x: x["name"])

    # 3. Stranded users — User object, no Identity at all.
    stranded_users = []
    for u in idx["users_by_name"].values():
        name = u["name"]
        if not idx["identities_by_user"].get(name):
            if is_baseline_user(u, idx):
                continue
            stranded_users.append({"name": name})
    stranded_users.sort(key=lambda x: x["name"])

    # 4. Orphan identities — Identity points to a User name that doesn't exist.
    orphan_identities = []
    for ident in (idx.get("identities") or []):
        uname = (ident.get("user") or {}).get("name", "")
        if uname and uname not in user_names:
            orphan_identities.append({
                "identity": ident["name"], "provider": ident.get("providerName"),
                "missing_user": uname,
            })
    orphan_identities.sort(key=lambda x: x["identity"])

    auditable = [i for i in idps if i.get("type") == "HTPasswd"]
    non_auditable = [i for i in idps if i.get("type") != "HTPasswd"]

    deleted_ns = deleted_namespaces_with_grants(idx)
    resurrectable_implicit = resurrectable_implicit_scc_groups(idx)

    # Actionable vs baseline split — the home dashboard's "looks risky"
    # counters use *actionable*, the identity-audit page shows both
    # families but renders baseline rows in a collapsible section.
    resurrectable_actionable = [r for r in resurrectable
                                 if not r.get("baseline")]
    resurrectable_baseline = [r for r in resurrectable
                               if r.get("baseline")]
    resurrectable_implicit_actionable = [r for r in resurrectable_implicit
                                          if not r.get("baseline")]
    resurrectable_implicit_baseline = [r for r in resurrectable_implicit
                                        if r.get("baseline")]

    # "critical" buckets count only actionable rows. A platform SA in
    # openshift-* that happens to be bound to cluster-admin is still
    # platform noise — admission rules prevent a developer from
    # recreating that namespace.
    resurrectable_critical = [r for r in resurrectable_actionable
                               if r["severity"] == "critical"]
    resurrectable_implicit_critical = [r for r in resurrectable_implicit_actionable
                                        if r["severity"] == "critical"]

    identity_total = (len(bound_ghosts) + len(latent_users) + len(phantom_users)
                      + len(stranded_users) + len(orphan_identities))

    return {
        "bound_ghosts": bound_ghosts,
        "hidden_ghost_count": hidden_ghost_count,
        "latent_users": latent_users,
        "phantom_users": phantom_users,
        "stranded_users": stranded_users,
        "orphan_identities": orphan_identities,
        "resurrectable_sas": resurrectable,
        "resurrectable_actionable": resurrectable_actionable,
        "resurrectable_baseline": resurrectable_baseline,
        "resurrectable_critical": resurrectable_critical,
        "resurrectable_implicit_groups": resurrectable_implicit,
        "resurrectable_implicit_actionable": resurrectable_implicit_actionable,
        "resurrectable_implicit_baseline": resurrectable_implicit_baseline,
        "resurrectable_implicit_critical": resurrectable_implicit_critical,
        "deleted_namespaces": deleted_ns,
        "idps_auditable": auditable,
        "idps_non_auditable": non_auditable,
        "identity_total": identity_total,
        # `total` and the home "review items" tile count only ACTIONABLE
        # findings — baseline platform noise stays out of the
        # "needs review" headline.
        "total": (identity_total + len(resurrectable_actionable)
                  + len(resurrectable_implicit_actionable)),
    }
