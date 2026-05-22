"""Baseline / unknown classification for namespaces, subjects, bindings,
users, and ServiceAccounts.

Layered model: each namespace gets a category (system / openshift /
project / unknown) plus the list of signals that produced that category.
The boolean is_baseline_namespace is a thin reduction kept for backward
compat. See classifier.classify_namespace_obj for the rule set and
rationale.
"""

from .. import classifier as cf


def _cluster_install_ts(idx):
    """Best-effort cluster install timestamp from the index. Used by the
    namespace classifier's install-window fallback rule.

    Prefers `kube-system.creationTimestamp` (always set at install time).
    Falls back to the earliest creationTimestamp across baseline-named
    namespaces. Returns None if nothing usable is available — the
    install-window rule then simply does not fire."""
    nses = idx.get("namespaces_by_name") or {}
    ksys = nses.get("kube-system")
    if ksys and ksys.get("creationTimestamp"):
        return ksys["creationTimestamp"]
    candidates = []
    for ns in nses.values():
        ts = ns.get("creationTimestamp")
        if not ts:
            continue
        if (ns.get("name") in cf.BASELINE_NAMESPACES
                or any((ns.get("name") or "").startswith(p)
                        for p in cf.BASELINE_NAMESPACE_PREFIXES)):
            candidates.append(ts)
    return min(candidates) if candidates else None


def classify_namespace(ns_name, idx):
    """Rich classification — category and the list of signals that produced
    it. Falls back to a conservative 'unknown' result if the namespace is
    not in idx (e.g. non-admin views without project access)."""
    ns_obj = (idx.get("namespaces_by_name") or {}).get(ns_name)
    install_ts = _cluster_install_ts(idx)
    if ns_obj is None:
        if cf.name_is_baseline(ns_name):
            return cf.classify_namespace_obj(
                {"name": ns_name, "labels": {}, "annotations": {}},
                install_ts=install_ts)
        return {"category": "unknown", "signals": [], "owner": None,
                "is_baseline": False, "is_unknown": True,
                "is_user_owned": False}
    return cf.classify_namespace_obj(ns_obj, install_ts=install_ts)


def is_baseline_namespace(ns_name, idx):
    """Boolean reduction — True only for system / openshift now.
    Unknown namespaces have their own flag via `is_unknown_namespace`."""
    return classify_namespace(ns_name, idx)["is_baseline"]


def is_unknown_namespace(ns_name, idx):
    """True for namespaces that no signal could classify confidently
    (typically created via `oc create namespace` without a requester
    annotation). Mutually exclusive with is_baseline_namespace."""
    return classify_namespace(ns_name, idx).get("is_unknown", False)


def is_mine_namespace(ns_summary, current_user):
    """Per-viewer ownership filter for the Namespaces page Mine chip.

    Differs from `is_baseline_namespace`, which classifies globally as
    user-team-vs-cluster. Mine is per-viewer: a project requested by
    `developer` is still a project (Projects chip), but it is NOT mine
    when I'm logged in as `alice`. Matches `project` namespaces whose
    `openshift.io/requester` equals the logged-in user (from `oc whoami`).
    """
    return (ns_summary.get("category") == "project"
            and ns_summary.get("owner") == current_user)


def is_baseline_subject(subject, idx):
    """Subject is baseline by name pattern, by namespace (for SAs),
    or by known cluster-bootstrap user name.

    The implicit-SA Group `system:serviceaccounts:<ns>` is special: its
    membership IS that namespace's ServiceAccounts. So its baseline-ness
    derives from the namespace it points at, not the system:* prefix
    alone — a binding to `system:serviceaccounts:hello` (where `hello`
    is a user namespace) should NOT be hidden as baseline.
    """
    if subject.get("kind") == "Group":
        name = subject.get("name") or ""
        prefix = "system:serviceaccounts:"
        if name.startswith(prefix):
            group_ns = name[len(prefix):]
            if group_ns:
                return is_baseline_namespace(group_ns, idx)
    if cf.is_baseline_subject(subject):
        return True
    if subject.get("kind") == "User" and _is_crc_default_htpasswd_user(
            subject.get("name"), idx):
        return True
    if subject.get("kind") == "ServiceAccount":
        ns = subject.get("namespace")
        if ns and is_baseline_namespace(ns, idx):
            return True
    return False


def is_baseline_binding(binding, idx):
    """Inline rules — does NOT delegate to cf.is_baseline_binding because
    that classifier's all-subjects-baseline check uses the bare
    cf.is_baseline_subject, which blankets every `system:*` Group as
    baseline. With idx in hand, the implicit-SA Group
    `system:serviceaccounts:<ns>` derives baseline-ness from the ns, so
    we must run the subject check with the engine wrapper here.

    A binding is not baseline just because it lives in `default`,
    `openshift-*`, or `kube-*`. RoleBindings in those namespaces can still
    name human users and should remain visible.
    """
    if not binding:
        return False
    name = binding.get("name") or ""
    # 1. Binding NAME pattern — platform-installed bindings carry known
    #    name prefixes (`system:*`, `kube-apiserver`, …).
    if any(name.startswith(p) for p in cf.BASELINE_BINDING_PREFIXES):
        return True
    # 2. Object-level provenance signals — managed-by labels, operator
    #    annotations / ownerReferences. These mean "an operator installed
    #    this resource" regardless of where it lives.
    if cf._has_managed_label(binding.get("labels")):
        return True
    if cf._has_managed_annotation(binding.get("annotations")):
        return True
    if cf._has_operator_owner(binding.get("ownerReferences")):
        return True
    # 3. Every subject is itself baseline — a binding that grants only
    #    platform identities (e.g. all `system:*` groups) is platform
    #    plumbing even when its own name and namespace are unremarkable.
    subjects = binding.get("subjects") or []
    if subjects and all(is_baseline_subject(s, idx) for s in subjects):
        return True
    return False


def is_baseline_user(user, idx):
    """A User is baseline only by system/bootstrap name.

    A normal User object with no Identity is a stranded user, not baseline.
    """
    name = user.get("name", "")
    if cf.is_baseline_subject({"kind": "User", "name": name}):
        return True
    return _is_crc_default_htpasswd_user(name, idx)


CRC_DEFAULT_HTPASSWD_USERS = frozenset({"developer", "kubeadmin"})


def _is_crc_default_htpasswd_user(name, idx):
    """Treat CRC's default HTPasswd users as baseline without hiding any
    arbitrary enterprise user with the same name.

    OpenShift Users are keyed only by username, so provider provenance is the
    only useful discriminator. Keep this strict: exactly the default
    HTPasswd IdP named `developer` and exactly one matching Identity. This
    uses OAuth + Identity metadata only; it does not depend on reading the
    HTPasswd Secret, so degraded Secret visibility does not change the result.
    If a second IdP also maps to the same User, classify it as non-baseline so
    the reviewer sees the ambiguity.
    """
    if name not in CRC_DEFAULT_HTPASSWD_USERS:
        return False
    idps = (idx.get("oauth_cluster") or {}).get("identityProviders") or []
    has_crc_idp = any(
        idp.get("name") == "developer" and idp.get("type") == "HTPasswd"
        for idp in idps
    )
    if not has_crc_idp:
        return False
    identities = (idx.get("identities_by_user") or {}).get(name) or []
    if len(identities) != 1:
        return False
    ident = identities[0]
    return (ident.get("providerName") == "developer"
            and ident.get("providerUserName") == name)


def is_baseline_sa(sa, idx):
    if is_baseline_namespace(sa.get("namespace"), idx):
        return True
    return cf.is_baseline_resource(sa)


def is_unknown_sa(sa, idx):
    """An SA inherits 'unknown' status from its namespace when that
    namespace is unknown and the SA itself is not platform-managed."""
    if is_baseline_sa(sa, idx):
        return False
    return is_unknown_namespace(sa.get("namespace"), idx)


def is_unknown_subject(subject, idx):
    """Subject is unknown if its OWN namespace context is unknown:
      - ServiceAccount living in an unknown namespace.
      - The implicit-SA Group `system:serviceaccounts:<ns>` whose ns is
        unknown (it resolves to every SA in that namespace).
    Regular Users and Groups never become unknown — their bucket is
    driven by identity/provenance, not by where a binding happens to
    live. See `who_can` / `_subject_binding_is_unknown`.
    """
    kind = subject.get("kind")
    if kind == "ServiceAccount":
        if is_baseline_subject(subject, idx):
            return False
        ns = subject.get("namespace")
        if not ns:
            return False
        # Match resurrectable-SA semantics: when the namespace is deleted
        # (absent from the index) AND its name is not baseline, we don't
        # claim 'unknown' — we don't know what category it was, but the
        # resurrectable angle is the meaningful signal. is_unknown_namespace
        # would otherwise blanket-classify ANY missing namespace as unknown,
        # which contradicts /subjects where the same SA shows up as Yours.
        if ns not in (idx.get("namespaces_by_name") or {}):
            return False
        return is_unknown_namespace(ns, idx)
    if kind == "Group":
        name = subject.get("name") or ""
        prefix = "system:serviceaccounts:"
        if name.startswith(prefix):
            group_ns = name[len(prefix):]
            if not group_ns:
                return False
            if is_baseline_namespace(group_ns, idx):
                return False
            return is_unknown_namespace(group_ns, idx)
    return False


def is_unknown_binding(binding, idx):
    """Binding is unknown when it lives in an unknown namespace and
    isn't already baseline. ClusterRoleBindings have no namespace and
    therefore cannot be unknown."""
    if is_baseline_binding(binding, idx):
        return False
    if binding.get("kind") != "RoleBinding":
        return False
    ns = binding.get("namespace")
    if not ns:
        return False
    return is_unknown_namespace(ns, idx)


def is_baseline_absent_sa(namespace, idx):
    """Classify a missing ServiceAccount principal without pretending an
    absent namespace is automatically user-owned.

    Present namespaces use the normal namespace classifier. Deleted namespace
    names that are clearly platform-owned stay baseline by name; deleted
    non-platform names are treated as user-managed residue so they remain
    visible in the default Subjects bucket.
    """
    if not namespace:
        return True
    if cf.name_is_baseline(namespace):
        return True
    if namespace in (idx.get("namespaces_by_name") or {}):
        return is_baseline_namespace(namespace, idx)
    return False


def is_unknown_absent_sa(namespace, idx):
    """The missing-SA principal is 'unknown' when its (present) namespace
    is in the unknown bucket. Absent namespaces fall through to yours."""
    if not namespace:
        return False
    if cf.name_is_baseline(namespace):
        return False
    if namespace in (idx.get("namespaces_by_name") or {}):
        return is_unknown_namespace(namespace, idx)
    return False
