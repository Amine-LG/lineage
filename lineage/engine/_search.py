"""Search index for the top-nav jump-to feature.

Builds a compact list of navigable items purely from the existing
in-memory engine index. Read-only, no cluster reads, no I/O. Each
item carries only the fields the navigation UI needs — no raw
Kubernetes objects, no annotations/labels wholesale, no Secret data.

The token list is what the client matches against. Keeping it
explicit and small means the JSON stays light and there is no way
to accidentally search a private field.
"""

import re
from urllib.parse import quote


# ReplicaSet names that pods are owned by look like "<deployment>-<hash>"
# where <hash> is a hex-like alphanumeric pad-hash (typically 9–11 chars).
# Stripping it recovers the Deployment name without needing the RS
# objects themselves in the index.
_RS_HASH_RE = re.compile(r"-[a-z0-9]{9,11}$")


def _q(s):
    """URL-encode a single path segment safely."""
    return quote(s or "", safe="")


def _ns_query(ns):
    return f"?namespace={_q(ns)}" if ns else ""


def _user_item(user):
    name = user.get("name") or ""
    if not name:
        return None
    return {
        "id": f"subject:User:{name}",
        "kind": "User",
        "display": name,
        "namespace": None,
        "description": "User",
        "url": f"/subject/User/{_q(name)}",
        "tokens": [name],
    }


def _group_item(group):
    name = group.get("name") or ""
    if not name:
        return None
    virtual = bool(group.get("virtual"))
    return {
        "id": f"subject:Group:{name}",
        "kind": "Group",
        "display": name,
        "namespace": None,
        "description": "Virtual group" if virtual else "Group",
        "url": f"/subject/Group/{_q(name)}",
        "tokens": [name],
    }


def _sa_item(sa):
    name = sa.get("name") or ""
    ns = sa.get("namespace") or ""
    if not name or not ns:
        return None
    principal = f"system:serviceaccount:{ns}:{name}"
    return {
        "id": f"subject:ServiceAccount:{ns}:{name}",
        "kind": "ServiceAccount",
        "display": principal,
        "namespace": ns,
        "description": f"ServiceAccount in {ns}",
        "url": f"/subject/ServiceAccount/{_q(name)}{_ns_query(ns)}",
        "tokens": [name, ns, principal, "serviceaccount"],
    }


def _namespace_item(ns):
    name = ns.get("name") or ""
    if not name:
        return None
    return {
        "id": f"namespace:{name}",
        "kind": "Namespace",
        "display": name,
        "namespace": name,
        "description": "Namespace",
        "url": f"/namespace/{_q(name)}",
        "tokens": [name],
    }


def _scc_item(scc):
    name = scc.get("name") or ""
    if not name:
        return None
    return {
        "id": f"scc:{name}",
        "kind": "SCC",
        "display": name,
        "namespace": None,
        "description": "SecurityContextConstraints",
        "url": f"/scc/{_q(name)}",
        "tokens": [name, "scc"],
    }


def _clusterrole_item(cr):
    name = cr.get("name") or ""
    if not name:
        return None
    return {
        "id": f"clusterrole:{name}",
        "kind": "ClusterRole",
        "display": name,
        "namespace": None,
        "description": "ClusterRole",
        "url": f"/clusterrole/{_q(name)}",
        "tokens": [name],
    }


def _role_item(role):
    name = role.get("name") or ""
    ns = role.get("namespace") or ""
    if not name or not ns:
        return None
    return {
        "id": f"role:{ns}:{name}",
        "kind": "Role",
        # Same-name roles can exist in many namespaces (a single dropdown
        # of "console-operator" rows is useless). Showing <ns>/<name>
        # disambiguates at a glance.
        "display": f"{ns}/{name}",
        "namespace": ns,
        "description": f"Role in {ns}",
        "url": f"/role/{_q(ns)}/{_q(name)}",
        "tokens": [name, ns],
    }


def _binding_item(binding):
    name = binding.get("name") or ""
    if not name:
        return None
    kind = binding.get("kind") or ""
    ns = binding.get("namespace") or None
    if kind == "ClusterRoleBinding":
        return {
            "id": f"clusterrolebinding:{name}",
            "kind": "ClusterRoleBinding",
            "display": name,
            "namespace": None,
            "description": "ClusterRoleBinding",
            "url": f"/permission-grants?q={_q(name)}",
            "tokens": [name],
        }
    if kind == "RoleBinding":
        return {
            "id": f"rolebinding:{ns or ''}:{name}",
            "kind": "RoleBinding",
            "display": name,
            "namespace": ns,
            "description": f"RoleBinding in {ns}" if ns else "RoleBinding",
            "url": f"/permission-grants?q={_q(name)}",
            "tokens": [name] + ([ns] if ns else []),
        }
    return None


def _workload_from_pod(pod):
    """Return (kind, name) for the pod's underlying workload, or None.

    ReplicaSet → Deployment (recovered by stripping the RS hash suffix).
    DaemonSet/StatefulSet/Job/CatalogSource → used as-is.
    Pods with no owner are kept as standalone Pod entries.
    """
    refs = pod.get("ownerReferences") or []
    if not refs:
        name = pod.get("name") or ""
        return ("Pod", name) if name else None
    ref = refs[0]
    owner_kind = ref.get("kind") or "Pod"
    owner_name = ref.get("name") or ""
    if not owner_name:
        return None
    if owner_kind == "ReplicaSet":
        stripped = _RS_HASH_RE.sub("", owner_name)
        if stripped and stripped != owner_name:
            return ("Deployment", stripped)
        # Fall through with the RS name if no hash suffix was found
        return ("ReplicaSet", owner_name)
    return (owner_kind, owner_name)


def _workload_items(idx):
    """Deduped workload entries from pod owners + raw Jobs + CronJobs.

    Pods themselves are not indexed individually — their names are
    ephemeral and the abstraction the user actually searches for is the
    workload (Deployment, DaemonSet, …). The destination is the
    namespace page where that workload's pods are listed.
    """
    items = []
    seen = set()

    def emit(ns, kind, name):
        if not (ns and name and kind):
            return
        key = (ns, kind, name)
        if key in seen:
            return
        seen.add(key)
        items.append({
            "id": f"workload:{kind}:{ns}:{name}",
            "kind": "Workload",
            # Same workload name can recur across namespaces
            # (e.g. "apiserver" in openshift-apiserver and openshift-oauth-apiserver).
            # <ns>/<name> disambiguates without forcing the user to scan
            # the meta line.
            "display": f"{ns}/{name}",
            "namespace": ns,
            "description": f"{kind} in {ns}",
            "url": f"/namespace/{_q(ns)}",
            "tokens": [name, ns, kind.lower()],
        })

    for pod in (idx.get("pods") or []):
        ns = pod.get("namespace")
        wl = _workload_from_pod(pod)
        if wl:
            emit(ns, wl[0], wl[1])

    for job in (idx.get("jobs") or []):
        emit(job.get("namespace"), "Job", job.get("name"))

    for cj in (idx.get("cronjobs") or []):
        emit(cj.get("namespace"), "CronJob", cj.get("name"))

    return items


def _virtual_group_items(idx):
    """OpenShift virtual groups (system:authenticated,
    system:serviceaccounts:<ns>, …) have no Group object in the
    cluster. The engine's `virtual_groups_referenced` helper already
    collects them from both RBAC binding subjects AND SCC.groups
    lists — reusing it guarantees search has the same coverage as the
    rest of Lineage (Subjects inventory, etc.).
    """
    from ._rbac import virtual_groups_referenced
    items = []
    for name in virtual_groups_referenced(idx):
        items.append({
            "id": f"subject:Group:{name}",
            "kind": "Group",
            "display": name,
            "namespace": None,
            "description": "Virtual group",
            "url": f"/subject/Group/{_q(name)}",
            "tokens": [name],
        })
    return items


def _image_short_name(ref):
    """Cheap, allocation-free shortening for tokens.

    Image refs look like 'registry/<path>/<name>[:tag|@sha256:...]'. The
    last path segment (without tag/digest) is what humans search for.
    """
    if not ref:
        return ""
    base = ref.rsplit("/", 1)[-1]
    # Strip tag or digest
    base = base.split("@", 1)[0]
    base = base.split(":", 1)[0]
    return base


def _image_items(image_inventory):
    """One entry per distinct image ref. Uses the already-computed
    inventory so no extra cluster reads are triggered."""
    items = []
    for row in (image_inventory or []):
        ref = row.get("image") or ""
        if not ref:
            continue
        registry = row.get("registry") or ""
        short = _image_short_name(ref)
        pod_count = row.get("pod_count") or 0
        tokens = [ref]
        if short and short != ref:
            tokens.append(short)
        if registry and registry not in tokens:
            tokens.append(registry)
        items.append({
            "id": f"image:{ref}",
            "kind": "Image",
            "display": ref,
            "namespace": None,
            "description": (f"Image · {pod_count} pod"
                            f"{'s' if pod_count != 1 else ''}"
                            f" · {registry}" if registry
                            else f"Image · {pod_count} pod"
                                 f"{'s' if pod_count != 1 else ''}"),
            "url": f"/image?ref={_q(ref)}",
            "tokens": tokens,
        })
    return items


def _imagestream_items(imagestreams):
    items = []
    for s in (imagestreams or []):
        name = s.get("name") or ""
        ns = s.get("namespace") or ""
        if not name or not ns:
            continue
        repo = s.get("dockerImageRepository") or ""
        tokens = [name, ns, "imagestream"]
        if repo and repo not in tokens:
            tokens.append(repo)
        items.append({
            "id": f"imagestream:{ns}:{name}",
            "kind": "ImageStream",
            "display": f"{ns}/{name}",
            "namespace": ns,
            "description": f"ImageStream in {ns}",
            "url": f"/namespace/{_q(ns)}",
            "tokens": tokens,
        })
    return items


def _identity_items(identities):
    """Identities link to their associated User detail page so the
    search lands on something navigable."""
    items = []
    for ident in (identities or []):
        ident_name = ident.get("name") or ""
        provider = ident.get("providerName") or ""
        user = (ident.get("user") or {}).get("name") or ""
        if not ident_name or not user:
            continue
        tokens = [ident_name, user]
        if provider and provider != user:
            tokens.append(provider)
        # Description: avoid awkward duplication like
        # "Identity for developer (provider: developer)".
        if provider and provider != user:
            description = f"Identity ({provider}) for {user}"
        else:
            description = f"Identity for {user}"
        items.append({
            "id": f"identity:{ident_name}",
            "kind": "Identity",
            "display": ident_name,
            "namespace": None,
            "description": description,
            "url": f"/subject/User/{_q(user)}",
            "tokens": tokens,
        })
    return items


def search_index(idx, image_inventory=None):
    """Return a flat list of navigable items from the existing index.

    Pure: reads idx in memory; performs no cluster calls. Each item is
    a small dict with the allowlisted fields the navigation UI needs.

    `image_inventory` is the already-computed list from
    `engine.image_inventory(idx)`. The route handler passes it in to
    avoid recomputing it; callers without it (tests, ad-hoc usage) get a
    safe default of an empty inventory.
    """
    items = []

    for u in (idx.get("users_by_name") or {}).values():
        item = _user_item(u)
        if item:
            items.append(item)

    for g in (idx.get("groups_by_name") or {}).values():
        item = _group_item(g)
        if item:
            items.append(item)

    for sa in (idx.get("sas_by_key") or {}).values():
        item = _sa_item(sa)
        if item:
            items.append(item)

    for ns in (idx.get("namespaces_by_name") or {}).values():
        item = _namespace_item(ns)
        if item:
            items.append(item)

    for scc in (idx.get("sccs_by_name") or {}).values():
        item = _scc_item(scc)
        if item:
            items.append(item)

    for cr in (idx.get("cluster_roles_by_name") or {}).values():
        item = _clusterrole_item(cr)
        if item:
            items.append(item)

    for role in (idx.get("roles_by_key") or {}).values():
        item = _role_item(role)
        if item:
            items.append(item)

    for b in (idx.get("all_bindings") or []):
        item = _binding_item(b)
        if item:
            items.append(item)

    items.extend(_identity_items(idx.get("identities") or []))
    items.extend(_virtual_group_items(idx))
    items.extend(_workload_items(idx))
    items.extend(_imagestream_items(idx.get("imagestreams") or []))
    items.extend(_image_items(image_inventory or []))

    items.sort(key=lambda i: (i["kind"], i["display"]))
    return items
