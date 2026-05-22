"""Image, ImageStream, registry, cross-namespace binding, image-puller,
aggregation, and SCC-use interpretation helpers.

Most of these are about images, but a handful of RBAC helpers
(`cross_namespace_bindings`, `bindings_for_role`,
`cross_ns_bindings_for_namespace`, `bindings_referencing_sa`,
`surviving_grants_for_absent_sa`, `aggregation_parents_for_role`,
`scc_use_interpretation`) live here because they are called by the
namespace / image-puller / SCC-detail views and ship together with the
image data path.
"""

from collections import defaultdict

from .. import classifier as cf
from ._constants import SA_PRINCIPAL_PREFIX
from ._classify import (
    is_baseline_namespace,
    is_unknown_namespace,
    is_baseline_subject,
    is_unknown_subject,
    is_baseline_binding,
    is_unknown_binding,
)
from ._rbac import _labels_match_any
from ._resurrectable import (
    _is_privileged_role_name,
    resurrectable_sa_identities,
)


def _pod_images(pod):
    spec = pod.get("spec") or {}
    statuses = {cs.get("name"): cs for cs in (pod.get("containerStatuses") or [])}
    for c in (spec.get("containers") or []):
        cs = statuses.get(c.get("name")) or {}
        yield {
            "image": c.get("image", ""),
            "actual_image": cs.get("image") or c.get("image", ""),
            "imageID": cs.get("imageID", ""),
            "container": c.get("name"),
        }
    for c in (spec.get("initContainers") or []):
        cs = statuses.get(c.get("name")) or {}
        yield {
            "image": c.get("image", ""),
            "actual_image": cs.get("image") or c.get("image", ""),
            "imageID": cs.get("imageID", ""),
            "container": c.get("name"),
        }


def image_inventory(idx):
    by_image = defaultdict(lambda: {"pods": [], "imageID": None})
    for pod in (idx.get("pods") or []):
        ns_baseline = is_baseline_namespace(pod.get("namespace"), idx)
        ns_unknown = (not ns_baseline) and is_unknown_namespace(
            pod.get("namespace"), idx)
        spec = pod.get("spec") or {}
        sa = (spec.get("serviceAccountName")
              or spec.get("serviceAccount") or "default")
        scc = (pod.get("annotations") or {}).get("openshift.io/scc")
        for ci in _pod_images(pod):
            ref = ci["actual_image"] or ci["image"]
            if not ref:
                continue
            entry = by_image[ref]
            entry["pods"].append({
                "name": pod.get("name"),
                "namespace": pod.get("namespace"),
                "container": ci["container"],
                "spec_image": ci["image"],
                "actual_image": ci["actual_image"],
                "imageID": ci["imageID"],
                "resolved_digest": _digest_of(ci["imageID"]),
                "phase": pod.get("phase"),
                "baseline_ns": ns_baseline,
                "unknown_ns": ns_unknown,
                "service_account": sa,
                "scc": scc,
            })
            if ci.get("imageID"):
                entry["imageID"] = ci["imageID"]

    out = []
    for ref, info in by_image.items():
        registry = cf.registry_for(ref)
        classification = cf.classify_image(ref)
        any_user = any(not p["baseline_ns"] and not p["unknown_ns"]
                        for p in info["pods"])
        any_unknown = any(p["unknown_ns"] for p in info["pods"])
        any_baseline = any(p["baseline_ns"] for p in info["pods"])
        out.append({
            "image": ref, "registry": registry,
            "classification": classification, "user_used": any_user,
            "unknown_used": any_unknown,
            "baseline_used": any_baseline,
            "pod_count": len(info["pods"]), "pods": info["pods"],
            "imageID": info["imageID"],
            "resolved_digest": _digest_of(info["imageID"]),
        })
    out.sort(key=lambda x: (not x["user_used"], not x["unknown_used"],
                             not x["baseline_used"],
                            -x["pod_count"], x["image"]))
    return out


def registry_summary(inventory):
    by_reg = defaultdict(lambda: {
        "classification": "unknown", "image_count": 0,
        "pod_count": 0, "user_used": False,
        "unknown_used": False, "baseline_used": False,
    })
    for img in inventory:
        r = by_reg[img["registry"]]
        r["classification"] = img["classification"]
        r["image_count"] += 1
        r["pod_count"] += img["pod_count"]
        if img["user_used"]:
            r["user_used"] = True
        if img.get("unknown_used"):
            r["unknown_used"] = True
        if img.get("baseline_used"):
            r["baseline_used"] = True
    out = [{"registry": k, **v} for k, v in by_reg.items()]
    out.sort(key=lambda r: (not r["user_used"], not r["unknown_used"],
                             not r["baseline_used"],
                            -r["pod_count"], r["registry"]))
    return out


def _digest_of(image_id):
    """Extract sha256:<hex> from a containerStatus imageID, or None."""
    if not image_id:
        return None
    s = image_id
    if s.startswith("docker-pullable://"):
        s = s[len("docker-pullable://"):]
    if "@sha256:" in s:
        return s.split("@", 1)[1]
    return None


def _spec_image_key(image_ref):
    if not image_ref:
        return None
    return image_ref.strip()


def image_drift(idx):
    """
    Detect 'stale by digest': pods that reference the same spec image tag
    but resolved to different digests. Indicates a mutable tag (':latest',
    ':1.25', etc.) was repushed under a running fleet.

    Skips digest-pinned spec refs (image@sha256:...) — drift impossible.
    Skips containers without a reported imageID (not yet running).
    """
    by_spec = defaultdict(list)
    for pod in (idx.get("pods") or []):
        ns_baseline = is_baseline_namespace(pod.get("namespace"), idx)
        ns_unknown = (not ns_baseline) and is_unknown_namespace(
            pod.get("namespace"), idx)
        for ci in _pod_images(pod):
            spec_ref = ci.get("image") or ""
            key = _spec_image_key(spec_ref)
            if not key:
                continue
            if "@sha256:" in spec_ref:
                continue
            digest = _digest_of(ci.get("imageID"))
            if not digest:
                continue
            by_spec[key].append({
                "digest": digest,
                "pod": pod.get("name"),
                "namespace": pod.get("namespace"),
                "container": ci.get("container"),
                "baseline_ns": ns_baseline,
                "unknown_ns": ns_unknown,
            })

    drifted = []
    for spec_ref, entries in by_spec.items():
        digests = {e["digest"] for e in entries}
        if len(digests) <= 1:
            continue
        by_digest = defaultdict(list)
        for e in entries:
            by_digest[e["digest"]].append(e)
        any_user = any(not e["baseline_ns"] and not e["unknown_ns"]
                        for e in entries)
        any_unknown = any(e["unknown_ns"] for e in entries)
        any_baseline = any(e["baseline_ns"] for e in entries)
        drifted.append({
            "image": spec_ref,
            "registry": cf.registry_for(spec_ref),
            "user_used": any_user,
            "unknown_used": any_unknown,
            "baseline_used": any_baseline,
            "digest_count": len(digests),
            "pod_count": len(entries),
            "digests": [
                {"digest": d, "pods": pods}
                for d, pods in sorted(
                    by_digest.items(), key=lambda kv: -len(kv[1])
                )
            ],
        })
    drifted.sort(key=lambda x: (not x["user_used"], not x["unknown_used"],
                                 not x["baseline_used"],
                                -x["pod_count"], x["image"]))
    return drifted


def imagestream_usage(idx):
    streams = idx.get("imagestreams") or []
    out = []
    for s in streams:
        repo = s.get("dockerImageRepository") or ""
        public = s.get("publicDockerImageRepository") or ""
        used_by = []
        if repo or public:
            for pod in (idx.get("pods") or []):
                for ci in _pod_images(pod):
                    ref = ci["actual_image"] or ci["image"] or ""
                    if (repo and repo in ref) or (public and public in ref):
                        used_by.append({"namespace": pod.get("namespace"),
                                         "pod": pod.get("name"),
                                         "container": ci["container"]})
                        break
        baseline = is_baseline_namespace(s.get("namespace"), idx)
        unknown = (not baseline) and is_unknown_namespace(s.get("namespace"), idx)
        out.append({"name": s.get("name"), "namespace": s.get("namespace"),
                    "baseline": baseline, "unknown": unknown,
                    "spec_tags": s.get("spec_tags") or [],
                    "status_tags": s.get("status_tags") or [],
                    "dockerImageRepository": repo,
                    "creation_ts": s.get("creationTimestamp"),
                    "used_by": used_by, "use_count": len(used_by)})
    out.sort(key=lambda x: (x["baseline"], -x["use_count"], x["name"]))
    out.sort(key=lambda x: x.get("creation_ts") or "", reverse=True)
    return out


def cross_namespace_bindings(idx):
    """
    RoleBindings whose subject is a ServiceAccount living in a DIFFERENT
    namespace than the binding itself.
    """
    out = []
    for b in idx["all_bindings"]:
        if b["kind"] != "RoleBinding":
            continue
        b_ns = b.get("namespace")
        for s in (b.get("subjects") or []):
            if s.get("kind") != "ServiceAccount":
                continue
            sa_ns = s.get("namespace")
            if not sa_ns or not b_ns or sa_ns == b_ns:
                continue
            sub_baseline = is_baseline_subject(s, idx)
            bind_baseline = is_baseline_binding(b, idx)
            baseline = sub_baseline and bind_baseline
            unknown = (not baseline) and (is_unknown_subject(s, idx)
                                            or is_unknown_binding(b, idx))
            ref = b.get("roleRef") or {}
            out.append({
                "subject": s,
                "binding": {"kind": b["kind"], "name": b["name"], "namespace": b_ns},
                "role": ref.get("name"), "role_kind": ref.get("kind"),
                "sa_namespace": sa_ns,
                "binding_namespace": b_ns,
                "is_privileged": _is_privileged_role_name(ref.get("name"), idx),
                "baseline": baseline,
                "unknown": unknown,
                "creation_ts": b.get("creationTimestamp"),
            })
    out.sort(key=lambda x: (not x["is_privileged"],
                            x["sa_namespace"], x["binding_namespace"]))
    out.sort(key=lambda x: x.get("creation_ts") or "", reverse=True)
    out.sort(key=lambda x: x["baseline"])
    return out


def bindings_for_role(role_kind, role_name, role_namespace, idx):
    """Inverse lookup: every binding (CRB/RB) referencing this exact role."""
    out = []
    for b in idx["all_bindings"]:
        ref = b.get("roleRef") or {}
        if ref.get("kind") != role_kind or ref.get("name") != role_name:
            continue
        # For Roles, must match namespace too. ClusterRole bindings ignore ns.
        if role_kind == "Role" and b.get("namespace") != role_namespace:
            continue
        out.append(b)
    out.sort(key=lambda b: (b.get("creationTimestamp") or "", b.get("name") or ""),
             reverse=True)
    return out


def image_puller_grants(idx):
    """
    system:image-puller and system:image-builder bindings outside the
    OpenShift defaults. Defaults filtered out:
      - Group/system:serviceaccounts:<ns> in <ns>
      - ServiceAccount/builder in <ns> (default builder grants itself system:image-builder)
      - ServiceAccount/deployer in <ns> (default deployer)
      - ServiceAccount/default in <ns>
    Whatever's left is interesting.
    """
    target_roles = {"system:image-puller", "system:image-builder"}
    default_sa_names = {"builder", "deployer", "default"}
    out = []
    for b in idx["all_bindings"]:
        if b["kind"] != "RoleBinding":
            continue
        ref = b.get("roleRef") or {}
        if ref.get("name") not in target_roles:
            continue
        b_ns = b.get("namespace")
        for s in (b.get("subjects") or []):
            kind = s.get("kind")
            name = s.get("name") or ""
            sa_ns = s.get("namespace") if kind == "ServiceAccount" else None
            cross_ns = bool(sa_ns and b_ns and sa_ns != b_ns)

            # Default 1: per-ns serviceaccounts group binding
            if (kind == "Group"
                    and name == f"system:serviceaccounts:{b_ns}"):
                continue
            # Default 2: built-in SAs in their own namespace
            if (kind == "ServiceAccount"
                    and name in default_sa_names
                    and sa_ns == b_ns):
                continue

            sub_baseline = is_baseline_subject(s, idx)
            sub_unknown = (not sub_baseline) and is_unknown_subject(s, idx)
            out.append({
                "subject": s,
                "binding": {"kind": b["kind"], "name": b["name"], "namespace": b_ns},
                "role": ref.get("name"),
                "namespace": b_ns,
                "cross_namespace": cross_ns,
                "baseline": sub_baseline,
                "unknown": sub_unknown,
                "creation_ts": b.get("creationTimestamp"),
            })
    out.sort(key=lambda x: (not x["cross_namespace"], x["role"], x["namespace"]))
    out.sort(key=lambda x: x.get("creation_ts") or "", reverse=True)
    out.sort(key=lambda x: x["baseline"])
    return out


# ============================================================ #
# Cross-namespace reach (namespace detail)                     #
# ============================================================ #

def cross_ns_bindings_for_namespace(ns, idx):
    """Bindings that link this namespace to other namespaces.

    incoming_rbs : RoleBindings in OTHER namespaces whose SA subjects live
                   in this namespace.
    outgoing_rbs : RoleBindings in THIS namespace whose SA subjects live in
                   other namespaces.
    incoming_crbs: ClusterRoleBindings naming a SA from this namespace.
    """
    incoming_rbs = []
    outgoing_rbs = []
    incoming_crbs = []
    for b in idx.get("all_bindings") or []:
        kind = b.get("kind")
        b_ns = b.get("namespace")
        for s in (b.get("subjects") or []):
            if s.get("kind") != "ServiceAccount":
                continue
            sa_ns = s.get("namespace")
            if not sa_ns:
                continue
            ref = b.get("roleRef") or {}
            entry = {
                "subject": {"kind": "ServiceAccount",
                             "name": s.get("name"),
                             "namespace": sa_ns},
                "binding": {"kind": kind, "name": b.get("name"),
                             "namespace": b_ns},
                "role": ref.get("name") or "",
                "role_kind": ref.get("kind") or "",
                "creation_ts": b.get("creationTimestamp"),
            }
            if kind == "ClusterRoleBinding" and sa_ns == ns:
                incoming_crbs.append(entry)
            elif kind == "RoleBinding":
                if sa_ns == ns and b_ns and b_ns != ns:
                    incoming_rbs.append(entry)
                elif b_ns == ns and sa_ns != ns:
                    outgoing_rbs.append(entry)
    for lst in (incoming_rbs, outgoing_rbs, incoming_crbs):
        lst.sort(key=lambda e: (e["binding"].get("namespace") or "",
                                 e["binding"].get("name") or ""))
    return {"incoming_rbs": incoming_rbs,
            "outgoing_rbs": outgoing_rbs,
            "incoming_crbs": incoming_crbs}


def images_running_in_namespace(ns, idx):
    """Distinct image refs running in this namespace, with pod counts."""
    counts = defaultdict(int)
    for pod in (idx.get("pods") or []):
        if pod.get("namespace") != ns:
            continue
        seen = set()
        for ci in _pod_images(pod):
            ref = ci.get("actual_image") or ci.get("image") or ""
            if not ref or ref in seen:
                continue
            seen.add(ref)
            counts[ref] += 1
    out = [{"image": ref, "registry": cf.registry_for(ref),
            "pod_count": n} for ref, n in counts.items()]
    out.sort(key=lambda x: (-x["pod_count"], x["image"]))
    return out


# ============================================================ #
# Reverse bindings for a ServiceAccount (subject detail)       #
# ============================================================ #

def bindings_referencing_sa(name, namespace, idx):
    """Every binding that authenticates this ServiceAccount, split by scope.

    Includes the older User-form principal (`system:serviceaccount:<ns>:<sa>`)
    that some bindings still use.
    """
    principal = f"{SA_PRINCIPAL_PREFIX}{namespace}:{name}"
    rbs_same_ns = []
    rbs_cross_ns = []
    crbs = []
    for b in idx.get("all_bindings") or []:
        matched = False
        for s in (b.get("subjects") or []):
            if (s.get("kind") == "ServiceAccount"
                    and s.get("name") == name
                    and s.get("namespace") == namespace):
                matched = True
                break
            if (s.get("kind") == "User"
                    and s.get("name") == principal):
                matched = True
                break
        if not matched:
            continue
        ref = b.get("roleRef") or {}
        entry = {
            "kind": b.get("kind"),
            "name": b.get("name"),
            "namespace": b.get("namespace"),
            "role": ref.get("name") or "",
            "role_kind": ref.get("kind") or "",
            "creation_ts": b.get("creationTimestamp"),
        }
        if b.get("kind") == "ClusterRoleBinding":
            crbs.append(entry)
        elif b.get("namespace") == namespace:
            rbs_same_ns.append(entry)
        else:
            rbs_cross_ns.append(entry)
    # Newest first by creationTimestamp; namespace and name are
    # deterministic tiebreakers.
    for lst in (rbs_same_ns, rbs_cross_ns, crbs):
        lst.sort(key=lambda e: (e.get("namespace") or "", e.get("name") or ""))
        lst.sort(key=lambda e: e.get("creation_ts") or "", reverse=True)
    return {"rbs_same_ns": rbs_same_ns,
            "rbs_cross_ns": rbs_cross_ns,
            "crbs": crbs}


def images_for_sa(name, namespace, idx):
    """Deduped image refs across pods running as the given SA."""
    # `pods_for_sa` still lives in __init__ — late import to avoid
    # cycle while __init__ is loading this module.
    from . import pods_for_sa
    counts = defaultdict(int)
    for pod in pods_for_sa(name, namespace, idx):
        seen = set()
        for ci in _pod_images(pod):
            ref = ci.get("actual_image") or ci.get("image") or ""
            if not ref or ref in seen:
                continue
            seen.add(ref)
            counts[ref] += 1
    out = [{"image": ref, "registry": cf.registry_for(ref),
            "pod_count": n} for ref, n in counts.items()]
    out.sort(key=lambda x: (-x["pod_count"], x["image"]))
    return out


def surviving_grants_for_absent_sa(name, namespace, idx):
    """If this SA is missing/resurrectable, return the surviving-grants entry
    from resurrectable_sa_identities. Otherwise None."""
    for entry in resurrectable_sa_identities(idx):
        if entry["name"] == name and entry["namespace"] == namespace:
            return entry
    return None


# ============================================================ #
# ClusterRole detail helpers                                   #
# ============================================================ #

def aggregation_parents_for_role(role, idx):
    """ClusterRoles whose aggregationRule selectors match this role's labels.

    The inverse of expand_aggregated_role's component view: given a candidate
    component role, return the parents that would pull it in.
    """
    labels = role.get("labels") or {}
    if not labels:
        return []
    parents = []
    for cr in (idx.get("cluster_roles_by_name") or {}).values():
        if cr.get("name") == role.get("name"):
            continue
        rule = cr.get("aggregationRule")
        if not rule:
            continue
        selectors = (rule or {}).get("clusterRoleSelectors") or []
        if _labels_match_any(labels, selectors):
            parents.append({"name": cr.get("name"),
                            "creation_ts": cr.get("creationTimestamp")})
    parents.sort(key=lambda p: p["name"])
    return parents


def scc_use_interpretation(rules, idx):
    """For a rule list, return the SCCs that the rules grant `use` on.

    Each entry: {scc_name, allowPrivilegedContainer, present}.
    Returns [] if no rule grants SCC use.
    """
    out = []
    seen = set()
    sccs = idx.get("sccs_by_name") or {}
    for r in (rules or []):
        verbs = r.get("verbs") or []
        resources = r.get("resources") or []
        api_groups = r.get("apiGroups") or [""]
        wildcard_verb = "*" in verbs
        wildcard_resource = "*" in resources
        wildcard_group = "*" in api_groups
        if not (wildcard_verb or "use" in verbs):
            continue
        if not (wildcard_resource
                or "securitycontextconstraints" in resources
                or "securitycontextconstraints.security.openshift.io" in resources):
            continue
        if not (wildcard_group
                or "security.openshift.io" in api_groups
                or "" in api_groups):
            # Only security.openshift.io owns SCCs; bail if a rule is
            # explicitly scoped to a different group.
            continue
        names = r.get("resourceNames") or []
        if not names:
            names = sorted(sccs.keys())
        for nm in names:
            if nm in seen:
                continue
            seen.add(nm)
            scc = sccs.get(nm)
            out.append({
                "scc_name": nm,
                "present": scc is not None,
                "allowPrivilegedContainer":
                    bool((scc or {}).get("allowPrivilegedContainer")),
            })
    out.sort(key=lambda e: (not e["allowPrivilegedContainer"], e["scc_name"]))
    return out


# ============================================================ #
# Image detail helpers                                         #
# ============================================================ #

def _normalize_image_repo(image_ref):
    """Strip tag/digest, return the repository portion.

    'docker.io/library/nginx:1.25' -> 'docker.io/library/nginx'
    'a/b@sha256:abc'               -> 'a/b'
    'host:5000/proj/img:tag'       -> 'host:5000/proj/img'
    """
    if not image_ref:
        return None
    ref = image_ref.strip()
    if "@" in ref:
        ref = ref.split("@", 1)[0]
    # A tag colon is the last colon after the last '/'. A port colon comes
    # before any '/', so splitting on the last segment is safe.
    if "/" in ref:
        head, last = ref.rsplit("/", 1)
        if ":" in last:
            last = last.split(":", 1)[0]
        return f"{head}/{last}"
    if ":" in ref:
        return ref.split(":", 1)[0]
    return ref


def imagestream_for_image(image_ref, idx):
    """Return the ImageStream record whose repository matches this image
    exactly. Conservative — no substring matching, no false positives."""
    repo = _normalize_image_repo(image_ref)
    if not repo:
        return None
    for s in (idx.get("imagestreams") or []):
        for key in ("dockerImageRepository", "publicDockerImageRepository"):
            sref = (s.get(key) or "").strip()
            if sref and sref == repo:
                return s
    return None


def digest_siblings_for_image(image_ref, idx):
    """Other resolved digests seen for this image ref (drift context).

    Returns the digests bound to other pods of this image entry,
    excluding the inventory entry's primary digest. Pods whose spec ref
    is already digest-pinned are skipped because drift is impossible by
    construction. Bounded by digest count per image entry.
    """
    entry = next((e for e in image_inventory(idx)
                   if e.get("image") == image_ref), None)
    if entry is None:
        return []
    primary = entry.get("resolved_digest")
    counts = defaultdict(int)
    for p in entry.get("pods") or []:
        if "@sha256:" in (p.get("spec_image") or ""):
            continue
        d = p.get("resolved_digest")
        if not d:
            continue
        counts[d] += 1
    siblings = [{"digest": d, "pod_count": n}
                for d, n in counts.items()
                if d != primary]
    siblings.sort(key=lambda x: (-x["pod_count"], x["digest"]))
    return siblings


def image_pods_by_namespace(pods):
    """Compact per-namespace summary of image pod entries.

    Input: the pod list from an image_inventory entry. Output: per-namespace
    {namespace, pod_count, container_count, any_baseline}.
    """
    by_ns = defaultdict(lambda: {"pod_count": 0, "container_count": 0,
                                   "any_baseline": False})
    pod_keys = defaultdict(set)
    for p in pods or []:
        ns = p.get("namespace") or ""
        row = by_ns[ns]
        row["container_count"] += 1
        if p.get("baseline_ns"):
            row["any_baseline"] = True
        pod_keys[ns].add(p.get("name"))
    for ns, names in pod_keys.items():
        by_ns[ns]["pod_count"] = len(names)
    out = [{"namespace": ns, **row} for ns, row in by_ns.items()]
    out.sort(key=lambda x: (x["any_baseline"], -x["pod_count"],
                             x["namespace"]))
    return out
