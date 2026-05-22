"""Effective permissions and reverse who-can lookup.

`effective_permissions` walks a subject's bindings → roles → rules and
returns a list of `EffectivePath` records (subject → ... → rule scope)
ready for the subject-detail UI.

`who_can` is the reverse: given (verb, resource[, namespace, name]), it
returns every subject whose bindings grant that combination.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from ._constants import PREFERRED_RESOURCE_API_GROUPS, CLUSTER_SCOPED_RBAC_RESOURCES
from ._classify import is_baseline_subject, is_baseline_binding, is_unknown_subject
from ._ghosts import is_ghost
from ._rbac import (
    rbac_groups_for_user,
    groups_for_serviceaccount,
    expand_aggregated_role,
    summarize_rules,
    _resolve_role,
)


@dataclass
class PathStep:
    kind: str
    name: str
    reason: str
    namespace: Optional[str] = None


@dataclass
class EffectivePath:
    subject: dict
    steps: list
    role: dict
    rules: list
    scope: str
    components: list = field(default_factory=list)
    via_group: Optional[str] = None
    bindings: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)


def effective_permissions(subject_kind, subject_name, subject_namespace=None, idx=None):
    if idx is None:
        from . import index  # local import to avoid circular package init
        idx = index()
    raw = []

    def collect(b, via_group):
        role_ref = b.get("roleRef") or {}
        role = _resolve_role(role_ref, b.get("namespace"), idx)
        if role is None:
            return
        rules, components = expand_aggregated_role(role, idx)
        scope = "cluster" if b["kind"] == "ClusterRoleBinding" \
            else f"namespace:{b.get('namespace')}"
        key = (via_group, role_ref.get("kind"), role_ref.get("name"),
               role.get("namespace"), scope)
        raw.append((key, b, via_group, role, rules, components, scope, role_ref))

    for b in idx["all_bindings"]:
        for s in (b.get("subjects") or []):
            if _subject_matches(s, subject_kind, subject_name, subject_namespace):
                collect(b, None)

    if subject_kind == "User":
        for gname in rbac_groups_for_user(subject_name, idx):
            for b in idx["all_bindings"]:
                for s in (b.get("subjects") or []):
                    if s.get("kind") == "Group" and s.get("name") == gname:
                        collect(b, gname)

    if subject_kind == "ServiceAccount":
        for gname in groups_for_serviceaccount(
                subject_name, subject_namespace, idx):
            for b in idx["all_bindings"]:
                for s in (b.get("subjects") or []):
                    if s.get("kind") == "Group" and s.get("name") == gname:
                        collect(b, gname)

    grouped = defaultdict(list)
    order = []
    for e in raw:
        if e[0] not in grouped:
            order.append(e[0])
        grouped[e[0]].append(e)

    paths = []
    for k in order:
        entries = grouped[k]
        _, rep_b, via_group, role, rules, components, scope, role_ref = entries[0]
        steps = [PathStep(subject_kind, subject_name, "self", subject_namespace)]
        if via_group:
            steps.append(PathStep("Group", via_group, "memberOf"))
        steps.append(PathStep(rep_b["kind"], rep_b["name"], "binds", rep_b.get("namespace")))
        steps.append(PathStep(role_ref.get("kind"), role_ref.get("name"), "ref",
                              role.get("namespace")))
        paths.append(EffectivePath(
            subject={"kind": subject_kind, "name": subject_name, "namespace": subject_namespace},
            steps=steps, role=role, rules=rules, scope=scope,
            components=components, via_group=via_group,
            bindings=[{"kind": e[1]["kind"], "name": e[1]["name"],
                       "namespace": e[1].get("namespace")} for e in entries],
            summary=summarize_rules(rules),
        ))
    return paths


def _subject_matches(s, kind, name, namespace):
    if s.get("kind") != kind:
        return False
    if s.get("name") != name:
        return False
    if kind == "ServiceAccount":
        return s.get("namespace") == namespace
    return True


# ============================================================ #
# Reverse: who-can                                             #
# ============================================================ #

def who_can(verb, resource, namespace=None, idx=None, name=None):
    if idx is None:
        from . import index  # local import to avoid circular package init
        idx = index()
    matches = []
    target_api_groups = _api_groups_for_resource(resource, idx)
    include_role_bindings = _role_bindings_can_grant_resource(resource)
    for b in idx["all_bindings"]:
        if b["kind"] == "RoleBinding" and not include_role_bindings:
            continue
        role = _resolve_role(b.get("roleRef") or {}, b.get("namespace"), idx)
        if role is None:
            continue
        rules, _ = expand_aggregated_role(role, idx)
        if not any(_rule_allows(r, verb, resource, target_api_groups, name)
                   for r in rules):
            continue
        if b["kind"] == "RoleBinding" and namespace and b.get("namespace") != namespace:
            continue
        bind_baseline = is_baseline_binding(b, idx)
        for s in (b.get("subjects") or []):
            sub_baseline = is_baseline_subject(s, idx)
            baseline = bind_baseline or sub_baseline
            # Subject-driven 'unknown': a human User bound by a RoleBinding
            # in an Unclassified namespace must NOT itself be Unclassified.
            # The binding's namespace is shown separately in the row.
            unknown = (not baseline) and is_unknown_subject(s, idx)
            if s.get("kind") == "Group":
                group = idx["groups_by_name"].get(s.get("name"))
                if group is None:
                    matches.append({"subject": s, "binding": b,
                                    "ghost": not (s.get("name") or "").startswith("system:"),
                                    "via_group": None,
                                    "baseline": baseline,
                                    "unknown": unknown})
                    continue
                matches.append({"subject": s, "binding": b, "ghost": False,
                                "via_group": None, "baseline": baseline,
                                "unknown": unknown})
                for member in (group.get("users") or []):
                    matches.append({"subject": {"kind": "User", "name": member},
                                    "binding": b, "ghost": False,
                                    "via_group": group["name"],
                                    "baseline": baseline,
                                    "unknown": unknown})
            else:
                matches.append({"subject": s, "binding": b,
                                "ghost": is_ghost(s, idx),
                                "via_group": None,
                                "baseline": baseline,
                                "unknown": unknown})
    return matches


def _resource_key(resource):
    return (resource or "").strip().lower().split("/", 1)[0]


def _preferred_api_groups_for_resource(resource):
    resource = (resource or "").strip().lower()
    if resource in PREFERRED_RESOURCE_API_GROUPS:
        return set(PREFERRED_RESOURCE_API_GROUPS[resource])
    base = _resource_key(resource)
    if base in PREFERRED_RESOURCE_API_GROUPS:
        return set(PREFERRED_RESOURCE_API_GROUPS[base])
    return None


def _role_bindings_can_grant_resource(resource):
    base = _resource_key(resource)
    if not base or base == "*":
        return True
    if base == "securitycontextconstraints":
        return True
    return base not in CLUSTER_SCOPED_RBAC_RESOURCES


def _api_groups_for_resource(resource, idx):
    if resource == "*":
        return {"*"}
    preferred = _preferred_api_groups_for_resource(resource)
    if preferred is not None:
        return preferred
    api_groups = set()

    def collect(rules):
        for rule in rules or []:
            if resource in (rule.get("resources") or []):
                api_groups.update(rule.get("apiGroups") or [""])

    for cr in idx["cluster_roles_by_name"].values():
        rules, _ = expand_aggregated_role(cr, idx)
        collect(rules)
    for role in idx["roles_by_key"].values():
        collect(role.get("rules") or [])
    return api_groups or {""}


def _rule_allows(rule, verb, resource, target_api_groups=None, name=None):
    verbs = rule.get("verbs") or []
    if "*" not in verbs and verb not in verbs:
        return False
    resources = rule.get("resources") or []
    if "*" not in resources and resource not in resources:
        return False
    resource_names = rule.get("resourceNames") or []
    if resource_names and "*" not in resource_names:
        if not name or name not in resource_names:
            return False
    api_groups = set(rule.get("apiGroups") or [""])
    if resource == "*":
        return "*" in api_groups
    if "*" in api_groups:
        return True
    target_api_groups = set(target_api_groups or {""})
    if "*" in target_api_groups:
        return True
    if api_groups.isdisjoint(target_api_groups):
        return False
    return True


def all_resources_seen(idx):
    seen = set()
    for cr in idx["cluster_roles_by_name"].values():
        rules, _ = expand_aggregated_role(cr, idx)
        for r in rules:
            for res in (r.get("resources") or []):
                if res:
                    seen.add(res)
    for r in idx["roles_by_key"].values():
        for rule in (r.get("rules") or []):
            for res in (rule.get("resources") or []):
                if res:
                    seen.add(res)
    return sorted(seen)
