"""
Heuristics for distinguishing cluster-managed (baseline) from user-managed
(yours) resources.

For NAMESPACES this module classifies each namespace into one of four
categories:

    system    — Kubernetes core (kube-system, kube-public, kube-node-lease,
                default, kube-*) and install-time infrastructure with no
                other markers.
    openshift — OpenShift core platform (openshift, openshift-*).
    project   — Created via `oc new-project` or the OpenShift Console
                (carries openshift.io/requester). The only built-in path
                into the user-owned bucket; every other "user-looking"
                annotation has been observed on cluster-installed
                namespaces too.
    unknown   — No signal — surfaced in its own chip so it can be reviewed
                rather than guessed into another category.

Each rule looks at one piece of metadata and returns a Signal(category,
reason) or None. Rules are evaluated in order; if more than one fires, the
highest category in CATEGORY_PRIORITY wins. Every fired signal is kept and
displayed on the namespace detail page, so every classification is auditable.

Extending the rules: append a callable `(ns_obj, *_) -> Signal | None` to
SIGNAL_RULES. The `*_` lets rules ignore future positional/keyword args.

For NON-namespace resources (bindings, SAs, etc.) the simpler waterfall
classifier below handles baseline detection.
"""

from collections import namedtuple
from datetime import datetime


# Install-time namespace grace window.
#
# Some OpenShift/CRC infrastructure namespaces are created shortly after the
# core cluster namespaces, and may not carry requester/project ownership
# signals. In CRC 4.19.8, hostpath-provisioner was observed about 25 hours
# after kube-system's creationTimestamp. A 24h window missed it; 25h caught it.
#
# Keep this conservative: larger values such as 48h/72h may reduce Unknown
# noise in slow installs, but can also classify early user-created namespaces
# as system/install-time infrastructure. This rule only runs when no stronger
# name/requester/signal rule matched. If the cluster install/reference
# timestamp is not visible, the rule is skipped and the namespace remains
# Unknown.
INSTALL_WINDOW_HOURS = 25


# ============================================================ #
# Namespace name patterns (used by both namespace classifier   #
# and the non-namespace baseline classifier)                   #
# ============================================================ #

BASELINE_NAMESPACE_PREFIXES = ("openshift-", "kube-")
BASELINE_NAMESPACES = {
    "default", "kube-public", "kube-system", "kube-node-lease",
    "openshift", "openshift-infra", "openshift-node",
}


# ============================================================ #
# Subject / binding classifier                                 #
# ============================================================ #

MANAGED_LABEL_KEYS = (
    "app.kubernetes.io/managed-by",
    "olm.managed",
    "olm.operatornamespace",
    "operators.coreos.com/",
    "openshift.io/run-level",
    "openshift.io/cluster-monitoring",
)

MANAGED_ANNOTATION_KEYS = (
    "olm.operatorGroup",
    "operatorframework.io/properties",
)

SYSTEM_SUBJECT_PREFIXES = ("system:",)
BASELINE_BINDING_PREFIXES = ("system:", "kubeadmin", "kube-apiserver",
                             "kube-controller-manager", "kube-scheduler")

SCC_BINDING_PREFIXES = ("system:openshift:scc:",)

BOOTSTRAP_USER_NAMES = {
    "kube-apiserver",
    "kube-controller-manager",
    "kube-scheduler",
    "kube-aggregator",
}


def is_scc_binding(binding):
    """OpenShift SCC bindings — admission controller, not RBAC."""
    if not binding:
        return False
    name = binding.get("name") or ""
    return any(name.startswith(p) for p in SCC_BINDING_PREFIXES)


def _has_managed_label(labels):
    if not labels:
        return False
    for key in labels:
        for managed in MANAGED_LABEL_KEYS:
            if key == managed or key.startswith(managed):
                return True
    return False


def _has_managed_annotation(annotations):
    if not annotations:
        return False
    for key in annotations:
        for managed in MANAGED_ANNOTATION_KEYS:
            if key == managed or key.startswith(managed):
                return True
    return False


def _has_operator_owner(refs):
    for ref in (refs or []):
        api = (ref.get("apiVersion") or "").lower()
        if any(s in api for s in ("operator", "openshift.io", "config.openshift.io")):
            return True
    return False


def name_is_baseline(name):
    """For namespace names. NOT for resource names in general — 'default' is
    a baseline namespace but also a valid SA name in user namespaces."""
    if not name:
        return False
    if name in BASELINE_NAMESPACES:
        return True
    if any(name.startswith(p) for p in BASELINE_NAMESPACE_PREFIXES):
        return True
    return False


def is_baseline_namespace(ns_name):
    """Pure name-pattern check. Use classify_namespace_obj for full
    classification (which adds the requester signal)."""
    return name_is_baseline(ns_name)


def is_baseline_resource(obj):
    """Generic resource classifier (bindings, SAs, etc.) — NOT namespaces.
    Does NOT match on the resource's own name (since 'default' is both a
    baseline namespace and a legitimate SA name in user namespaces)."""
    if not obj:
        return False
    ns = obj.get("namespace")
    if ns and name_is_baseline(ns):
        return True
    if _has_managed_label(obj.get("labels")):
        return True
    if _has_managed_annotation(obj.get("annotations")):
        return True
    if _has_operator_owner(obj.get("ownerReferences")):
        return True
    return False


def is_baseline_subject(subject):
    """Catches system: prefix, well-known cluster-bootstrap users,
    and SAs in baseline namespaces."""
    if not subject:
        return False
    name = subject.get("name") or ""
    if any(name.startswith(p) for p in SYSTEM_SUBJECT_PREFIXES):
        return True
    if subject.get("kind") == "User" and name in BOOTSTRAP_USER_NAMES:
        return True
    if subject.get("kind") == "ServiceAccount":
        ns = subject.get("namespace")
        if ns and name_is_baseline(ns):
            return True
    return False


def is_baseline_binding(binding):
    if not binding:
        return False
    name = binding.get("name") or ""
    if any(name.startswith(p) for p in BASELINE_BINDING_PREFIXES):
        return True
    if is_baseline_resource(binding):
        return True
    subjects = binding.get("subjects") or []
    if subjects and all(is_baseline_subject(s) for s in subjects):
        return True
    return False


# ============================================================ #
# Namespace classification                                      #
# ============================================================ #

Signal = namedtuple("Signal", ["category", "reason"])

# Tie-breaking priority when more than one rule fires (earlier wins). The
# requester annotation always wins over name patterns: a user who created
# `oc new-project openshift-sandbox` should land in `project`, not
# `openshift`, even though the name matches the platform prefix.
CATEGORY_PRIORITY = ["project", "system", "openshift"]
BASELINE_CATEGORIES = {"system", "openshift"}
USER_OWNED_CATEGORIES = {"project"}


def _rule_name_kube_or_default(ns_obj, *_):
    name = ns_obj.get("name") or ""
    if name in {"kube-system", "kube-public", "kube-node-lease", "default"}:
        return Signal("system", f"name '{name}' is a Kubernetes core namespace")
    if name.startswith("kube-"):
        return Signal("system", f"name '{name}' is in the kube-* core")
    return None


def _rule_name_openshift(ns_obj, *_):
    name = ns_obj.get("name") or ""
    if name in {"openshift", "openshift-infra", "openshift-node"}:
        return Signal("openshift", f"name '{name}' is an OpenShift core namespace")
    if name.startswith("openshift-"):
        return Signal("openshift",
                      f"name '{name}' matches the openshift-* platform prefix")
    return None


def _rule_requester(ns_obj, *_):
    """The only built-in positive signal that puts a namespace into the
    user-owned bucket. `openshift.io/requester` is set by the OpenShift
    project lifecycle when a human runs `oc new-project` or creates a
    project from the Console — no other component sets it. Other
    "user-looking" annotations (kubectl-applied, display-name,
    description) have all been observed on cluster-installed namespaces
    too, so they are not used."""
    requester = (ns_obj.get("annotations") or {}).get("openshift.io/requester")
    if requester:
        return Signal("project",
                      f"annotation openshift.io/requester={requester} "
                      "(created via `oc new-project` / Console)")
    return None


def _parse_iso(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


def _rule_install_window(ns_obj, install_ts):
    """Fallback rule. Fires only when no other signal classifies a namespace
    AND the namespace was created within INSTALL_WINDOW_HOURS of cluster
    install. Result: category `system`, reason mentions the window.

    Intentionally NOT a member of SIGNAL_RULES — it's evaluated last by
    classify_namespace_obj so it does NOT override an existing match
    (e.g. an `openshift-*` namespace already firing the openshift rule)."""
    install_dt = _parse_iso(install_ts)
    created_dt = _parse_iso(ns_obj.get("creationTimestamp"))
    if not install_dt or not created_dt:
        return None
    delta = (created_dt - install_dt).total_seconds()
    if 0 <= delta <= INSTALL_WINDOW_HOURS * 3600:
        return Signal(
            "system",
            f"created within {INSTALL_WINDOW_HOURS}h of cluster install "
            f"(install at {install_ts}) — treated as install-time "
            f"infrastructure; edit INSTALL_WINDOW_HOURS in "
            f"lineage/classifier.py to tune"
        )
    return None


# Public, append-able list for deployments that need local namespace signals.
SIGNAL_RULES = [
    _rule_name_kube_or_default,
    _rule_name_openshift,
    _rule_requester,
]


def classify_namespace_obj(ns_obj, install_ts=None, **_kwargs):
    """Run signal rules. The highest-priority firing category wins.

    Args:
      ns_obj:     the namespace dict from the index.
      install_ts: ISO timestamp of cluster install (typically the
                  creationTimestamp of `kube-system`). Used by the
                  install-window fallback so day-zero namespaces don't
                  flap to `unknown`. Optional — without it the install
                  window rule simply doesn't fire.

    Returns:
      {
        "category":     "system" | "openshift" | "project" | "unknown",
        "signals":      [Signal(category, reason), ...],
        "owner":        str | None,    # openshift.io/requester if present
        "is_baseline":  bool,          # True only for system / openshift
        "is_unknown":   bool,          # True for unknown category
        "is_user_owned": bool,         # True for project
      }

    Note: `unknown` is no longer rolled into `is_baseline`. Namespaces created
    with `oc create namespace` (no requester, non-platform name, outside the
    install window) land in `unknown` and should be reviewed, not silently
    treated as platform.

    `**_kwargs` is accepted for forward-compatibility.
    """
    blank = {
        "category": "unknown",
        "signals": [],
        "owner": None,
        "is_baseline": False,
        "is_unknown": True,
        "is_user_owned": False,
    }
    if not ns_obj:
        return blank

    signals = []
    for rule in SIGNAL_RULES:
        try:
            result = rule(ns_obj)
        except Exception:
            continue
        if result is None:
            continue
        if isinstance(result, Signal):
            signals.append(result)
        else:
            signals.extend(result)

    # Fallback: only when NO other rule fired, consult the install-window
    # rule. This keeps openshift-* / kube-* / requester classifications
    # exactly as before and only tweaks the unknown-vs-system boundary.
    if not signals and install_ts:
        result = _rule_install_window(ns_obj, install_ts)
        if isinstance(result, Signal):
            signals.append(result)

    if not signals:
        return blank

    cats_fired = {s.category for s in signals}
    best_cat = next((c for c in CATEGORY_PRIORITY if c in cats_fired), None)
    if best_cat is None:
        best_cat = next(iter(cats_fired))

    requester = (ns_obj.get("annotations") or {}).get("openshift.io/requester")
    return {
        "category": best_cat,
        "signals": signals,
        "owner": requester,
        "is_baseline": best_cat in BASELINE_CATEGORIES,
        "is_unknown": best_cat == "unknown",
        "is_user_owned": best_cat in USER_OWNED_CATEGORIES,
    }


# ============================================================ #
# Image classification                                          #
# ============================================================ #

def classify_image(ref):
    if not ref:
        return "unknown"
    ref_lower = ref.lower()
    if "image-registry.openshift-image-registry.svc" in ref_lower:
        return "internal"
    if (ref_lower.startswith("registry.redhat.io")
            or ref_lower.startswith("registry.access.redhat.com")):
        return "redhat"
    if (ref_lower.startswith("quay.io/openshift")
            or ref_lower.startswith("quay.io/openshift-release-dev")):
        return "redhat"
    head = ref.split("/", 1)[0] if "/" in ref else ""
    public_registries = (
        "quay.io", "docker.io", "gcr.io", "ghcr.io",
        "k8s.gcr.io", "registry.k8s.io",
        "mcr.microsoft.com", "public.ecr.aws",
    )
    if head in public_registries:
        return "public"
    if "." in head:
        return "public"
    return "unknown"


def registry_for(image_ref):
    if not image_ref:
        return "unknown"
    if "/" not in image_ref:
        return "docker.io"
    head = image_ref.split("/", 1)[0]
    if "." in head or ":" in head:
        return head
    return "docker.io"
