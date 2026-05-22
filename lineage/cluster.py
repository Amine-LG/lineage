"""
Live cluster reader. Shells out to `oc -o json` and reshapes results.
TTL-cached. Per-fetch diagnostics.
"""

import base64
import json
import subprocess
import time
from threading import RLock

from .openshift import shapes as shape

# Live `oc` read cache TTL. The Refresh button invalidates this immediately.
# 5 minutes is the practical sweet spot: long enough to absorb a normal
# review session (multiple page loads, navigation back-and-forth) on one
# warm index, short enough that a manual cluster change doesn't go
# unnoticed for an entire reviewer sitting.
CACHE_TTL_SECONDS = 300
_cache: dict = {}
_last_identity = {"user": None, "server": None}
_status_cache = {"ts": 0, "data": None}
_lock = RLock()


def invalidate_cache():
    with _lock:
        _cache.clear()


def cache_age_seconds():
    with _lock:
        if not _cache:
            return None
        return time.time() - min(e["ts"] for e in _cache.values())


def fetch_errors():
    """Surface the `_error` field from any cached `_oc_json` result.

    Lets callers distinguish 'no objects exist' (empty list, no error)
    from 'we could not read this resource' (empty list because the API
    refused). Already-tracked state — no extra oc calls.

    Returns a list of {key, kind, namespace, error} dicts. `kind` is the
    short resource name (e.g. 'users', 'pods') and `namespace` is set for
    per-namespace fallback fetches keyed `pods:<ns>`.
    """
    out = []
    with _lock:
        items = list(_cache.items())
    for key, entry in items:
        data = entry.get("data") or {}
        if not isinstance(data, dict):
            continue
        err = data.get("_error")
        if not err:
            continue
        kind, _, namespace = key.partition(":")
        out.append({"key": key, "kind": kind,
                    "namespace": namespace or None, "error": err})
    out.sort(key=lambda e: (e["kind"], e["namespace"] or "", e["key"]))
    return out


def _cached(key, fetch):
    with _lock:
        entry = _cache.get(key)
        if entry and time.time() - entry["ts"] < CACHE_TTL_SECONDS:
            return entry["data"]
    data = fetch()
    with _lock:
        _cache[key] = {"ts": time.time(), "data": data}
    return data


def _oc_json(*args, timeout=20):
    cmd = ["oc"] + list(args) + ["-o", "json"]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.PIPE, timeout=timeout)
        return json.loads(out)
    except subprocess.CalledProcessError as e:
        msg = e.stderr.decode("utf-8", errors="replace").strip() or f"exit {e.returncode}"
        return {"items": [], "_error": msg}
    except FileNotFoundError:
        return {"items": [], "_error": "oc CLI not found on PATH"}
    except subprocess.TimeoutExpired:
        return {"items": [], "_error": f"timeout after {timeout}s"}
    except Exception as e:
        return {"items": [], "_error": str(e)}


def _can(verb, resource, namespace=None):
    """`oc auth can-i <verb> <resource>`. Returns True/False, never raises."""
    cmd = ["oc", "auth", "can-i", verb, resource]
    if namespace:
        cmd += ["-n", namespace]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def live_status():
    # Always check whoami first (cheap) so user switches are detected
    # immediately and the data cache is invalidated before any fetch.
    try:
        server = subprocess.check_output(
            ["oc", "whoami", "--show-server"],
            stderr=subprocess.PIPE, timeout=5,
        ).decode().strip()
        user = subprocess.check_output(
            ["oc", "whoami"],
            stderr=subprocess.PIPE, timeout=5,
        ).decode().strip()
    except subprocess.CalledProcessError as e:
        msg = e.stderr.decode("utf-8", errors="replace").strip()
        hint = "run `oc login` to fix" if "login" in msg.lower() or "Unauthorized" in msg else None
        return {"ok": False, "error": msg, "hint": hint, "mock": False, "is_admin": False}
    except FileNotFoundError:
        return {"ok": False, "error": "oc CLI not found on PATH",
                "hint": "install the OpenShift CLI", "mock": False, "is_admin": False}
    except Exception as e:
        return {"ok": False, "error": str(e), "mock": False, "is_admin": False}

    if (_last_identity["user"] is not None and
        (_last_identity["user"] != user or _last_identity["server"] != server)):
        invalidate_cache()
        _status_cache["data"] = None
    _last_identity["user"] = user
    _last_identity["server"] = server

    # Memoize the heavier admin/version checks for 5s
    if _status_cache["data"] and time.time() - _status_cache["ts"] < 5:
        return _status_cache["data"]

    # Resolve the OpenShift release version with non-admin in mind. Order:
    #   1. releaseClientVersion — present for every user on a CRC/OpenShift
    #      release-built oc, so it works for non-admin sessions too.
    #   2. openshiftVersion     — present only when the session can read
    #      the cluster's OpenShift version from cluster state (admins /
    #      some readers). When present it confirms cluster matches client.
    #   3. clusterversion       — admin-only, used as a confirming fallback
    #      for older oc binaries that don't emit the fields above, and as
    #      the in-pod path (the bundled origin-cli oc surfaces neither
    #      releaseClientVersion nor openshiftVersion).
    #   4. serverVersion.gitVersion — Kubernetes version (e.g. v1.32.7),
    #      the least informative for an OpenShift cluster; last resort only.
    version = "unknown"
    blob = None
    try:
        out = subprocess.check_output(
            ["oc", "version", "-o", "json"],
            stderr=subprocess.PIPE, timeout=5,
        ).decode().strip()
        if out:
            blob = json.loads(out)
    except Exception:
        blob = None
    if blob:
        version = (blob.get("releaseClientVersion")
                   or blob.get("openshiftVersion")
                   or "unknown")
    if version == "unknown":
        try:
            version = subprocess.check_output(
                ["oc", "get", "clusterversion", "version",
                 "-o", "jsonpath={.status.desired.version}"],
                stderr=subprocess.PIPE, timeout=5,
            ).decode().strip() or "unknown"
        except Exception:
            pass
    if version == "unknown" and blob:
        # Last resort: surface the Kubernetes server gitVersion so /home
        # doesn't read 'unknown' when we have *some* version info.
        version = (blob.get("serverVersion") or {}).get("gitVersion") or "unknown"
    is_admin = (_can("list", "users.user.openshift.io")
                and _can("list", "clusterrolebindings.rbac.authorization.k8s.io"))
    result = {"ok": True, "server": server, "user": user,
              "version": version, "mock": False, "is_admin": is_admin}
    _status_cache["ts"] = time.time()
    _status_cache["data"] = result
    return result


# ---------- Reshapers ---------- #

_meta = shape.meta


def users():
    raw = _cached("users", lambda: _oc_json("get", "users"))
    return [shape.user(u) for u in raw.get("items", [])]


def identities():
    raw = _cached("identities", lambda: _oc_json("get", "identities"))
    return [shape.identity(i) for i in raw.get("items", [])]


def groups():
    raw = _cached("groups", lambda: _oc_json("get", "groups"))
    return [shape.group(g) for g in raw.get("items", [])]




def cluster_roles():
    raw = _cached("clusterroles", lambda: _oc_json("get", "clusterroles"))
    return [shape.cluster_role(cr) for cr in raw.get("items", [])]



def cluster_role_bindings():
    raw = _cached("crb", lambda: _oc_json("get", "clusterrolebindings"))
    return [shape.cluster_role_binding(b) for b in raw.get("items", [])]



def oauth_cluster():
    raw = _cached("oauth", lambda: _oc_json("get", "oauth", "cluster"))
    spec = (raw.get("spec") or {}) if isinstance(raw, dict) else {}
    return {
        "name": _meta(raw).get("name", "cluster"),
        "identityProviders": spec.get("identityProviders") or [],
    }



def security_context_constraints():
    raw = _cached("scc", lambda: _oc_json("get", "scc"))
    return [shape.security_context_constraint(s) for s in raw.get("items", [])]


def imagestreams():
    """OpenShift ImageStreams across all namespaces. Empty on plain k8s."""
    raw = _cached("imagestreams", lambda: _oc_json(
        "get", "imagestreams", "--all-namespaces"))
    return [shape.imagestream(i) for i in raw.get("items", [])]

def jobs():
    raw = _cached("jobs", lambda: _oc_json("get", "jobs", "--all-namespaces"))
    items = raw.get("items") or []
    if not items and "_error" in raw:
        return _per_namespace_fetch("jobs", "jobs", shape.job)
    return [shape.job(j) for j in items]


def cronjobs():
    raw = _cached("cronjobs", lambda: _oc_json("get", "cronjobs", "--all-namespaces"))
    items = raw.get("items") or []
    if not items and "_error" in raw:
        return _per_namespace_fetch("cronjobs", "cronjobs", shape.cronjob)
    return [shape.cronjob(c) for c in items]

def htpasswd_users():
    """Read OAuth, find HTPasswd Secret refs, return availability + usernames.

    Returns a dict with:
      - configured: True if at least one HTPasswd IdP is declared in OAuth/cluster
      - available:  True if every configured HTPasswd Secret was readable
                    (also True when not configured — nothing to read)
      - users:      list of {username, idp_name, secret_namespace, secret_name}
      - reason:     short string describing the first read failure (or None)

    Distinguishing "readable but empty" from "unavailable" lets callers avoid
    flagging false-positive phantoms when the Secret simply can't be read."""
    oauth = oauth_cluster()
    out = []
    configured = False
    available = True
    reason = None
    for idp in oauth.get("identityProviders", []):
        if idp.get("type") != "HTPasswd":
            continue
        configured = True
        secret_name = ((idp.get("htpasswd") or {}).get("fileData") or {}).get("name")
        if not secret_name:
            available = False
            reason = reason or f"HTPasswd IdP {idp.get('name','?')} has no fileData.name"
            continue
        ns = "openshift-config"
        key = f"secret:{ns}:{secret_name}"
        raw = _cached(key, lambda: _oc_json(
            "get", "secret", secret_name, "-n", ns,
        ))
        if "_error" in raw:
            available = False
            reason = reason or raw.get("_error")
            continue
        data = raw.get("data") or {}
        encoded = data.get("htpasswd")
        if not encoded:
            available = False
            reason = reason or f"Secret {ns}/{secret_name} has no htpasswd key"
            continue
        try:
            decoded = base64.b64decode(encoded).decode("utf-8", errors="replace")
        except Exception as e:
            available = False
            reason = reason or f"decode failed: {e}"
            continue
        for line in decoded.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            username = line.split(":", 1)[0].strip()
            if username:
                out.append({
                    "username": username,
                    "idp_name": idp.get("name", "?"),
                    "secret_namespace": ns,
                    "secret_name": secret_name,
                })
    return {"configured": configured, "available": available,
            "users": out, "reason": reason}

def _projects():
    """Returns full Project items (alice can read her own projects' metadata,
    including the openshift.io/requester annotation)."""
    raw = _cached("projects", lambda: _oc_json("get", "projects"))
    return raw.get("items") or []

def _project_names():
    return [_meta(p).get("name", "") for p in _projects() if _meta(p).get("name")]



def _per_namespace_fetch(key_prefix, kind, reshaper):
    out = []
    for ns in _project_names():
        key = f"{key_prefix}:{ns}"
        raw = _cached(key, lambda ns=ns: _oc_json("get", kind, "-n", ns))
        for item in raw.get("items", []):
            out.append(reshaper(item))
    return out


def namespaces():
    raw = _cached("namespaces", lambda: _oc_json("get", "namespaces"))
    items = raw.get("items") or []
    # Cluster-wide forbidden — fall back to projects, preserving metadata
    # so the openshift.io/requester annotation survives the classifier.
    if not items and "_error" in raw:
        items = _projects()
    return [shape.namespace(n) for n in items]


def service_accounts():
    raw = _cached("sa", lambda: _oc_json("get", "sa", "--all-namespaces"))
    items = raw.get("items") or []
    if not items and "_error" in raw:
        return _per_namespace_fetch("sa", "sa", shape.service_account)
    return [shape.service_account(s) for s in items]


def roles():
    raw = _cached("roles", lambda: _oc_json("get", "roles", "--all-namespaces"))
    items = raw.get("items") or []
    if not items and "_error" in raw:
        return _per_namespace_fetch("roles", "roles", shape.role)
    return [shape.role(r) for r in items]


def role_bindings():
    raw = _cached("rb", lambda: _oc_json("get", "rolebindings", "--all-namespaces"))
    items = raw.get("items") or []
    if not items and "_error" in raw:
        return _per_namespace_fetch("rb", "rolebindings", shape.role_binding)
    return [shape.role_binding(b) for b in items]


def pods():
    raw = _cached("pods", lambda: _oc_json("get", "pods", "--all-namespaces"))
    items = raw.get("items") or []
    if not items and "_error" in raw:
        return _per_namespace_fetch("pods", "pods", shape.pod)
    return [shape.pod(p) for p in items]
