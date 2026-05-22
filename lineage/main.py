"""Lineage — Flask app."""

import os
import secrets
import time
from urllib.parse import urlsplit
from flask import Flask, render_template, request, redirect, url_for, abort, session
from . import engine, data
from .ui.buckets import (
    bucket_filter,
    bucket_counts,
)
from .ui.filters import (
    cache_ttl_label as _cache_ttl_label,
    ago,
    humantime,
    humanage,
    category_label,
    short_image,
)
from .ui.pages import (
    home_context,
    identity_audit_context,
    subject_detail_context,
    who_can_context,
    aggregated_context,
    scc_detail_context,
    namespaces_context,
    namespace_detail_context,
    cross_namespace_context,
    images_context,
    image_detail_context,
    clusterroles_context,
    clusterrole_detail_context,
    roles_context,
    role_detail_context,
)

app = Flask(__name__)
app.secret_key = os.environ.get("LINEAGE_SECRET_KEY") or secrets.token_hex(32)
app.template_filter("ago")(ago)
app.template_filter("humantime")(humantime)
app.template_filter("humanage")(humanage)
app.template_filter("category_label")(category_label)
app.template_filter("short_image")(short_image)


@app.context_processor
def inject_globals():
    return {
        "cluster_status": data.live_status(),
        "cache_age": data.cache_age_seconds(),
        "cache_ttl_seconds": data.CACHE_TTL_SECONDS,
        "cache_ttl_label": _cache_ttl_label(data.CACHE_TTL_SECONDS),
        "fetch_errors": data.fetch_errors(),
        "refreshed_recently": session.pop("refreshed_at", None),
    }


@app.route("/")
def home():
    return render_template("home.html", **home_context())


@app.route("/identity-audit")
def identity_audit_page():
    return render_template("identity_audit.html",
                           **identity_audit_context(request.args))


@app.route("/subjects")
def subjects_page():
    idx = engine.index()
    subjects = engine.all_subjects(idx)
    total = len(subjects)
    counts = bucket_counts(subjects)
    bucket = request.args.get("bucket", "yours")
    subjects = bucket_filter(subjects, bucket)
    kind_filter = request.args.get("kind", "")
    if kind_filter:
        subjects = [s for s in subjects if s["kind"] == kind_filter]
    if request.args.get("ghost") == "1":
        subjects = [s for s in subjects if s.get("ghost")]
    if request.args.get("latent") == "1":
        subjects = [s for s in subjects if s.get("latent")]
    q = (request.args.get("q") or "").strip().lower()
    if q:
        subjects = [s for s in subjects if q in (s["name"] or "").lower()]
    subjects.sort(key=lambda s: (s.get("kind") or "",
                                 s.get("namespace") or "",
                                 s.get("name") or ""))
    subjects.sort(key=lambda s: s.get("creationTimestamp") or "", reverse=True)
    return render_template("subjects.html",
                           subjects=subjects,
                           kind_filter=kind_filter,
                           show_ghosts_only=request.args.get("ghost") == "1",
                           show_latent_only=request.args.get("latent") == "1",
                           bucket=bucket, total_count=total,
                           counts=counts)


@app.route("/subject/<kind>/<name>")
def subject_detail(kind, name):
    namespace = request.args.get("namespace") or None
    return render_template("subject_detail.html",
                           **subject_detail_context(kind, name, namespace))

@app.route("/who-can")
def who_can_page():
    return render_template("who_can.html", **who_can_context(request.args))


@app.route("/aggregated")
def aggregated_page():
    return render_template("aggregated.html", **aggregated_context())


@app.route("/privileged")
def privileged_page():
    idx = engine.index()
    items = engine.privileged_subjects(idx)
    duplicates = engine.duplicate_bindings(idx)
    total = len(items)
    counts = bucket_counts(items)
    dup_counts = bucket_counts(duplicates)
    bucket = request.args.get("bucket", "yours")
    items = bucket_filter(items, bucket)
    duplicates = bucket_filter(duplicates, bucket)
    resurrectable_priv = [r for r in engine.resurrectable_sa_identities(idx)
                          if r["severity"] in ("critical", "high")]
    return render_template("privileged.html",
                           items=items, duplicates=duplicates,
                           resurrectable_priv=resurrectable_priv,
                           privileged_roles=engine.PRIVILEGED_ROLES,
                           bucket=bucket, total_count=total,
                           counts=counts, dup_counts=dup_counts)


@app.route("/permission-grants")
def permission_grants_page():
    """All role grants to non-baseline subjects, regardless of role privilege."""
    idx = engine.index()
    grants = engine.role_grants(idx)
    role_filter = (request.args.get("role") or "").strip()
    if role_filter:
        grants = [g for g in grants if g["role"] == role_filter]
    q = (request.args.get("q") or "").strip().lower()
    if q:
        grants = [g for g in grants
                  if q in (g["subject"].get("name") or "").lower()
                  or q in g["role"].lower()]
    # Distinct roles for the filter
    all_roles = sorted({g["role"] for g in engine.role_grants(idx)})
    resurrectable_priv = [r for r in engine.resurrectable_sa_identities(idx)
                          if r["severity"] in ("critical", "high")]
    return render_template("permission_grants.html",
                           grants=grants, role_filter=role_filter,
                           resurrectable_priv=resurrectable_priv,
                           all_roles=all_roles, q=q)


@app.route("/sccs")
def sccs_page():
    idx = engine.index()
    rows = engine.sccs_with_admission_counts(idx)
    # Newest first. None / empty creationTimestamp sorts last and never crashes.
    rows.sort(key=lambda r: (r.get("scc") or {}).get("creationTimestamp") or "",
              reverse=True)
    # Absent-SA grants per SCC. SCC.users containing
    # `system:serviceaccount:<ns>:<name>` for an SA that doesn't exist is
    # the same lifecycle gap as a CRB to a missing SA: the SCC will still
    # admit a pod the moment the SA name is recreated.
    absent_by_scc = {r["scc"]["name"]:
                      engine.absent_sa_grants_for_scc(r["scc"]["name"], idx)
                      for r in rows}
    error_kinds = idx.get("fetch_error_kinds") or set()
    sccs_visible = bool(rows) or "scc" not in error_kinds
    return render_template("sccs.html", rows=rows,
                           absent_by_scc=absent_by_scc,
                           sccs_visible=sccs_visible,
                           is_admin=idx.get("is_admin", True))


@app.route("/scc/<name>")
def scc_detail(name):
    context = scc_detail_context(name, request.args)
    if context is None:
        abort(404)
    return render_template("scc_detail.html", **context)


@app.route("/namespaces")
def namespaces_page():
    return render_template("namespaces.html", **namespaces_context(request.args))


@app.route("/namespace/<ns>")
def namespace_detail(ns):
    return render_template("namespace_detail.html",
                           **namespace_detail_context(ns, request.args))


@app.route("/images")
def images_page():
    return render_template("images.html", **images_context(request.args))


@app.route("/image")
def image_detail():
    ref = (request.args.get("ref") or "").strip()
    if not ref:
        abort(404)
    context = image_detail_context(ref)
    if context is None:
        abort(404)
    return render_template("image_detail.html", **context)


def _current_mode(status):
    """Best-effort mode classifier for /setup. Mirrors the three runtime
    modes documented in docs/, plus disconnected state. Returns one of:
    'mock', 'in_cluster', 'local', 'disconnected'."""
    if status.get("mock"):
        return "mock"
    if not status.get("ok"):
        return "disconnected"
    user = status.get("user") or ""
    if user.startswith("system:serviceaccount:"):
        return "in_cluster"
    return "local"


@app.route("/setup")
def setup_page():
    status = data.live_status()
    return render_template(
        "setup.html",
        status=status,
        current_mode=_current_mode(status),
    )


def _safe_redirect_target(target):
    if not target:
        return url_for("home")
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return url_for("home")
    if not target.startswith("/") or target.startswith("//"):
        return url_for("home")
    return target


@app.route("/refresh", methods=["POST"])
def refresh():
    data.invalidate_cache()
    session["refreshed_at"] = time.strftime("%H:%M:%S")
    return redirect(_safe_redirect_target(request.form.get("next")))


@app.route("/healthz")
def healthz():
    """Liveness/readiness probe target. Returns 200 without touching
    the cluster or the cache, so it is safe to hit on cold start and
    during a slow refresh."""
    return "ok", 200, {"Content-Type": "text/plain"}


@app.route("/cross-namespace")
def cross_namespace_page():
    return render_template("cross_namespace.html",
                           **cross_namespace_context(request.args))


@app.route("/clusterroles")
def clusterroles_page():
    return render_template("clusterroles.html",
                           **clusterroles_context(request.args))


@app.route("/clusterrole/<name>")
def clusterrole_detail(name):
    context = clusterrole_detail_context(name)
    if context is None:
        abort(404)
    return render_template("clusterrole_detail.html", **context)


@app.route("/roles")
def roles_page():
    return render_template("roles.html", **roles_context(request.args))


@app.route("/role/<namespace>/<name>")
def role_detail(namespace, name):
    context = role_detail_context(namespace, name)
    if context is None:
        abort(404)
    return render_template("role_detail.html", **context)
