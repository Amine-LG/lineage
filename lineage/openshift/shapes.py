"""Pure reshape helpers for live `oc -o json` objects."""


def meta(obj):
    return obj.get("metadata") or {}


def user(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "fullName": obj.get("fullName") or "",
        "uid": m.get("uid"),
        "creationTimestamp": m.get("creationTimestamp"),
        "identities": obj.get("identities") or [],
    }


def identity(obj):
    m = meta(obj)
    user_obj = obj.get("user") or {}
    return {
        "name": m.get("name", ""),
        "providerName": obj.get("providerName"),
        "providerUserName": obj.get("providerUserName"),
        "user": {"name": user_obj.get("name", "")},
        "creationTimestamp": m.get("creationTimestamp"),
    }


def group(obj):
    return {
        "name": meta(obj).get("name", ""),
        "users": obj.get("users") or [],
        "creationTimestamp": meta(obj).get("creationTimestamp"),
    }


def cluster_role(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "labels": m.get("labels") or {},
        "annotations": m.get("annotations") or {},
        "aggregationRule": obj.get("aggregationRule"),
        "rules": obj.get("rules") or [],
        "creationTimestamp": m.get("creationTimestamp"),
    }


def cluster_role_binding(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "labels": m.get("labels") or {},
        "annotations": m.get("annotations") or {},
        "subjects": obj.get("subjects") or [],
        "roleRef": obj.get("roleRef") or {},
        "creationTimestamp": m.get("creationTimestamp"),
    }


def security_context_constraint(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "priority": obj.get("priority"),
        "allowPrivilegedContainer": obj.get("allowPrivilegedContainer"),
        "allowHostNetwork": obj.get("allowHostNetwork"),
        "allowHostPID": obj.get("allowHostPID"),
        "allowHostIPC": obj.get("allowHostIPC"),
        "allowPrivilegeEscalation": obj.get("allowPrivilegeEscalation"),
        "readOnlyRootFilesystem": obj.get("readOnlyRootFilesystem"),
        "runAsUser": obj.get("runAsUser") or {},
        "allowedCapabilities": obj.get("allowedCapabilities") or [],
        "defaultAddCapabilities": obj.get("defaultAddCapabilities") or [],
        "requiredDropCapabilities": obj.get("requiredDropCapabilities") or [],
        "seccompProfiles": obj.get("seccompProfiles") or [],
        "users": obj.get("users") or [],
        "groups": obj.get("groups") or [],
        "creationTimestamp": m.get("creationTimestamp"),
    }


def imagestream(obj):
    m = meta(obj)
    spec_tags = (obj.get("spec") or {}).get("tags") or []
    status_tags = (obj.get("status") or {}).get("tags") or []
    repo = (obj.get("status") or {}).get("dockerImageRepository") or ""
    public_repo = (obj.get("status") or {}).get("publicDockerImageRepository") or ""
    return {
        "name": m.get("name", ""),
        "namespace": m.get("namespace", ""),
        "labels": m.get("labels") or {},
        "annotations": m.get("annotations") or {},
        "creationTimestamp": m.get("creationTimestamp"),
        "spec_tags": [
            {"name": t.get("name"),
             "from": (t.get("from") or {}).get("name", "")}
            for t in spec_tags
        ],
        "status_tags": [t.get("tag") for t in status_tags],
        "dockerImageRepository": repo,
        "publicDockerImageRepository": public_repo,
    }


def job(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "namespace": m.get("namespace", ""),
        "creationTimestamp": m.get("creationTimestamp"),
        "ownerReferences": m.get("ownerReferences") or [],
        "spec": obj.get("spec") or {},
    }


def cronjob(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "namespace": m.get("namespace", ""),
        "creationTimestamp": m.get("creationTimestamp"),
        "schedule": (obj.get("spec") or {}).get("schedule"),
        "spec": obj.get("spec") or {},
    }


def namespace(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "labels": m.get("labels") or {},
        "annotations": m.get("annotations") or {},
        "creationTimestamp": m.get("creationTimestamp"),
    }


def service_account(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "namespace": m.get("namespace", ""),
        "labels": m.get("labels") or {},
        "creationTimestamp": m.get("creationTimestamp"),
        "ownerReferences": m.get("ownerReferences") or [],
    }


def role(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "namespace": m.get("namespace", ""),
        "rules": obj.get("rules") or [],
        "creationTimestamp": m.get("creationTimestamp"),
    }


def role_binding(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "namespace": m.get("namespace", ""),
        "labels": m.get("labels") or {},
        "annotations": m.get("annotations") or {},
        "subjects": obj.get("subjects") or [],
        "roleRef": obj.get("roleRef") or {},
        "creationTimestamp": m.get("creationTimestamp"),
    }


def pod(obj):
    m = meta(obj)
    return {
        "name": m.get("name", ""),
        "namespace": m.get("namespace", ""),
        "annotations": m.get("annotations") or {},
        "labels": m.get("labels") or {},
        "ownerReferences": m.get("ownerReferences") or [],
        "spec": obj.get("spec") or {},
        "phase": (obj.get("status") or {}).get("phase"),
        "containerStatuses": (obj.get("status") or {}).get("containerStatuses") or [],
        "creationTimestamp": m.get("creationTimestamp"),
    }
