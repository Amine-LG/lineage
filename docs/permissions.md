# Permissions

Lineage is read-only. Runtime access is limited to:

- `oc get ... -o json`
- `oc auth can-i`
- version and identity checks such as `oc whoami`

It does not run mutating commands against the inspected cluster.

## Main Reads

| Resource | Why |
| --- | --- |
| Users, Identities, Groups | subject and identity context |
| Namespaces / Projects | inventory and classification |
| ServiceAccounts | workload identity graph |
| Roles, ClusterRoles, RoleBindings, ClusterRoleBindings | RBAC graph |
| SCCs | SCC grants and pod admission |
| Pods, Jobs, CronJobs | workload and ServiceAccount context |
| ImageStreams | OpenShift image relationships |
| OAuth, ClusterVersion | IdP and cluster context |

The in-cluster ClusterRole is in
[deploy/openshift/10-rbac.yaml](../deploy/openshift/10-rbac.yaml).

## Secrets

Lineage does not list Secrets.

The only Secret read is optional: if an HTPasswd IdP is configured,
Lineage can read the referenced Secret by exact name in
`openshift-config`. This enables latent, phantom, and htpasswd-backed
identity signals.

ServiceAccount-token Secrets are not inventoried.

## Degraded Views

When a read fails, Lineage records it and shows the limitation on
`/setup`. It should not turn missing visibility into a clean result.

Examples:

- no SCC permission -> `/sccs` shows limited visibility;
- HTPasswd Secret unreadable -> HTPasswd-derived identity signals are
  unavailable;
- lower-permission account -> pages render what is visible and show the
  missing read surface.
