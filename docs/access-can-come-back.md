# Access That Can Come Back — Verification

This page shows the empirical behavior behind Lineage's `Resurrectable*`
labels. The commands here create and delete test objects. Run them on a
non-production cluster.

## Claim

A ClusterRoleBinding whose `subjects` reference a ServiceAccount continues
to exist after the namespace containing that ServiceAccount is deleted.
The grant is not garbage-collected. Recreating the namespace and
ServiceAccount with the same names reactivates the access — no new binding
is created and the existing binding is not modified.

## Step-by-step

```sh
# 1. Create a namespace and a ServiceAccount in it.
oc create namespace ghost-claim-test
oc create serviceaccount scanner -n ghost-claim-test

# 2. Create a ClusterRoleBinding granting the SA the `view` ClusterRole.
cat <<EOF | oc apply -f -
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ghost-claim-test-crb
subjects:
- kind: ServiceAccount
  name: scanner
  namespace: ghost-claim-test
roleRef:
  kind: ClusterRole
  name: view
  apiGroup: rbac.authorization.k8s.io
EOF

# 3. Confirm baseline access.
oc auth can-i list pods \
  --as=system:serviceaccount:ghost-claim-test:scanner -n default
# Expected: yes

# 4. Delete the namespace. The ServiceAccount is deleted with it.
oc delete namespace ghost-claim-test --wait=true

# 5. Confirm the namespace and SA are gone.
oc get namespace ghost-claim-test
# Expected: Error from server (NotFound)

# 6. Confirm the ClusterRoleBinding still exists with the orphaned subject.
oc get clusterrolebinding ghost-claim-test-crb -o yaml | grep -A6 'subjects:'
# Expected: subjects array unchanged, still names ghost-claim-test:scanner

# 7. Confirm the impersonation answer has not changed.
oc auth can-i list pods \
  --as=system:serviceaccount:ghost-claim-test:scanner -n default
# Expected: yes  (the API resolves the grant by name, not by live subject)

# 8. Recreate the namespace and SA with the same names. Access reactivates
#    without any change to the ClusterRoleBinding.
oc create namespace ghost-claim-test
oc create serviceaccount scanner -n ghost-claim-test
oc auth can-i list pods \
  --as=system:serviceaccount:ghost-claim-test:scanner -n default
# Expected: yes
```

## Cleanup

```sh
oc delete clusterrolebinding ghost-claim-test-crb
oc delete namespace ghost-claim-test --wait=true
```

## Why not RoleBindings in the same namespace

A RoleBinding inside the same namespace as the ServiceAccount it references
is deleted when the namespace is deleted — both are namespaced objects, so
namespace deletion cascades to both. That case is not resurrectable on its
own and Lineage does not flag it.

The resurrectable shape applies when the binding survives because it lives
outside the deleted scope:

1. **ClusterRoleBindings** — cluster-scoped, never deleted by a namespace.
2. **RoleBindings in a different namespace** than the subject they name —
   the binding's namespace still exists, so the binding persists.
3. **SCC `.users` / `.groups`** — SCC objects are cluster-scoped, so entries
   pointing at deleted subjects persist.

## What Lineage does with this

Lineage flags any RoleBinding, ClusterRoleBinding, or SCC user-list entry
whose ServiceAccount subject is not currently present in the cluster, and
separates these rows from live grants under the `Resurrectable*` labels
described in the [findings legend](../README.md#how-to-read-findings).

The same shape applies to SCC namespace targets
(`system:serviceaccounts:<namespace>`) and to RBAC grants on
`securitycontextconstraints/<name>` for SCCs that do not exist yet.
